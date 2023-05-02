use std::{
  collections::{HashSet, HashMap},
  str::FromStr,
};

use rand_core::{OsRng, RngCore};

use serde::Deserialize;
use serde_json::json;

use monero_rpc::{
  monero::{
    Amount, Address,
    cryptonote::{hash::Hash, subaddress::Index},
    util::address::PaymentId,
  },
  TransferOptions, WalletClient,
};

use monero_serai::{
  transaction::Transaction,
  rpc::{HttpRpc, Rpc},
  wallet::{
    address::{Network, AddressSpec, SubaddressIndex, MoneroAddress},
    extra::{MAX_TX_EXTRA_NONCE_SIZE, Extra},
    Scanner,
  },
};

mod runner;

async fn make_integrated_address(payment_id: [u8; 8]) -> String {
  #[derive(Deserialize, Debug)]
  struct IntegratedAddressResponse {
    integrated_address: String,
  }

  let rpc = HttpRpc::new("http://127.0.0.1:6061".to_string()).unwrap();
  let res = rpc
    .json_rpc_call::<IntegratedAddressResponse>(
      "make_integrated_address",
      Some(json!({ "payment_id": hex::encode(payment_id) })),
    )
    .await
    .unwrap();

  res.integrated_address
}

async fn initialize_rpcs() -> (WalletClient, Rpc<HttpRpc>, monero_rpc::monero::Address) {
  let wallet_rpc =
    monero_rpc::RpcClientBuilder::new().build("http://127.0.0.1:6061").unwrap().wallet();
  let daemon_rpc = runner::rpc().await;

  let address_resp = wallet_rpc.get_address(0, None).await;
  let wallet_rpc_addr = if address_resp.is_ok() {
    address_resp.unwrap().address
  } else {
    wallet_rpc.create_wallet("wallet".to_string(), None, "English".to_string()).await.unwrap();
    let addr = wallet_rpc.get_address(0, None).await.unwrap().address;
    daemon_rpc.generate_blocks(&addr.to_string(), 70).await.unwrap();
    addr
  };
  (wallet_rpc, daemon_rpc, wallet_rpc_addr)
}

async fn from_wallet_rpc_to_self(spec: AddressSpec) {
  // initialize rpc
  let (wallet_rpc, daemon_rpc, wallet_rpc_addr) = initialize_rpcs().await;

  // make an addr
  let (_, view_pair, _) = runner::random_address();
  let addr = Address::from_str(&view_pair.address(Network::Mainnet, spec).to_string()[..]).unwrap();

  // refresh & make a tx
  wallet_rpc.refresh(None).await.unwrap();
  let tx = wallet_rpc
    .transfer(
      HashMap::from([(addr, Amount::ONE_XMR)]),
      monero_rpc::TransferPriority::Default,
      TransferOptions::default(),
    )
    .await
    .unwrap();
  let tx_hash: [u8; 32] = tx.tx_hash.0.try_into().unwrap();

  // unlock it
  runner::mine_until_unlocked(&daemon_rpc, &wallet_rpc_addr.to_string(), tx_hash).await;

  // create the scanner
  let mut scanner = Scanner::from_view(view_pair, Some(HashSet::new()));
  if let AddressSpec::Subaddress(index) = spec {
    scanner.register_subaddress(index);
  }

  // retrieve it and confirm
  let tx = daemon_rpc.get_transaction(tx_hash).await.unwrap();
  let output = scanner.scan_transaction(&tx).not_locked().swap_remove(0);

  match spec {
    AddressSpec::Subaddress(index) => assert_eq!(output.metadata.subaddress, Some(index)),
    AddressSpec::Integrated(payment_id) => {
      assert_eq!(output.metadata.payment_id, payment_id);
      assert_eq!(output.metadata.subaddress, None);
    }
    _ => assert_eq!(output.metadata.subaddress, None),
  }
  assert_eq!(output.commitment().amount, 1000000000000);
}

async_sequential!(
  async fn receipt_of_wallet_rpc_tx_standard() {
    from_wallet_rpc_to_self(AddressSpec::Standard).await;
  }

  async fn receipt_of_wallet_rpc_tx_subaddress() {
    from_wallet_rpc_to_self(AddressSpec::Subaddress(SubaddressIndex::new(0, 1).unwrap())).await;
  }

  async fn receipt_of_wallet_rpc_tx_integrated() {
    let mut payment_id = [0u8; 8];
    OsRng.fill_bytes(&mut payment_id);
    from_wallet_rpc_to_self(AddressSpec::Integrated(payment_id)).await;
  }
);

test!(
  send_to_wallet_rpc_standard,
  (
    |_, mut builder: Builder, _| async move {
      // initialize rpc
      let (wallet_rpc, _, wallet_rpc_addr) = initialize_rpcs().await;

      // add destination
      builder.add_payment(
        MoneroAddress::from_str(Network::Mainnet, &wallet_rpc_addr.to_string()).unwrap(),
        1000000,
      );
      (builder.build().unwrap(), (wallet_rpc,))
    },
    |_, tx: Transaction, _, data: (WalletClient,)| async move {
      // confirm receipt
      data.0.refresh(None).await.unwrap();
      let transfer =
        data.0.get_transfer(Hash::from_slice(&tx.hash()), None).await.unwrap().unwrap();
      assert_eq!(transfer.amount.as_pico(), 1000000);
      assert_eq!(transfer.subaddr_index, Index { major: 0, minor: 0 });
    },
  ),
);

test!(
  send_to_wallet_rpc_subaddress,
  (
    |_, mut builder: Builder, _| async move {
      // initialize rpc
      let (wallet_rpc, _, _) = initialize_rpcs().await;

      // make the addr
      let (subaddress, index) = wallet_rpc.create_address(0, None).await.unwrap();

      builder.add_payment(
        MoneroAddress::from_str(Network::Mainnet, &subaddress.to_string()).unwrap(),
        1000000,
      );
      (builder.build().unwrap(), (wallet_rpc, index))
    },
    |_, tx: Transaction, _, data: (WalletClient, u32)| async move {
      // confirm receipt
      data.0.refresh(None).await.unwrap();
      let transfer =
        data.0.get_transfer(Hash::from_slice(&tx.hash()), None).await.unwrap().unwrap();
      assert_eq!(transfer.amount.as_pico(), 1000000);
      assert_eq!(transfer.subaddr_index, Index { major: 0, minor: data.1 });

      // Make sure only one R was included in TX extra
      assert!(Extra::read::<&[u8]>(&mut tx.prefix.extra.as_ref())
        .unwrap()
        .keys()
        .unwrap()
        .1
        .is_none());
    },
  ),
);

test!(
  send_to_wallet_rpc_integrated,
  (
    |_, mut builder: Builder, _| async move {
      // initialize rpc
      let (wallet_rpc, _, _) = initialize_rpcs().await;

      // make the addr
      let mut payment_id = [0u8; 8];
      OsRng.fill_bytes(&mut payment_id);
      let addr = make_integrated_address(payment_id).await;

      builder.add_payment(MoneroAddress::from_str(Network::Mainnet, &addr).unwrap(), 1000000);
      (builder.build().unwrap(), (wallet_rpc, payment_id))
    },
    |_, tx: Transaction, _, data: (WalletClient, [u8; 8])| async move {
      // confirm receipt
      data.0.refresh(None).await.unwrap();
      let transfer =
        data.0.get_transfer(Hash::from_slice(&tx.hash()), None).await.unwrap().unwrap();
      assert_eq!(transfer.amount.as_pico(), 1000000);
      assert_eq!(transfer.subaddr_index, Index { major: 0, minor: 0 });
      assert_eq!(transfer.payment_id.0, PaymentId::from_slice(&data.1));
    },
  ),
);

test!(
  send_to_wallet_rpc_with_arb_data,
  (
    |_, mut builder: Builder, _| async move {
      // initialize rpc
      let (wallet_rpc, _, wallet_rpc_addr) = initialize_rpcs().await;

      // add destination
      builder.add_payment(
        MoneroAddress::from_str(Network::Mainnet, &wallet_rpc_addr.to_string()).unwrap(),
        1000000,
      );

      // Make 2 data that is the full 255 bytes
      for _ in 0 .. 2 {
        // Subtract 1 since we prefix data with 127
        let data = vec![b'a'; MAX_TX_EXTRA_NONCE_SIZE - 1];
        assert!(builder.add_data(data).is_ok());
      }

      (builder.build().unwrap(), (wallet_rpc,))
    },
    |_, tx: Transaction, _, data: (WalletClient,)| async move {
      // confirm receipt
      data.0.refresh(None).await.unwrap();
      let transfer =
        data.0.get_transfer(Hash::from_slice(&tx.hash()), None).await.unwrap().unwrap();
      assert_eq!(transfer.amount.as_pico(), 1000000);
      assert_eq!(transfer.subaddr_index, Index { major: 0, minor: 0 });
    },
  ),
);
