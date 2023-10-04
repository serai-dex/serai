use std::collections::HashSet;

use rand_core::{OsRng, RngCore};

use serde::Deserialize;
use serde_json::json;

use monero_serai::{
  transaction::Transaction,
  rpc::{EmptyResponse, HttpRpc, Rpc},
  wallet::{
    address::{Network, AddressSpec, SubaddressIndex, MoneroAddress},
    extra::{MAX_TX_EXTRA_NONCE_SIZE, Extra},
    Scanner, FeePriority,
  },
};

mod runner;

async fn make_integrated_address(rpc: &Rpc<HttpRpc>, payment_id: [u8; 8]) -> String {
  #[derive(Debug, Deserialize)]
  struct IntegratedAddressResponse {
    integrated_address: String,
  }

  let res = rpc
    .json_rpc_call::<IntegratedAddressResponse>(
      "make_integrated_address",
      Some(json!({ "payment_id": hex::encode(payment_id) })),
    )
    .await
    .unwrap();

  res.integrated_address
}

async fn initialize_rpcs() -> (Rpc<HttpRpc>, Rpc<HttpRpc>, String) {
  let wallet_rpc = HttpRpc::new("http://127.0.0.1:6061".to_string()).unwrap();
  let daemon_rpc = runner::rpc().await;

  #[derive(Debug, Deserialize)]
  struct AddressResponse {
    address: String,
  }

  let mut wallet_id = [0; 8];
  OsRng.fill_bytes(&mut wallet_id);
  let _: EmptyResponse = wallet_rpc
    .json_rpc_call(
      "create_wallet",
      Some(json!({ "filename": hex::encode(wallet_id), "language": "English" })),
    )
    .await
    .unwrap();

  let address: AddressResponse =
    wallet_rpc.json_rpc_call("get_address", Some(json!({ "account_index": 0 }))).await.unwrap();

  // Fund the new wallet
  daemon_rpc.generate_blocks(&address.address, 70).await.unwrap();

  (wallet_rpc, daemon_rpc, address.address)
}

async fn from_wallet_rpc_to_self(spec: AddressSpec) {
  // initialize rpc
  let (wallet_rpc, daemon_rpc, wallet_rpc_addr) = initialize_rpcs().await;

  // make an addr
  let (_, view_pair, _) = runner::random_address();
  let addr = view_pair.address(Network::Mainnet, spec);

  // refresh & make a tx
  let _: EmptyResponse = wallet_rpc.json_rpc_call("refresh", None).await.unwrap();

  #[derive(Debug, Deserialize)]
  struct TransferResponse {
    tx_hash: String,
  }
  let tx: TransferResponse = wallet_rpc
    .json_rpc_call(
      "transfer",
      Some(json!({
        "destinations": [{"address": addr.to_string(), "amount": 1_000_000_000_000u64 }],
      })),
    )
    .await
    .unwrap();
  let tx_hash = hex::decode(tx.tx_hash).unwrap().try_into().unwrap();

  let fee_rate = daemon_rpc
    // Uses `FeePriority::Low` instead of `FeePriority::Lowest` because wallet RPC
    // adjusts `monero_rpc::TransferPriority::Default` up by 1
    .get_fee(daemon_rpc.get_protocol().await.unwrap(), FeePriority::Low)
    .await
    .unwrap();

  // unlock it
  runner::mine_until_unlocked(&daemon_rpc, &wallet_rpc_addr, tx_hash).await;

  // Create the scanner
  let mut scanner = Scanner::from_view(view_pair, Some(HashSet::new()));
  if let AddressSpec::Subaddress(index) = spec {
    scanner.register_subaddress(index);
  }

  // Retrieve it and scan it
  let tx = daemon_rpc.get_transaction(tx_hash).await.unwrap();
  let output = scanner.scan_transaction(&tx).not_locked().swap_remove(0);

  runner::check_weight_and_fee(&tx, fee_rate);

  match spec {
    AddressSpec::Subaddress(index) => assert_eq!(output.metadata.subaddress, Some(index)),
    AddressSpec::Integrated(payment_id) => {
      assert_eq!(output.metadata.payment_id, payment_id);
      assert_eq!(output.metadata.subaddress, None);
    }
    AddressSpec::Standard | AddressSpec::Featured { .. } => {
      assert_eq!(output.metadata.subaddress, None)
    }
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

#[derive(PartialEq, Eq, Debug, Deserialize)]
struct Index {
  major: u32,
  minor: u32,
}

#[derive(Debug, Deserialize)]
struct Transfer {
  payment_id: String,
  subaddr_index: Index,
  amount: u64,
}

#[derive(Debug, Deserialize)]
struct TransfersResponse {
  transfer: Transfer,
}

test!(
  send_to_wallet_rpc_standard,
  (
    |_, mut builder: Builder, _| async move {
      // initialize rpc
      let (wallet_rpc, _, wallet_rpc_addr) = initialize_rpcs().await;

      // add destination
      builder
        .add_payment(MoneroAddress::from_str(Network::Mainnet, &wallet_rpc_addr).unwrap(), 1000000);
      (builder.build().unwrap(), wallet_rpc)
    },
    |_, tx: Transaction, _, data: Rpc<HttpRpc>| async move {
      // confirm receipt
      let _: EmptyResponse = data.json_rpc_call("refresh", None).await.unwrap();
      let transfer: TransfersResponse = data
        .json_rpc_call("get_transfer_by_txid", Some(json!({ "txid": hex::encode(tx.hash()) })))
        .await
        .unwrap();
      assert_eq!(transfer.transfer.subaddr_index, Index { major: 0, minor: 0 });
      assert_eq!(transfer.transfer.amount, 1000000);
    },
  ),
);

test!(
  send_to_wallet_rpc_subaddress,
  (
    |_, mut builder: Builder, _| async move {
      // initialize rpc
      let (wallet_rpc, _, _) = initialize_rpcs().await;

      // make the subaddress
      #[derive(Debug, Deserialize)]
      struct AccountResponse {
        address: String,
        account_index: u32,
      }
      let addr: AccountResponse = wallet_rpc.json_rpc_call("create_account", None).await.unwrap();
      assert!(addr.account_index != 0);

      builder
        .add_payment(MoneroAddress::from_str(Network::Mainnet, &addr.address).unwrap(), 1000000);
      (builder.build().unwrap(), (wallet_rpc, addr.account_index))
    },
    |_, tx: Transaction, _, data: (Rpc<HttpRpc>, u32)| async move {
      // confirm receipt
      let _: EmptyResponse = data.0.json_rpc_call("refresh", None).await.unwrap();
      let transfer: TransfersResponse = data
        .0
        .json_rpc_call(
          "get_transfer_by_txid",
          Some(json!({ "txid": hex::encode(tx.hash()), "account_index": data.1 })),
        )
        .await
        .unwrap();
      assert_eq!(transfer.transfer.subaddr_index, Index { major: data.1, minor: 0 });
      assert_eq!(transfer.transfer.amount, 1000000);

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
      let addr = make_integrated_address(&wallet_rpc, payment_id).await;

      builder.add_payment(MoneroAddress::from_str(Network::Mainnet, &addr).unwrap(), 1000000);
      (builder.build().unwrap(), (wallet_rpc, payment_id))
    },
    |_, tx: Transaction, _, data: (Rpc<HttpRpc>, [u8; 8])| async move {
      // confirm receipt
      let _: EmptyResponse = data.0.json_rpc_call("refresh", None).await.unwrap();
      let transfer: TransfersResponse = data
        .0
        .json_rpc_call("get_transfer_by_txid", Some(json!({ "txid": hex::encode(tx.hash()) })))
        .await
        .unwrap();
      assert_eq!(transfer.transfer.subaddr_index, Index { major: 0, minor: 0 });
      assert_eq!(transfer.transfer.payment_id, hex::encode(data.1));
      assert_eq!(transfer.transfer.amount, 1000000);
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
      builder
        .add_payment(MoneroAddress::from_str(Network::Mainnet, &wallet_rpc_addr).unwrap(), 1000000);

      // Make 2 data that is the full 255 bytes
      for _ in 0 .. 2 {
        // Subtract 1 since we prefix data with 127
        let data = vec![b'a'; MAX_TX_EXTRA_NONCE_SIZE - 1];
        builder.add_data(data).unwrap();
      }

      (builder.build().unwrap(), wallet_rpc)
    },
    |_, tx: Transaction, _, data: Rpc<HttpRpc>| async move {
      // confirm receipt
      let _: EmptyResponse = data.json_rpc_call("refresh", None).await.unwrap();
      let transfer: TransfersResponse = data
        .json_rpc_call("get_transfer_by_txid", Some(json!({ "txid": hex::encode(tx.hash()) })))
        .await
        .unwrap();
      assert_eq!(transfer.transfer.subaddr_index, Index { major: 0, minor: 0 });
      assert_eq!(transfer.transfer.amount, 1000000);
    },
  ),
);
