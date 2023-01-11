use std::collections::HashSet;

use rand_core::OsRng;
use rand::RngCore;

use serde_json::json;
use serde::Deserialize;

use curve25519_dalek::scalar::Scalar;

use monero_serai::{
  rpc::{Rpc, EmptyResponse},
  wallet::address::{MoneroAddress, Network, AddressSpec},
  wallet::Scanner,
};
use zeroize::Zeroizing;

mod runner;

#[derive(Deserialize, Debug)]
struct AddressResponse {
  address: String
}

async fn create_rpc_wallet(wallet_rpc: &Rpc, spend: Scalar, view: Zeroizing<Scalar>, address: &str) {
  let params = json!({
      "file_name": "test_wallet",
      "password": "pass",
      "address": address,
      "spendkey": hex::encode(spend.as_bytes()),
      "viewkey": hex::encode(view.as_bytes())
  });
  wallet_rpc.json_rpc_call::<AddressResponse>("generate_from_keys", Some(params)).await.unwrap();
}

async fn make_tx(wallet_rpc: &Rpc, to: &str, amount: u64) -> [u8; 32] {
  #[derive(Deserialize, Debug)]
  struct TransactionResponse {
    tx_hash_list: [String; 1],
  }

  // refresh the wallet first
  wallet_rpc.json_rpc_call::<EmptyResponse>("refresh", Some(json!({}))).await.unwrap();

  let params = json!({
      "destinations" : [{
          "amount": amount,
          "address": to
      }],
      "get_tx_hex": false,
  });
  let resp =
  wallet_rpc.json_rpc_call::<TransactionResponse>("transfer_split", Some(params)).await.unwrap();

  if resp.tx_hash_list.is_empty() {
    panic!("something went wrong creating tx");
  }

  hex::decode(&resp.tx_hash_list[0]).unwrap().try_into().unwrap()
}

async fn wallet_rpc_address(wallet_rpc: &Rpc) -> Option<MoneroAddress> {

  let resp = wallet_rpc.json_rpc_call::<AddressResponse>(
    "get_address",
    Some(json!({"account_index": 0})))
  .await;

  if resp.is_err() {
    return None;
  }

  Some(MoneroAddress::from_str(Network::Mainnet, &resp.unwrap().address).unwrap())
}

async fn test_from_wallet_rpc_to(spec: AddressSpec) {
  let wallet_rpc = Rpc::new("http://127.0.0.1:6061".to_string()).unwrap();
  let daemon_rpc = runner::rpc().await;

  // initialize monero wallet rpc
  let wallet_rpc_addr = if let Some(addr) = wallet_rpc_address(&wallet_rpc).await {
    addr
  } else {
    let (spend, view, addr) = runner::random_address();
    daemon_rpc.generate_blocks(&addr.to_string(), 70).await.unwrap();
    create_rpc_wallet(&wallet_rpc, spend, view.view(), &addr.to_string()).await;
    addr
  };

  // make tx to an addr
  let (_, view_pair, _) = runner::random_address();
  let tx_id = make_tx(&wallet_rpc, &view_pair.address(Network::Mainnet, spec).to_string(), 1000000).await;

  // unlock it
  runner::mine_until_unlocked(&daemon_rpc, &wallet_rpc_addr.to_string(), tx_id).await;

  // create the scanner
  let mut scanner = Scanner::from_view(view_pair, Some(HashSet::new()));
  if let AddressSpec::Subaddress(index) = spec  {
    scanner.register_subaddress(index);
  }

  // retrieve it and confirm
  let tx = daemon_rpc.get_transaction(tx_id).await.unwrap();
  let output = scanner.scan_transaction(&tx).ignore_timelock().swap_remove(0);

  match spec {
    AddressSpec::Subaddress(index) => assert_eq!(output.metadata.subaddress, index),
    AddressSpec::Integrated(payment_id) => assert_eq!(output.metadata.payment_id, payment_id),
    _ => {},
  }
  assert_eq!(output.commitment().amount, 1000000);
}

async_sequential!(
  async fn test_receipt_of_wallet_rpc_tx_standard() {
    test_from_wallet_rpc_to(AddressSpec::Standard).await;
  }

  async fn test_receipt_of_wallet_rpc_tx_subaddress() {
    test_from_wallet_rpc_to(AddressSpec::Subaddress((0, 1))).await;
  }

  async fn test_receipt_of_wallet_rpc_tx_integrated() {
    let mut payment_id = [0u8; 8];
    OsRng.fill_bytes(&mut payment_id);
    test_from_wallet_rpc_to(AddressSpec::Integrated(payment_id)).await;
  }

);
