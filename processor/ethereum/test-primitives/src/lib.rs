#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use k256::{elliptic_curve::sec1::ToEncodedPoint, ProjectivePoint};

use alloy_core::{
  primitives::{Address, U256, Bytes, PrimitiveSignature, TxKind},
  hex::FromHex,
};
use alloy_consensus::{SignableTransaction, TxLegacy, Signed};

use alloy_rpc_types_eth::TransactionReceipt;
use alloy_simple_request_transport::SimpleRequest;
use alloy_provider::{Provider, RootProvider};

use ethereum_primitives::{keccak256, deterministically_sign};

fn address(point: &ProjectivePoint) -> [u8; 20] {
  let encoded_point = point.to_encoded_point(false);
  // Last 20 bytes of the hash of the concatenated x and y coordinates
  // We obtain the concatenated x and y coordinates via the uncompressed encoding of the point
  keccak256(&encoded_point.as_ref()[1 .. 65])[12 ..].try_into().unwrap()
}

/// Fund an account.
pub async fn fund_account(provider: &RootProvider<SimpleRequest>, address: Address, value: U256) {
  let _: () = provider
    .raw_request("anvil_setBalance".into(), [address.to_string(), value.to_string()])
    .await
    .unwrap();
}

/// Publish an already-signed transaction.
pub async fn publish_tx(
  provider: &RootProvider<SimpleRequest>,
  tx: Signed<TxLegacy>,
) -> TransactionReceipt {
  // Fund the sender's address
  fund_account(
    provider,
    tx.recover_signer().unwrap(),
    (U256::from(tx.tx().gas_limit) * U256::from(tx.tx().gas_price)) + tx.tx().value,
  )
  .await;

  let (tx, sig, _) = tx.into_parts();
  let mut bytes = vec![];
  tx.into_signed(sig).eip2718_encode(&mut bytes);
  let pending_tx = provider.send_raw_transaction(&bytes).await.unwrap();
  pending_tx.get_receipt().await.unwrap()
}

/// Deploy a contract.
///
/// The contract deployment will be done by a random account.
pub async fn deploy_contract(
  provider: &RootProvider<SimpleRequest>,
  file_path: &str,
  constructor_arguments: &[u8],
) -> Address {
  let hex_bin_buf = std::fs::read_to_string(file_path).unwrap();
  let hex_bin =
    if let Some(stripped) = hex_bin_buf.strip_prefix("0x") { stripped } else { &hex_bin_buf };
  let mut bin = Vec::<u8>::from(Bytes::from_hex(hex_bin).unwrap());
  bin.extend(constructor_arguments);

  let deployment_tx = TxLegacy {
    chain_id: None,
    nonce: 0,
    // 100 gwei
    gas_price: 100_000_000_000u128,
    gas_limit: 1_000_000,
    to: TxKind::Create,
    value: U256::ZERO,
    input: bin.into(),
  };

  let deployment_tx = deterministically_sign(deployment_tx);

  let receipt = publish_tx(provider, deployment_tx).await;
  assert!(receipt.status());

  receipt.contract_address.unwrap()
}

/// Sign and send a transaction from the specified wallet.
///
/// This assumes the wallet is funded.
pub async fn send(
  provider: &RootProvider<SimpleRequest>,
  wallet: &k256::ecdsa::SigningKey,
  mut tx: TxLegacy,
) -> TransactionReceipt {
  let verifying_key = *wallet.verifying_key().as_affine();
  let address = Address::from(address(&verifying_key.into()));

  // https://github.com/alloy-rs/alloy/issues/539
  // let chain_id = provider.get_chain_id().await.unwrap();
  // tx.chain_id = Some(chain_id);
  tx.chain_id = None;
  tx.nonce = provider.get_transaction_count(address).await.unwrap();
  // 100 gwei
  tx.gas_price = 100_000_000_000u128;

  let sig = wallet.sign_prehash_recoverable(tx.signature_hash().as_ref()).unwrap();
  assert_eq!(address, tx.clone().into_signed(sig.into()).recover_signer().unwrap());
  assert!(
    provider.get_balance(address).await.unwrap() >
      ((U256::from(tx.gas_price) * U256::from(tx.gas_limit)) + tx.value)
  );

  let mut bytes = vec![];
  tx.into_signed(PrimitiveSignature::from(sig)).eip2718_encode(&mut bytes);
  let pending_tx = provider.send_raw_transaction(&bytes).await.unwrap();
  pending_tx.get_receipt().await.unwrap()
}
