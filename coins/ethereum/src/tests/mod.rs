use std::{sync::Arc, collections::HashMap};

use rand_core::OsRng;

use k256::{Scalar, ProjectivePoint};
use frost::{curve::Secp256k1, Participant, ThresholdKeys, tests::key_gen as frost_key_gen};

use alloy_core::{
  primitives::{Address, U256, Bytes, TxKind},
  hex::FromHex,
};
use alloy_consensus::{SignableTransaction, TxLegacy};

use alloy_rpc_types_eth::TransactionReceipt;
use alloy_simple_request_transport::SimpleRequest;
use alloy_provider::{Provider, RootProvider};

use crate::crypto::{address, deterministically_sign, PublicKey};

#[cfg(test)]
mod crypto;

#[cfg(test)]
mod abi;
#[cfg(test)]
mod schnorr;
#[cfg(test)]
mod router;

pub fn key_gen() -> (HashMap<Participant, ThresholdKeys<Secp256k1>>, PublicKey) {
  let mut keys = frost_key_gen::<_, Secp256k1>(&mut OsRng);
  let mut group_key = keys[&Participant::new(1).unwrap()].group_key();

  let mut offset = Scalar::ZERO;
  while PublicKey::new(group_key).is_none() {
    offset += Scalar::ONE;
    group_key += ProjectivePoint::GENERATOR;
  }
  for keys in keys.values_mut() {
    *keys = keys.offset(offset);
  }
  let public_key = PublicKey::new(group_key).unwrap();

  (keys, public_key)
}

// TODO: Use a proper error here
pub async fn send(
  provider: &RootProvider<SimpleRequest>,
  wallet: &k256::ecdsa::SigningKey,
  mut tx: TxLegacy,
) -> Option<TransactionReceipt> {
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
  tx.encode_with_signature_fields(&sig.into(), &mut bytes);
  let pending_tx = provider.send_raw_transaction(&bytes).await.ok()?;
  pending_tx.get_receipt().await.ok()
}

pub async fn fund_account(
  provider: &RootProvider<SimpleRequest>,
  wallet: &k256::ecdsa::SigningKey,
  to_fund: Address,
  value: U256,
) -> Option<()> {
  let funding_tx =
    TxLegacy { to: TxKind::Call(to_fund), gas_limit: 21_000, value, ..Default::default() };
  assert!(send(provider, wallet, funding_tx).await.unwrap().status());

  Some(())
}

// TODO: Use a proper error here
pub async fn deploy_contract(
  client: Arc<RootProvider<SimpleRequest>>,
  wallet: &k256::ecdsa::SigningKey,
  name: &str,
) -> Option<Address> {
  let hex_bin_buf = std::fs::read_to_string(format!("./artifacts/{name}.bin")).unwrap();
  let hex_bin =
    if let Some(stripped) = hex_bin_buf.strip_prefix("0x") { stripped } else { &hex_bin_buf };
  let bin = Bytes::from_hex(hex_bin).unwrap();

  let deployment_tx = TxLegacy {
    chain_id: None,
    nonce: 0,
    // 100 gwei
    gas_price: 100_000_000_000u128,
    gas_limit: 1_000_000,
    to: TxKind::Create,
    value: U256::ZERO,
    input: bin,
  };

  let deployment_tx = deterministically_sign(&deployment_tx);

  // Fund the deployer address
  fund_account(
    &client,
    wallet,
    deployment_tx.recover_signer().unwrap(),
    U256::from(deployment_tx.tx().gas_limit) * U256::from(deployment_tx.tx().gas_price),
  )
  .await?;

  let (deployment_tx, sig, _) = deployment_tx.into_parts();
  let mut bytes = vec![];
  deployment_tx.encode_with_signature_fields(&sig, &mut bytes);
  let pending_tx = client.send_raw_transaction(&bytes).await.ok()?;
  let receipt = pending_tx.get_receipt().await.ok()?;
  assert!(receipt.status());

  Some(receipt.contract_address.unwrap())
}
