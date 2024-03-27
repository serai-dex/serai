use std::{sync::Arc, collections::HashMap};

use rand_core::OsRng;

use group::ff::PrimeField;
use k256::{Scalar, ProjectivePoint};
use frost::{curve::Secp256k1, Participant, ThresholdKeys, tests::key_gen as frost_key_gen};

use ethers_core::types::{U256, H160, Signature as EthersSignature, TransactionRequest};
use ethers_providers::{Middleware, Provider, Http};

use crate::crypto::{address, deterministically_sign, PublicKey};

mod crypto;

mod abi;
mod schnorr;
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

pub async fn fund_account(
  provider: &Provider<Http>,
  wallet: &k256::ecdsa::SigningKey,
  to_fund: H160,
  value: U256,
) -> Option<()> {
  let chain_id = provider.get_chainid().await.unwrap().as_u64();

  let verifying_key = *wallet.verifying_key().as_affine();

  let funding_tx = TransactionRequest {
    from: None,
    to: Some(to_fund.into()),
    gas: Some(21_000.into()),
    // 100 gwei
    gas_price: Some(100_000_000_000u64.into()),
    value: Some(value),
    data: None,
    nonce: Some(
      provider.get_transaction_count(H160(address(&verifying_key.into())), None).await.unwrap(),
    ),
    chain_id: Some(chain_id.into()),
  };

  let (sig, rid) = wallet.sign_prehash_recoverable(funding_tx.sighash().as_ref()).unwrap();

  // EIP-155 v
  let mut v = u64::from(rid.to_byte());
  assert!((v == 0) || (v == 1));
  v += (chain_id * 2) + 35;

  let funding_tx = funding_tx.rlp_signed(&EthersSignature {
    v,
    r: sig.r().to_repr().as_slice().into(),
    s: sig.s().to_repr().as_slice().into(),
  });

  let pending_tx = provider.send_raw_transaction(funding_tx).await.ok()?;
  let receipt = pending_tx.await.ok()??;
  assert!(receipt.status == Some(1.into()));
  Some(())
}

// TODO:
/*
  1) Deploy Deployer from an account with an unknown private key.
  2) Use CREATE2 to deploy the Router *with* the DKG'd address (removing initialize).
*/
// TODO: Use a proper error here
pub async fn deploy_contract(
  chain_id: u32,
  client: Arc<Provider<Http>>,
  wallet: &k256::ecdsa::SigningKey,
  name: &str,
) -> Option<H160> {
  let hex_bin_buf = std::fs::read_to_string(format!("./artifacts/{name}.bin")).unwrap();
  let hex_bin =
    if let Some(stripped) = hex_bin_buf.strip_prefix("0x") { stripped } else { &hex_bin_buf };
  let bin = hex::decode(hex_bin).unwrap();

  let deployment_tx = TransactionRequest {
    from: None,
    to: None,
    gas: Some(1_000_000u64.into()),
    // 100 gwei
    gas_price: Some(100_000_000_000u64.into()),
    value: Some(U256::zero()),
    data: Some(bin.into()),
    nonce: Some(U256::zero()),
    chain_id: Some(chain_id.into()),
  };

  let deployment_tx = deterministically_sign(chain_id.into(), &deployment_tx).unwrap();

  // Fund the deployer address
  fund_account(
    &client,
    wallet,
    deployment_tx.from,
    deployment_tx.gas * deployment_tx.gas_price.unwrap(),
  )
  .await?;

  let pending_tx = client.send_raw_transaction(deployment_tx.rlp()).await.ok()?;
  let receipt = pending_tx.await.ok()??;
  assert!(receipt.status == Some(1.into()));

  Some(receipt.contract_address.unwrap())
}
