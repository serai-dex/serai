use std::{sync::Arc, time::Duration, fs::File, collections::HashMap};

use rand_core::OsRng;

use group::ff::PrimeField;
use k256::{Scalar, ProjectivePoint};
use frost::{curve::Secp256k1, Participant, ThresholdKeys, tests::key_gen as frost_key_gen};

use ethers_core::{
  types::{H160, Signature as EthersSignature},
  abi::Abi,
};
use ethers_contract::ContractFactory;
use ethers_providers::{Middleware, Provider, Http};

use crate::crypto::PublicKey;

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

// TODO: Replace with a contract deployment from an unknown account, so the environment solely has
// to fund the deployer, not create/pass a wallet
// TODO: Deterministic deployments across chains
// TODO: Use a proper error here
pub async fn deploy_contract(
  chain_id: u32,
  client: Arc<Provider<Http>>,
  wallet: &k256::ecdsa::SigningKey,
  name: &str,
) -> Option<H160> {
  let abi: Abi =
    serde_json::from_reader(File::open(format!("./artifacts/{name}.abi")).unwrap()).unwrap();

  let hex_bin_buf = std::fs::read_to_string(format!("./artifacts/{name}.bin")).unwrap();
  let hex_bin =
    if let Some(stripped) = hex_bin_buf.strip_prefix("0x") { stripped } else { &hex_bin_buf };
  let bin = hex::decode(hex_bin).unwrap();
  let factory = ContractFactory::new(abi, bin.into(), client.clone());

  let mut deployment_tx = factory.deploy(()).ok()?.tx;
  deployment_tx.set_chain_id(chain_id);
  deployment_tx.set_gas(1_000_000);
  let (max_fee_per_gas, max_priority_fee_per_gas) =
    client.estimate_eip1559_fees(None).await.ok()?;
  deployment_tx.as_eip1559_mut().unwrap().max_fee_per_gas = Some(max_fee_per_gas);
  deployment_tx.as_eip1559_mut().unwrap().max_priority_fee_per_gas = Some(max_priority_fee_per_gas);

  let sig_hash = deployment_tx.sighash();
  let (sig, rid) = wallet.sign_prehash_recoverable(sig_hash.as_ref()).unwrap();

  // EIP-155 v
  let mut v = u64::from(rid.to_byte());
  assert!((v == 0) || (v == 1));
  v += u64::from((chain_id * 2) + 35);

  let r = sig.r().to_repr();
  let r_ref: &[u8] = r.as_ref();
  let s = sig.s().to_repr();
  let s_ref: &[u8] = s.as_ref();
  let deployment_tx =
    deployment_tx.rlp_signed(&EthersSignature { r: r_ref.into(), s: s_ref.into(), v });

  let pending_tx = client.send_raw_transaction(deployment_tx).await.ok()?;

  let mut receipt;
  while {
    receipt = client.get_transaction_receipt(pending_tx.tx_hash()).await.ok()?;
    receipt.is_none()
  } {
    tokio::time::sleep(Duration::from_secs(6)).await;
  }
  let receipt = receipt.unwrap();
  assert!(receipt.status == Some(1.into()));

  Some(receipt.contract_address.unwrap())
}
