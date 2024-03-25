use std::{sync::Arc, time::Duration, fs::File, collections::HashMap};

use rand_core::OsRng;

use group::ff::PrimeField;
use k256::{Scalar, ProjectivePoint, elliptic_curve::ops::Reduce};
use frost::{curve::Secp256k1, Participant, ThresholdKeys, tests::key_gen as frost_key_gen};

use ethers_core::{
  types::{U256, H160, Signature as EthersSignature},
  abi::Abi,
};
use ethers_contract::ContractFactory;
use ethers_providers::{Middleware, Provider, Http};

use crate::crypto::PublicKey;

mod crypto;
use crypto::ecrecover;

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
  let abi: Abi =
    serde_json::from_reader(File::open(format!("./artifacts/{name}.abi")).unwrap()).unwrap();

  let hex_bin_buf = std::fs::read_to_string(format!("./artifacts/{name}.bin")).unwrap();
  let hex_bin =
    if let Some(stripped) = hex_bin_buf.strip_prefix("0x") { stripped } else { &hex_bin_buf };
  let bin = hex::decode(hex_bin).unwrap();
  let factory = ContractFactory::new(abi, bin.clone().into(), client.clone());

  let mut deployment_tx = factory.deploy(()).ok()?.tx;
  deployment_tx.set_chain_id(chain_id);
  deployment_tx.set_gas(1_000_000);
  let (max_fee_per_gas, max_priority_fee_per_gas) =
    client.estimate_eip1559_fees(None).await.ok()?;
  deployment_tx.as_eip1559_mut().unwrap().max_fee_per_gas = Some(max_fee_per_gas);
  deployment_tx.as_eip1559_mut().unwrap().max_priority_fee_per_gas = Some(max_priority_fee_per_gas);

  let sig_hash = deployment_tx.sighash();

  // EIP-155 v
  let mut r = crypto::hash_to_scalar(&[bin.as_slice(), b"r"].concat());
  let mut s = crypto::hash_to_scalar(&[bin.as_slice(), b"s"].concat());
  let (deployment_tx, deployment_address) = loop {
    let v = (u64::from(chain_id) * 2) + 35;
    let deployment_tx = deployment_tx.rlp_signed(&EthersSignature {
      v,
      r: r.to_repr().as_slice().into(),
      s: s.to_repr().as_slice().into(),
    });
    let Some(deployment_address) =
      ecrecover(<Scalar as Reduce<k256::U256>>::reduce_bytes(&sig_hash.0.into()), 0, r, s)
    else {
      r = crypto::hash_to_scalar(r.to_repr().as_ref());
      s = crypto::hash_to_scalar(s.to_repr().as_ref());
      continue;
    };
    break (deployment_tx, deployment_address);
  };

  // Fund the deployer address
  {
    let mut funding_tx =
      ethers_core::types::transaction::eip2718::TypedTransaction::Eip1559(Default::default());
    funding_tx.set_chain_id(chain_id);
    funding_tx.set_gas(21_000);
    funding_tx.as_eip1559_mut().unwrap().max_fee_per_gas = Some(max_fee_per_gas);
    funding_tx.as_eip1559_mut().unwrap().max_priority_fee_per_gas = Some(max_priority_fee_per_gas);
    funding_tx.set_to(H160::from(deployment_address));
    funding_tx.set_value(U256::from(1_000_000) * (max_fee_per_gas + max_fee_per_gas));

    let (sig, rid) = wallet.sign_prehash_recoverable(funding_tx.sighash().as_ref()).unwrap();

    // EIP-155 v
    let mut v = u64::from(rid.to_byte());
    assert!((v == 0) || (v == 1));
    v += u64::from((chain_id * 2) + 35);

    let funding_tx = funding_tx.rlp_signed(&EthersSignature {
      v,
      r: sig.r().to_repr().as_slice().into(),
      s: sig.s().to_repr().as_slice().into(),
    });

    let pending_tx = client.send_raw_transaction(funding_tx).await.ok()?;
    let mut receipt;
    while {
      receipt = client.get_transaction_receipt(pending_tx.tx_hash()).await.ok()?;
      receipt.is_none()
    } {
      tokio::time::sleep(Duration::from_secs(6)).await;
    }
    let receipt = receipt.unwrap();
    assert!(receipt.status == Some(1.into()));
  }

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
