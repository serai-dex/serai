use std::{convert::TryFrom, sync::Arc, collections::HashMap};

use rand_core::OsRng;

use group::ff::PrimeField;
use frost::{
  curve::Secp256k1,
  Participant, ThresholdKeys,
  algorithm::IetfSchnorr,
  tests::{algorithm_machines, sign},
};

use ethers_core::{
  types::{H160, U256, Bytes},
  abi::AbiEncode,
  utils::{Anvil, AnvilInstance},
};
use ethers_providers::{Middleware, Provider, Http};

use crate::{
  crypto::{keccak256, PublicKey, EthereumHram, Signature},
  router::{self, *},
  tests::{key_gen, deploy_contract},
};

async fn setup_test() -> (
  u32,
  AnvilInstance,
  Router<Provider<Http>>,
  HashMap<Participant, ThresholdKeys<Secp256k1>>,
  PublicKey,
) {
  let anvil = Anvil::new().spawn();

  let provider = Provider::<Http>::try_from(anvil.endpoint()).unwrap();
  let chain_id = provider.get_chainid().await.unwrap().as_u32();
  let wallet = anvil.keys()[0].clone().into();
  let client = Arc::new(provider);

  let contract_address =
    deploy_contract(chain_id, client.clone(), &wallet, "Router").await.unwrap();
  let contract = Router::new(contract_address, client.clone());

  let (keys, public_key) = key_gen();

  // Set the key to the threshold keys
  let tx = contract.init_serai_key(public_key.px.to_repr().into()).gas(100_000);
  let pending_tx = tx.send().await.unwrap();
  let receipt = pending_tx.await.unwrap().unwrap();
  assert!(receipt.status == Some(1.into()));

  (chain_id, anvil, contract, keys, public_key)
}

#[tokio::test]
async fn test_deploy_contract() {
  setup_test().await;
}

pub fn hash_and_sign(
  keys: &HashMap<Participant, ThresholdKeys<Secp256k1>>,
  public_key: &PublicKey,
  chain_id: U256,
  message: &[u8],
) -> Signature {
  let hashed_message = keccak256(message);

  let mut chain_id_bytes = [0; 32];
  chain_id.to_big_endian(&mut chain_id_bytes);
  let full_message = &[chain_id_bytes.as_slice(), &hashed_message].concat();

  let algo = IetfSchnorr::<Secp256k1, EthereumHram>::ietf();
  let sig = sign(
    &mut OsRng,
    &algo,
    keys.clone(),
    algorithm_machines(&mut OsRng, &algo, keys),
    full_message,
  );

  Signature::new(public_key, k256::U256::from_words(chain_id.0), message, sig).unwrap()
}

#[tokio::test]
async fn test_router_execute() {
  let (chain_id, _anvil, contract, keys, public_key) = setup_test().await;

  let to = H160([0u8; 20]);
  let value = U256([0u64; 4]);
  let data = Bytes::from([0]);
  let tx = OutInstruction { to, value, data: data.clone() };

  let nonce_call = contract.nonce();
  let nonce = nonce_call.call().await.unwrap();

  let encoded =
    ("execute".to_string(), nonce, vec![router::OutInstruction { to, value, data }]).encode();
  let sig = hash_and_sign(&keys, &public_key, chain_id.into(), &encoded);

  let tx = contract
    .execute(vec![tx], router::Signature { c: sig.c.to_repr().into(), s: sig.s.to_repr().into() })
    .gas(300_000);
  let pending_tx = tx.send().await.unwrap();
  let receipt = dbg!(pending_tx.await.unwrap().unwrap());
  assert!(receipt.status == Some(1.into()));

  println!("gas used: {:?}", receipt.cumulative_gas_used);
  println!("logs: {:?}", receipt.logs);
}
