use std::{convert::TryFrom, sync::Arc, collections::HashMap};

use rand_core::OsRng;

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
  crypto::{PublicKey, EthereumHram, Signature},
  router::{Router, abi as router},
  tests::{key_gen, deploy_contract},
};

async fn setup_test(
) -> (u32, AnvilInstance, Router, HashMap<Participant, ThresholdKeys<Secp256k1>>, PublicKey) {
  let anvil = Anvil::new().spawn();

  let provider = Provider::<Http>::try_from(anvil.endpoint()).unwrap();
  let chain_id = provider.get_chainid().await.unwrap().as_u32();
  let wallet = anvil.keys()[0].clone().into();
  let client = Arc::new(provider);

  let contract_address =
    deploy_contract(chain_id, client.clone(), &wallet, "Router").await.unwrap();
  let contract = Router::new(client.clone(), contract_address.into());

  let (keys, public_key) = key_gen();

  // Set the key to the threshold keys
  let tx = contract.initialize(&public_key);
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
  message: &[u8],
) -> Signature {
  let algo = IetfSchnorr::<Secp256k1, EthereumHram>::ietf();
  let sig =
    sign(&mut OsRng, &algo, keys.clone(), algorithm_machines(&mut OsRng, &algo, keys), message);

  Signature::new(public_key, message, sig).unwrap()
}

#[tokio::test]
async fn test_router_execute() {
  let (chain_id, _anvil, contract, keys, public_key) = setup_test().await;

  let to = H160([0u8; 20]);
  let value = U256([0u64; 4]);
  let data = Bytes::from([0]);
  let tx = router::OutInstruction { to, value, data: data.clone() };
  let txs = vec![tx];

  let nonce = contract.nonce().await.unwrap();

  let encoded = ("execute".to_string(), U256::from(chain_id), nonce, txs.clone()).encode();
  let sig = hash_and_sign(&keys, &public_key, &encoded);

  let tx = contract.execute(txs, &sig).gas(300_000);
  let pending_tx = tx.send().await.unwrap();
  let receipt = dbg!(pending_tx.await.unwrap().unwrap());
  assert!(receipt.status == Some(1.into()));

  println!("gas used: {:?}", receipt.cumulative_gas_used);
  println!("logs: {:?}", receipt.logs);
}
