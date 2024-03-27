use std::{convert::TryFrom, sync::Arc, collections::HashMap};

use rand_core::OsRng;

use group::Group;
use k256::ProjectivePoint;
use frost::{
  curve::Secp256k1,
  Participant, ThresholdKeys,
  algorithm::IetfSchnorr,
  tests::{algorithm_machines, sign},
};

use ethers_core::{
  types::{H160, U256, Bytes},
  utils::{Anvil, AnvilInstance},
};
use ethers_providers::{Middleware, Provider, Http};

use crate::{
  crypto::*,
  deployer::Deployer,
  router::{Router, abi as router},
  tests::{key_gen, fund_account},
};

async fn setup_test(
) -> (AnvilInstance, u64, Router, HashMap<Participant, ThresholdKeys<Secp256k1>>, PublicKey) {
  let anvil = Anvil::new().spawn();

  let provider = Provider::<Http>::try_from(anvil.endpoint()).unwrap();
  let chain_id = provider.get_chainid().await.unwrap().as_u64();
  let wallet = anvil.keys()[0].clone().into();
  let client = Arc::new(provider);

  assert!(Deployer::new(client.clone()).await.unwrap().is_none());
  let tx = Deployer::deployment_tx(chain_id).unwrap();
  fund_account(&client, &wallet, tx.from, tx.gas * tx.gas_price.unwrap()).await.unwrap();
  let pending_tx = client.send_raw_transaction(tx.rlp()).await.unwrap();
  let receipt = pending_tx.await.unwrap().unwrap();
  assert_eq!(receipt.status, Some(1.into()));

  let deployer = Deployer::new(client.clone()).await.unwrap().unwrap();

  let (keys, public_key) = key_gen();
  assert_eq!(
    deployer.deploy_router(&public_key).send().await.unwrap().await.unwrap().unwrap().status,
    Some(1.into())
  );
  let contract = deployer.find_router(client, &public_key).await.unwrap().unwrap();

  (anvil, chain_id, contract, keys, public_key)
}

#[tokio::test]
async fn test_deploy_contract() {
  let (_anvil, _, router, _, public_key) = setup_test().await;

  assert_eq!(router.serai_key().await.unwrap(), public_key);
  assert_eq!(router.nonce().await.unwrap(), 0.into());
  // TODO: Check it emitted SeraiKeyUpdated(public_key) at its genesis
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
async fn test_router_update_serai_key() {
  let (_anvil, chain_id, contract, keys, public_key) = setup_test().await;

  let next_key = loop {
    let point = ProjectivePoint::random(&mut OsRng);
    let Some(next_key) = PublicKey::new(point) else { continue };
    break next_key;
  };

  let message = Router::update_serai_key_message(chain_id.into(), &next_key);
  let sig = hash_and_sign(&keys, &public_key, &message);

  let receipt =
    contract.update_serai_key(&next_key, &sig).send().await.unwrap().await.unwrap().unwrap();
  assert_eq!(receipt.status, Some(1.into()));

  assert_eq!(contract.serai_key().await.unwrap(), next_key);
  // TODO: Check logs

  println!("gas used: {:?}", receipt.cumulative_gas_used);
  println!("logs: {:?}", receipt.logs);
}

#[tokio::test]
async fn test_router_execute() {
  let (_anvil, chain_id, contract, keys, public_key) = setup_test().await;

  let to = H160([0u8; 20]);
  let value = U256([0u64; 4]);
  let data = Bytes::from([0]);
  let tx = router::OutInstruction { to, value, data: data.clone() };
  let txs = vec![tx];

  let nonce = contract.nonce().await.unwrap();
  assert_eq!(nonce, 0.into());

  let message = Router::execute_message(chain_id.into(), nonce, txs.clone());
  let sig = hash_and_sign(&keys, &public_key, &message);

  let tx = contract.execute(txs, &sig);
  let pending_tx = tx.send().await.unwrap();
  let receipt = pending_tx.await.unwrap().unwrap();
  assert_eq!(receipt.status, Some(1.into()));

  assert_eq!(contract.nonce().await.unwrap(), 1.into());
  // TODO: Check logs

  println!("gas used: {:?}", receipt.cumulative_gas_used);
  println!("logs: {:?}", receipt.logs);
}
