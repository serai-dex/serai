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
  types::{H160, U256},
  utils::{Anvil, AnvilInstance},
};
use ethers_providers::{Middleware, Provider, Http};

use crate::{
  crypto::*,
  deployer::Deployer,
  router::{Router, abi as router},
  tests::{key_gen, fund_account},
};

async fn setup_test() -> (
  AnvilInstance,
  Arc<Provider<Http>>,
  u64,
  Router,
  HashMap<Participant, ThresholdKeys<Secp256k1>>,
  PublicKey,
) {
  let anvil = Anvil::new().spawn();

  let provider = Provider::<Http>::try_from(anvil.endpoint()).unwrap();
  let chain_id = provider.get_chainid().await.unwrap().as_u64();
  let wallet = anvil.keys()[0].clone().into();
  let client = Arc::new(provider);

  // Make sure the Deployer constructor returns None, as it doesn't exist yet
  assert!(Deployer::new(client.clone()).await.unwrap().is_none());

  // Deploy the Deployer
  let tx = Deployer::deployment_tx(chain_id).unwrap();
  fund_account(&client, &wallet, tx.from, tx.gas * tx.gas_price.unwrap()).await.unwrap();
  let pending_tx = client.send_raw_transaction(tx.rlp()).await.unwrap();
  let receipt = pending_tx.await.unwrap().unwrap();
  assert_eq!(receipt.status, Some(1.into()));
  let deployer = Deployer::new(client.clone()).await.unwrap().unwrap();

  let (keys, public_key) = key_gen();

  // Verify the Router constructor returns None, as it doesn't exist yet
  assert!(deployer.find_router(client.clone(), &public_key).await.unwrap().is_none());

  // Deploy the router
  assert_eq!(
    deployer.deploy_router(&public_key).send().await.unwrap().await.unwrap().unwrap().status,
    Some(1.into())
  );
  let contract = deployer.find_router(client.clone(), &public_key).await.unwrap().unwrap();

  (anvil, client, chain_id, contract, keys, public_key)
}

async fn latest_block_hash(client: &Provider<Http>) -> [u8; 32] {
  client.get_block(client.get_block_number().await.unwrap()).await.unwrap().unwrap().hash.unwrap().0
}

#[tokio::test]
async fn test_deploy_contract() {
  let (_anvil, client, _, router, _, public_key) = setup_test().await;

  let block_hash = latest_block_hash(&client).await;
  assert_eq!(router.serai_key(block_hash).await.unwrap(), public_key);
  assert_eq!(router.nonce(block_hash).await.unwrap(), 0.into());
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
  let (_anvil, client, chain_id, contract, keys, public_key) = setup_test().await;

  let next_key = loop {
    let point = ProjectivePoint::random(&mut OsRng);
    let Some(next_key) = PublicKey::new(point) else { continue };
    break next_key;
  };

  let message = Router::update_serai_key_message(chain_id.into(), &next_key);
  let sig = hash_and_sign(&keys, &public_key, &message);

  let first_block_hash = latest_block_hash(&client).await;
  assert_eq!(contract.serai_key(first_block_hash).await.unwrap(), public_key);

  let receipt =
    contract.update_serai_key(&next_key, &sig).send().await.unwrap().await.unwrap().unwrap();
  assert_eq!(receipt.status, Some(1.into()));

  let second_block_hash = latest_block_hash(&client).await;
  assert_eq!(contract.serai_key(second_block_hash).await.unwrap(), next_key);
  // Check this does still offer the historical state
  assert_eq!(contract.serai_key(first_block_hash).await.unwrap(), public_key);
  // TODO: Check logs

  println!("gas used: {:?}", receipt.cumulative_gas_used);
  println!("logs: {:?}", receipt.logs);
}

#[tokio::test]
async fn test_router_execute() {
  let (_anvil, client, chain_id, contract, keys, public_key) = setup_test().await;

  let to = H160([0u8; 20]);
  let value = U256([0u64; 4]);
  let tx = router::OutInstruction { to, value, calls: vec![] };
  let txs = vec![tx];

  let first_block_hash = latest_block_hash(&client).await;
  let nonce = contract.nonce(first_block_hash).await.unwrap();
  assert_eq!(nonce, 0.into());

  let message = Router::execute_message(chain_id.into(), nonce, txs.clone());
  let sig = hash_and_sign(&keys, &public_key, &message);

  let tx = contract.execute(txs, &sig);
  let pending_tx = tx.send().await.unwrap();
  let receipt = pending_tx.await.unwrap().unwrap();
  assert_eq!(receipt.status, Some(1.into()));

  let second_block_hash = latest_block_hash(&client).await;
  assert_eq!(contract.nonce(second_block_hash).await.unwrap(), 1.into());
  // Check this does still offer the historical state
  assert_eq!(contract.nonce(first_block_hash).await.unwrap(), 0.into());
  // TODO: Check logs

  println!("gas used: {:?}", receipt.cumulative_gas_used);
  println!("logs: {:?}", receipt.logs);
}
