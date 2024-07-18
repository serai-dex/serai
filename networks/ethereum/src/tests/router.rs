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

use alloy_core::primitives::{Address, U256};

use alloy_simple_request_transport::SimpleRequest;
use alloy_rpc_types_eth::BlockTransactionsKind;
use alloy_rpc_client::ClientBuilder;
use alloy_provider::{Provider, RootProvider};

use alloy_node_bindings::{Anvil, AnvilInstance};

use crate::{
  crypto::*,
  deployer::Deployer,
  router::{Router, abi as router},
  tests::{key_gen, send, fund_account},
};

async fn setup_test() -> (
  AnvilInstance,
  Arc<RootProvider<SimpleRequest>>,
  u64,
  Router,
  HashMap<Participant, ThresholdKeys<Secp256k1>>,
  PublicKey,
) {
  let anvil = Anvil::new().spawn();

  let provider = RootProvider::new(
    ClientBuilder::default().transport(SimpleRequest::new(anvil.endpoint()), true),
  );
  let chain_id = provider.get_chain_id().await.unwrap();
  let wallet = anvil.keys()[0].clone().into();
  let client = Arc::new(provider);

  // Make sure the Deployer constructor returns None, as it doesn't exist yet
  assert!(Deployer::new(client.clone()).await.unwrap().is_none());

  // Deploy the Deployer
  let tx = Deployer::deployment_tx();
  fund_account(
    &client,
    &wallet,
    tx.recover_signer().unwrap(),
    U256::from(tx.tx().gas_limit) * U256::from(tx.tx().gas_price),
  )
  .await
  .unwrap();

  let (tx, sig, _) = tx.into_parts();
  let mut bytes = vec![];
  tx.encode_with_signature_fields(&sig, &mut bytes);

  let pending_tx = client.send_raw_transaction(&bytes).await.unwrap();
  let receipt = pending_tx.get_receipt().await.unwrap();
  assert!(receipt.status());
  let deployer =
    Deployer::new(client.clone()).await.expect("network error").expect("deployer wasn't deployed");

  let (keys, public_key) = key_gen();

  // Verify the Router constructor returns None, as it doesn't exist yet
  assert!(deployer.find_router(client.clone(), &public_key).await.unwrap().is_none());

  // Deploy the router
  let receipt = send(&client, &anvil.keys()[0].clone().into(), deployer.deploy_router(&public_key))
    .await
    .unwrap();
  assert!(receipt.status());
  let contract = deployer.find_router(client.clone(), &public_key).await.unwrap().unwrap();

  (anvil, client, chain_id, contract, keys, public_key)
}

async fn latest_block_hash(client: &RootProvider<SimpleRequest>) -> [u8; 32] {
  client
    .get_block(client.get_block_number().await.unwrap().into(), BlockTransactionsKind::Hashes)
    .await
    .unwrap()
    .unwrap()
    .header
    .hash
    .unwrap()
    .0
}

#[tokio::test]
async fn test_deploy_contract() {
  let (_anvil, client, _, router, _, public_key) = setup_test().await;

  let block_hash = latest_block_hash(&client).await;
  assert_eq!(router.serai_key(block_hash).await.unwrap(), public_key);
  assert_eq!(router.nonce(block_hash).await.unwrap(), U256::try_from(1u64).unwrap());
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
  let (anvil, client, chain_id, contract, keys, public_key) = setup_test().await;

  let next_key = loop {
    let point = ProjectivePoint::random(&mut OsRng);
    let Some(next_key) = PublicKey::new(point) else { continue };
    break next_key;
  };

  let message = Router::update_serai_key_message(
    U256::try_from(chain_id).unwrap(),
    U256::try_from(1u64).unwrap(),
    &next_key,
  );
  let sig = hash_and_sign(&keys, &public_key, &message);

  let first_block_hash = latest_block_hash(&client).await;
  assert_eq!(contract.serai_key(first_block_hash).await.unwrap(), public_key);

  let receipt =
    send(&client, &anvil.keys()[0].clone().into(), contract.update_serai_key(&next_key, &sig))
      .await
      .unwrap();
  assert!(receipt.status());

  let second_block_hash = latest_block_hash(&client).await;
  assert_eq!(contract.serai_key(second_block_hash).await.unwrap(), next_key);
  // Check this does still offer the historical state
  assert_eq!(contract.serai_key(first_block_hash).await.unwrap(), public_key);
  // TODO: Check logs

  println!("gas used: {:?}", receipt.gas_used);
  // println!("logs: {:?}", receipt.logs);
}

#[tokio::test]
async fn test_router_execute() {
  let (anvil, client, chain_id, contract, keys, public_key) = setup_test().await;

  let to = Address::from([0; 20]);
  let value = U256::ZERO;
  let tx = router::OutInstruction { to, value, calls: vec![] };
  let txs = vec![tx];

  let first_block_hash = latest_block_hash(&client).await;
  let nonce = contract.nonce(first_block_hash).await.unwrap();
  assert_eq!(nonce, U256::try_from(1u64).unwrap());

  let message = Router::execute_message(U256::try_from(chain_id).unwrap(), nonce, txs.clone());
  let sig = hash_and_sign(&keys, &public_key, &message);

  let receipt =
    send(&client, &anvil.keys()[0].clone().into(), contract.execute(&txs, &sig)).await.unwrap();
  assert!(receipt.status());

  let second_block_hash = latest_block_hash(&client).await;
  assert_eq!(contract.nonce(second_block_hash).await.unwrap(), U256::try_from(2u64).unwrap());
  // Check this does still offer the historical state
  assert_eq!(contract.nonce(first_block_hash).await.unwrap(), U256::try_from(1u64).unwrap());
  // TODO: Check logs

  println!("gas used: {:?}", receipt.gas_used);
  // println!("logs: {:?}", receipt.logs);
}
