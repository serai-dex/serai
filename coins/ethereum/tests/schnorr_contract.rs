use ethereum_serai::schnorr_contract::{call_verify, deploy_schnorr_verifier_contract};
use frost::{curve::Secp256k1, FrostKeys};
use k256::ProjectivePoint;
use ethers::{prelude::*, utils::Anvil};
use std::{convert::TryFrom, collections::HashMap, sync::Arc, time::Duration};

mod utils;
use crate::utils::{generate_keys, hash_and_sign};

#[tokio::test]
async fn test_deploy_schnorr_contract() {
  let anvil = Anvil::new().spawn();
  let wallet: LocalWallet = anvil.keys()[0].clone().into();
  let provider =
    Provider::<Http>::try_from(anvil.endpoint()).unwrap().interval(Duration::from_millis(10u64));
  let client = Arc::new(SignerMiddleware::new(provider, wallet));

  let _contract = deploy_schnorr_verifier_contract(client).await.unwrap();
}

#[tokio::test]
async fn test_ecrecover_hack() {
  let (keys, group_key): (HashMap<u16, FrostKeys<Secp256k1>>, ProjectivePoint) =
    generate_keys().await;

  let anvil = Anvil::new().spawn();
  let wallet: LocalWallet = anvil.keys()[0].clone().into();
  let provider =
    Provider::<Http>::try_from(anvil.endpoint()).unwrap().interval(Duration::from_millis(10u64));
  let chain_id = provider.get_chainid().await.unwrap();
  let client = Arc::new(SignerMiddleware::new(provider, wallet));

  const MESSAGE: &'static [u8] = b"Hello, World!";
  let mut processed_sig = hash_and_sign(MESSAGE, &keys, &group_key, chain_id).await;

  let contract = deploy_schnorr_verifier_contract(client).await.unwrap();
  call_verify(&contract, &processed_sig).await.unwrap();

  // test invalid signature fails
  processed_sig.message[0] = 0;
  let res = call_verify(&contract, &processed_sig).await;
  assert!(res.is_err());
}
