use crate::utils::{generate_keys, hash_and_sign};

use ethereum_serai::{
  router_contract::{call_router_execute, deploy_router_contract, router_mod},
};
use frost::{curve::Secp256k1, FrostKeys};
use k256::ProjectivePoint;
use ethers::{
  prelude::*,
  utils::{Anvil},
  abi,
};
use std::{convert::TryFrom, collections::HashMap, sync::Arc, time::Duration};

#[tokio::test]
async fn test_deploy_router_contract() {
  let anvil = Anvil::new().spawn();
  let wallet: LocalWallet = anvil.keys()[0].clone().into();
  let provider =
    Provider::<Http>::try_from(anvil.endpoint()).unwrap().interval(Duration::from_millis(10u64));
  let client = Arc::new(SignerMiddleware::new(provider, wallet));

  let _contract = deploy_router_contract(client).await.unwrap();
}

#[tokio::test]
async fn test_call_router_execute() {
  let (keys, group_key): (HashMap<u16, FrostKeys<Secp256k1>>, ProjectivePoint) =
    generate_keys().await;

  let anvil = Anvil::new().spawn();
  let wallet: LocalWallet = anvil.keys()[0].clone().into();
  let provider =
    Provider::<Http>::try_from(anvil.endpoint()).unwrap().interval(Duration::from_millis(10u64));
  let chain_id = provider.get_chainid().await.unwrap();
  let client = Arc::new(SignerMiddleware::new(provider, wallet));

  let to = H160([0u8; 20]);
  let value = U256([0u64; 4]);
  let data = Bytes::from([0]);
  let tx = router_mod::Transaction { to: to.clone(), value: value.clone(), data: data.clone() };
  let txs = vec![tx];

  // try with wrong message
  const MESSAGE: &'static [u8] = b"Hello, World!";
  let processed_sig = hash_and_sign(MESSAGE, &keys, &group_key, chain_id).await;

  let contract = deploy_router_contract(client.clone()).await.unwrap();
  let res = call_router_execute(&contract, txs.clone(), &processed_sig).await;
  assert!(res.is_err()); // should revert as signature is for incorrect message

  // try w actual data
  let tokens = vec![abi::Token::Array(vec![abi::Token::Tuple(vec![
    abi::Token::Address(to),
    abi::Token::Uint(value),
    abi::Token::Bytes(data.to_vec()),
  ])])];
  let encoded_calldata = abi::encode(&tokens);
  let processed_sig = hash_and_sign(&encoded_calldata, &keys, &group_key, chain_id).await;
  let contract = deploy_router_contract(client).await.unwrap();
  let receipt = call_router_execute(&contract, txs.clone(), &processed_sig).await.unwrap().unwrap();
  println!("gas used: {:?}", receipt.cumulative_gas_used);
}
