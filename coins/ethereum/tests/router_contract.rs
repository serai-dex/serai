use ethereum_serai::{
  crypto::PublicKey,
  router::router::Transaction,
  router_contract::{router_execute, router_set_public_key, deploy_router_contract},
};
use frost::{curve::Secp256k1, ThresholdKeys};
use k256::ProjectivePoint;
use ethers::{
  prelude::*,
  utils::{Anvil},
  abi,
};
use std::{convert::TryFrom, collections::HashMap, sync::Arc, time::Duration};

mod utils;
use crate::utils::{generate_keys, hash_and_sign};

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
async fn test_router_execute() {
  let (keys, group_key): (HashMap<u16, ThresholdKeys<Secp256k1>>, ProjectivePoint) =
    generate_keys().await;

  let anvil = Anvil::new().spawn();
  let wallet: LocalWallet = anvil.keys()[0].clone().into();
  let provider =
    Provider::<Http>::try_from(anvil.endpoint()).unwrap().interval(Duration::from_millis(10u64));
  let chain_id = provider.get_chainid().await.unwrap();
  let client = Arc::new(SignerMiddleware::new(provider, wallet));

  // deploy and set public key
  let contract = deploy_router_contract(client.clone()).await.unwrap();
  let public_key = PublicKey::new(&group_key);
  router_set_public_key(&contract, &public_key).await.unwrap();

  let to = H160([0u8; 20]);
  let value = U256([0u64; 4]);
  let gas = U256::from(7000000); // arbitrary
  let data = Bytes::from([0]);
  let tx =
    Transaction { to: to.clone(), value: value.clone(), gas: gas.clone(), data: data.clone() };
  let txs = vec![tx];

  // try with wrong message
  const MESSAGE: &'static [u8] = b"Hello, World!";
  let processed_sig = hash_and_sign(MESSAGE, keys.clone(), &group_key, chain_id).await;
  let res = router_execute(&contract, txs.clone(), &processed_sig).await;
  // assert!(res.is_err()); // should revert as signature is for incorrect message

  // try w actual data
  let nonce_call = contract.get_nonce();
  let nonce = nonce_call.call().await.unwrap();
  let tokens = vec![
    abi::Token::Uint(nonce),
    abi::Token::Array(vec![abi::Token::Tuple(vec![
      abi::Token::Address(to),
      abi::Token::Uint(value),
      abi::Token::Uint(gas),
      abi::Token::Bytes(data.to_vec()),
    ])]),
  ];
  let encoded_calldata = abi::encode(&tokens);
  let processed_sig = hash_and_sign(&encoded_calldata, keys, &group_key, chain_id).await;
  let receipt = router_execute(&contract, txs.clone(), &processed_sig).await.unwrap().unwrap();
  //assert_eq!(receipt.status.unwrap(), U64::from(1));
  println!("gas used: {:?}", receipt.cumulative_gas_used);
  println!("logs: {:?}", receipt.logs);
}
