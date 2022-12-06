use std::sync::Mutex;

use lazy_static::lazy_static;
use rand_core::OsRng;

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};

use serde_json::json;

use monero_serai::{
  Protocol, random_scalar,
  wallet::{
    ViewPair,
    address::{Network, AddressType, AddressMeta, MoneroAddress},
  },
  rpc::{EmptyResponse, Rpc},
};

pub fn random_address() -> (Scalar, ViewPair, MoneroAddress) {
  let spend = random_scalar(&mut OsRng);
  let spend_pub = &spend * &ED25519_BASEPOINT_TABLE;
  let view = random_scalar(&mut OsRng);
  (
    spend,
    ViewPair::new(spend_pub, view),
    MoneroAddress {
      meta: AddressMeta::new(Network::Mainnet, AddressType::Standard),
      spend: spend_pub,
      view: &view * &ED25519_BASEPOINT_TABLE,
    },
  )
}

pub async fn mine_blocks(rpc: &Rpc, address: &str) {
  rpc
    .rpc_call::<_, EmptyResponse>(
      "json_rpc",
      Some(json!({
        "method": "generateblocks",
        "params": {
          "wallet_address": address,
          "amount_of_blocks": 10
        },
      })),
    )
    .await
    .unwrap();
}

pub async fn rpc() -> Rpc {
  let rpc = Rpc::new("http://127.0.0.1:18081".to_string()).unwrap();

  // Only run once
  if rpc.get_height().await.unwrap() != 1 {
    return rpc;
  }

  let addr = MoneroAddress {
    meta: AddressMeta::new(Network::Mainnet, AddressType::Standard),
    spend: &random_scalar(&mut OsRng) * &ED25519_BASEPOINT_TABLE,
    view: &random_scalar(&mut OsRng) * &ED25519_BASEPOINT_TABLE,
  }
  .to_string();

  // Mine 40 blocks to ensure decoy availability
  for _ in 0 .. 4 {
    mine_blocks(&rpc, &addr).await;
  }
  assert!(!matches!(rpc.get_protocol().await.unwrap(), Protocol::Unsupported(_)));

  rpc
}

lazy_static! {
  pub static ref SEQUENTIAL: Mutex<()> = Mutex::new(());
}

#[macro_export]
macro_rules! async_sequential {
  ($(async fn $name: ident() $body: block)*) => {
    $(
      #[tokio::test]
      async fn $name() {
        let guard = runner::SEQUENTIAL.lock().unwrap();
        let local = tokio::task::LocalSet::new();
        local.run_until(async move {
          if let Err(err) = tokio::task::spawn_local(async move { $body }).await {
            drop(guard);
            Err(err).unwrap()
          }
        }).await;
      }
    )*
  }
}

#[macro_export]
macro_rules! test {
  (
    $name: ident,
    (
      $first_tx: expr,
      $first_checks: expr,
    ),
    $((
      $tx: expr,
      $checks: expr,
    )$(,)?),*
  ) => {
    async_sequential! {
      async fn $name() {
        use core::{ops::Deref, any::Any};
        use std::collections::HashSet;
        #[cfg(feature = "multisig")]
        use std::collections::HashMap;

        use zeroize::Zeroizing;
        use rand_core::OsRng;

        use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;

        #[cfg(feature = "multisig")]
        use transcript::{Transcript, RecommendedTranscript};
        #[cfg(feature = "multisig")]
        use frost::{
          curve::Ed25519,
          tests::{THRESHOLD, key_gen},
        };

        use monero_serai::{
          random_scalar,
          wallet::{
            address::Network, ViewPair, Scanner, SignableTransaction,
            SignableTransactionBuilder,
          },
        };

        use runner::{random_address, rpc, mine_blocks};

        type Builder = SignableTransactionBuilder;

        // Run each function as both a single signer and as a multisig
        for multisig in [false, true] {
          // Only run the multisig variant if multisig is enabled
          if multisig {
            #[cfg(not(feature = "multisig"))]
            continue;
          }

          let spend = Zeroizing::new(random_scalar(&mut OsRng));
          #[cfg(feature = "multisig")]
          let keys = key_gen::<_, Ed25519>(&mut OsRng);

          let spend_pub = if !multisig {
            spend.deref() * &ED25519_BASEPOINT_TABLE
          } else {
            #[cfg(not(feature = "multisig"))]
            panic!("Multisig branch called without the multisig feature");
            #[cfg(feature = "multisig")]
            keys[&1].group_key().0
          };

          let view = ViewPair::new(spend_pub, random_scalar(&mut OsRng));

          let rpc = rpc().await;

          let (addr, miner_tx) = {
            let mut scanner =
              Scanner::from_view(view.clone(), Network::Mainnet, Some(HashSet::new()));
            let addr = scanner.address();

            let start = rpc.get_height().await.unwrap();
            for _ in 0 .. 7 {
              mine_blocks(&rpc, &addr.to_string()).await;
            }

            let block = rpc.get_block(start).await.unwrap();
            (
              addr,
              scanner.scan(
                &rpc,
                &block
              ).await.unwrap().swap_remove(0).ignore_timelock().swap_remove(0)
            )
          };

          let builder = SignableTransactionBuilder::new(
            rpc.get_protocol().await.unwrap(),
            rpc.get_fee().await.unwrap(),
            Some(random_address().2),
          );

          let sign = |tx: SignableTransaction| {
            let rpc = rpc.clone();
            let spend = spend.clone();
            #[cfg(feature = "multisig")]
            let keys = keys.clone();
            async move {
              if !multisig {
                tx.sign(&mut OsRng, &rpc, &spend).await.unwrap()
              } else {
                #[cfg(not(feature = "multisig"))]
                panic!("Multisig branch called without the multisig feature");
                #[cfg(feature = "multisig")]
                {
                  let mut machines = HashMap::new();
                  for i in 1 ..= THRESHOLD {
                    machines.insert(
                      i,
                      tx
                        .clone()
                        .multisig(
                          &rpc,
                          keys[&i].clone(),
                          RecommendedTranscript::new(b"Monero Serai Test Transaction"),
                          rpc.get_height().await.unwrap() - 10,
                          (1 ..= THRESHOLD).collect::<Vec<_>>(),
                        )
                        .await
                        .unwrap(),
                    );
                  }

                  frost::tests::sign(&mut OsRng, machines, &vec![])
                }
              }
            }
          };

          // TODO: Generate a distinct wallet for each transaction to prevent overlap
          let next_addr = addr;

          let temp = Box::new({
            let mut builder = builder.clone();
            builder.add_input(miner_tx);
            let (tx, state) = ($first_tx)(rpc.clone(), builder, next_addr).await;

            let signed = sign(tx).await;
            rpc.publish_transaction(&signed).await.unwrap();
            mine_blocks(&rpc, &random_address().2.to_string()).await;
            ($first_checks)(rpc.clone(), signed.hash(), view.clone(), state).await
          });
          #[allow(unused_variables, unused_mut, unused_assignments)]
          let mut carried_state: Box<dyn Any> = temp;

          $(
            let (tx, state) = ($tx)(
              rpc.clone(),
              builder.clone(),
              next_addr,
              *carried_state.downcast().unwrap()
            ).await;

            let signed = sign(tx).await;
            rpc.publish_transaction(&signed).await.unwrap();
            mine_blocks(&rpc, &random_address().2.to_string()).await;
            #[allow(unused_assignments)]
            {
              carried_state =
                Box::new(($checks)(rpc.clone(), signed.hash(), view.clone(), state).await);
            }
          )*
        }
      }
    }
  }
}
