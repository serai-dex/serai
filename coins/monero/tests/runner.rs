use core::ops::Deref;
use std::collections::HashSet;

use lazy_static::lazy_static;

use zeroize::Zeroizing;
use rand_core::OsRng;

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};

use tokio::sync::Mutex;

use monero_serai::{
  random_scalar,
  rpc::{HttpRpc, Rpc},
  wallet::{
    ViewPair, Scanner,
    address::{Network, AddressType, AddressSpec, AddressMeta, MoneroAddress},
    SpendableOutput,
  },
};

pub fn random_address() -> (Scalar, ViewPair, MoneroAddress) {
  let spend = random_scalar(&mut OsRng);
  let spend_pub = &spend * &ED25519_BASEPOINT_TABLE;
  let view = Zeroizing::new(random_scalar(&mut OsRng));
  (
    spend,
    ViewPair::new(spend_pub, view.clone()),
    MoneroAddress {
      meta: AddressMeta::new(Network::Mainnet, AddressType::Standard),
      spend: spend_pub,
      view: view.deref() * &ED25519_BASEPOINT_TABLE,
    },
  )
}

// TODO: Support transactions already on-chain
// TODO: Don't have a side effect of mining blocks more blocks than needed under race conditions
// TODO: mine as much as needed instead of default 10 blocks
pub async fn mine_until_unlocked(rpc: &Rpc<HttpRpc>, addr: &str, tx_hash: [u8; 32]) {
  // mine until tx is in a block
  let mut height = rpc.get_height().await.unwrap();
  let mut found = false;
  while !found {
    let block = rpc.get_block_by_number(height - 1).await.unwrap();
    found = match block.txs.iter().find(|&&x| x == tx_hash) {
      Some(_) => true,
      None => {
        rpc.generate_blocks(addr, 1).await.unwrap();
        height += 1;
        false
      }
    }
  }

  // mine 9 more blocks to unlock the tx
  rpc.generate_blocks(addr, 9).await.unwrap();
}

// Mines 60 blocks and returns an unlocked miner TX output.
#[allow(dead_code)]
pub async fn get_miner_tx_output(rpc: &Rpc<HttpRpc>, view: &ViewPair) -> SpendableOutput {
  let mut scanner = Scanner::from_view(view.clone(), Some(HashSet::new()));

  // Mine 60 blocks to unlock a miner TX
  let start = rpc.get_height().await.unwrap();
  rpc
    .generate_blocks(&view.address(Network::Mainnet, AddressSpec::Standard).to_string(), 60)
    .await
    .unwrap();

  let block = rpc.get_block_by_number(start).await.unwrap();
  scanner.scan(rpc, &block).await.unwrap().swap_remove(0).ignore_timelock().swap_remove(0)
}

pub async fn rpc() -> Rpc<HttpRpc> {
  let rpc = HttpRpc::new("http://127.0.0.1:18081".to_string()).unwrap();

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
  rpc.generate_blocks(&addr, 40).await.unwrap();

  // Make sure we recognize the protocol
  rpc.get_protocol().await.unwrap();

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
        let guard = runner::SEQUENTIAL.lock().await;
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
          Participant,
          tests::{THRESHOLD, key_gen},
        };

        use monero_serai::{
          random_scalar,
          wallet::{
            address::{Network, AddressSpec}, ViewPair, Scanner, Change, SignableTransaction,
            SignableTransactionBuilder,
          },
        };

        use runner::{random_address, rpc, mine_until_unlocked, get_miner_tx_output};

        type Builder = SignableTransactionBuilder;

        // Run each function as both a single signer and as a multisig
        #[allow(clippy::redundant_closure_call)]
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
            keys[&Participant::new(1).unwrap()].group_key().0
          };

          let rpc = rpc().await;

          let view = ViewPair::new(spend_pub, Zeroizing::new(random_scalar(&mut OsRng)));
          let addr = view.address(Network::Mainnet, AddressSpec::Standard);

          let miner_tx = get_miner_tx_output(&rpc, &view).await;

          let builder = SignableTransactionBuilder::new(
            rpc.get_protocol().await.unwrap(),
            rpc.get_fee().await.unwrap(),
            Some(Change::new(
              &ViewPair::new(
                &random_scalar(&mut OsRng) * &ED25519_BASEPOINT_TABLE,
                Zeroizing::new(random_scalar(&mut OsRng))
              ),
              false
            )),
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
                  for i in (1 ..= THRESHOLD).map(|i| Participant::new(i).unwrap()) {
                    machines.insert(
                      i,
                      tx
                        .clone()
                        .multisig(
                          &rpc,
                          keys[&i].clone(),
                          RecommendedTranscript::new(b"Monero Serai Test Transaction"),
                          rpc.get_height().await.unwrap() - 10,
                        )
                        .await
                        .unwrap(),
                    );
                  }

                  frost::tests::sign_without_caching(&mut OsRng, machines, &[])
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
            mine_until_unlocked(&rpc, &random_address().2.to_string(), signed.hash()).await;
            let tx = rpc.get_transaction(signed.hash()).await.unwrap();
            let scanner =
              Scanner::from_view(view.clone(), Some(HashSet::new()));
            ($first_checks)(rpc.clone(), tx, scanner, state).await
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
            mine_until_unlocked(&rpc, &random_address().2.to_string(), signed.hash()).await;
            let tx = rpc.get_transaction(signed.hash()).await.unwrap();
            #[allow(unused_assignments)]
            {
              let scanner =
                Scanner::from_view(view.clone(), Some(HashSet::new()));
              carried_state =
                Box::new(($checks)(rpc.clone(), tx, scanner, state).await);
            }
          )*
        }
      }
    }
  }
}
