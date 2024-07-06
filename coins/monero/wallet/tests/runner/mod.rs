use core::ops::Deref;
use std_shims::sync::OnceLock;

use zeroize::Zeroizing;
use rand_core::OsRng;

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};

use tokio::sync::Mutex;

use monero_simple_request_rpc::SimpleRequestRpc;
use monero_wallet::{
  ringct::RctType,
  transaction::Transaction,
  block::Block,
  rpc::{Rpc, FeeRate},
  address::{Network, AddressType, MoneroAddress},
  DEFAULT_LOCK_WINDOW, ViewPair, GuaranteedViewPair, WalletOutput, Scanner,
};

mod builder;
pub use builder::SignableTransactionBuilder;

pub fn ring_len(rct_type: RctType) -> usize {
  match rct_type {
    RctType::ClsagBulletproof => 11,
    RctType::ClsagBulletproofPlus => 16,
    _ => panic!("ring size unknown for RctType"),
  }
}

pub fn random_address() -> (Scalar, ViewPair, MoneroAddress) {
  let spend = Scalar::random(&mut OsRng);
  let spend_pub = &spend * ED25519_BASEPOINT_TABLE;
  let view = Zeroizing::new(Scalar::random(&mut OsRng));
  (
    spend,
    ViewPair::new(spend_pub, view.clone()),
    MoneroAddress::new(
      Network::Mainnet,
      AddressType::Legacy,
      spend_pub,
      view.deref() * ED25519_BASEPOINT_TABLE,
    ),
  )
}

#[allow(unused)]
pub fn random_guaranteed_address() -> (Scalar, GuaranteedViewPair, MoneroAddress) {
  let spend = Scalar::random(&mut OsRng);
  let spend_pub = &spend * ED25519_BASEPOINT_TABLE;
  let view = Zeroizing::new(Scalar::random(&mut OsRng));
  (
    spend,
    GuaranteedViewPair::new(spend_pub, view.clone()),
    MoneroAddress::new(
      Network::Mainnet,
      AddressType::Legacy,
      spend_pub,
      view.deref() * ED25519_BASEPOINT_TABLE,
    ),
  )
}

// TODO: Support transactions already on-chain
// TODO: Don't have a side effect of mining blocks more blocks than needed under race conditions
pub async fn mine_until_unlocked(
  rpc: &SimpleRequestRpc,
  addr: &MoneroAddress,
  tx_hash: [u8; 32],
) -> Block {
  // mine until tx is in a block
  let mut height = rpc.get_height().await.unwrap();
  let mut found = false;
  let mut block = None;
  while !found {
    let inner_block = rpc.get_block_by_number(height - 1).await.unwrap();
    found = match inner_block.transactions.iter().find(|&&x| x == tx_hash) {
      Some(_) => {
        block = Some(inner_block);
        true
      }
      None => {
        height = rpc.generate_blocks(addr, 1).await.unwrap().1 + 1;
        false
      }
    }
  }

  // Mine until tx's outputs are unlocked
  for _ in 0 .. (DEFAULT_LOCK_WINDOW - 1) {
    rpc.generate_blocks(addr, 1).await.unwrap();
  }

  block.unwrap()
}

// Mines 60 blocks and returns an unlocked miner TX output.
#[allow(dead_code)]
pub async fn get_miner_tx_output(rpc: &SimpleRequestRpc, view: &ViewPair) -> WalletOutput {
  let mut scanner = Scanner::new(view.clone());

  // Mine 60 blocks to unlock a miner TX
  let start = rpc.get_height().await.unwrap();
  rpc.generate_blocks(&view.legacy_address(Network::Mainnet), 60).await.unwrap();

  let block = rpc.get_block_by_number(start).await.unwrap();
  scanner.scan(rpc, &block).await.unwrap().ignore_additional_timelock().swap_remove(0)
}

/// Make sure the weight and fee match the expected calculation.
pub fn check_weight_and_fee(tx: &Transaction, fee_rate: FeeRate) {
  let Transaction::V2 { proofs: Some(ref proofs), .. } = tx else { panic!("TX wasn't RingCT") };
  let fee = proofs.base.fee;

  let weight = tx.weight();
  let expected_weight = fee_rate.calculate_weight_from_fee(fee);
  assert_eq!(weight, expected_weight);

  let expected_fee = fee_rate.calculate_fee_from_weight(weight);
  assert_eq!(fee, expected_fee);
}

pub async fn rpc() -> SimpleRequestRpc {
  let rpc =
    SimpleRequestRpc::new("http://serai:seraidex@127.0.0.1:18081".to_string()).await.unwrap();

  // Only run once
  if rpc.get_height().await.unwrap() != 1 {
    return rpc;
  }

  let addr = MoneroAddress::new(
    Network::Mainnet,
    AddressType::Legacy,
    &Scalar::random(&mut OsRng) * ED25519_BASEPOINT_TABLE,
    &Scalar::random(&mut OsRng) * ED25519_BASEPOINT_TABLE,
  );

  // Mine 40 blocks to ensure decoy availability
  rpc.generate_blocks(&addr, 40).await.unwrap();

  rpc
}

pub static SEQUENTIAL: OnceLock<Mutex<()>> = OnceLock::new();

#[macro_export]
macro_rules! async_sequential {
  ($(async fn $name: ident() $body: block)*) => {
    $(
      #[tokio::test]
      async fn $name() {
        let guard = runner::SEQUENTIAL.get_or_init(|| tokio::sync::Mutex::new(())).lock().await;
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
        #[cfg(feature = "multisig")]
        use std::collections::HashMap;

        use zeroize::Zeroizing;
        use rand_core::{RngCore, OsRng};

        use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, scalar::Scalar};

        #[cfg(feature = "multisig")]
        use frost::{
          curve::Ed25519,
          Participant,
          tests::{THRESHOLD, key_gen},
        };

        use monero_wallet::{
          primitives::Decoys,
          ringct::RctType,
          rpc::FeePriority,
          address::Network,
          ViewPair,
          DecoySelection,
          Scanner,
          send::{Change, SignableTransaction, Eventuality},
        };

        use runner::{
          SignableTransactionBuilder, ring_len, random_address, rpc, mine_until_unlocked,
          get_miner_tx_output, check_weight_and_fee,
        };

        type Builder = SignableTransactionBuilder;

        // Run each function as both a single signer and as a multisig
        #[allow(clippy::redundant_closure_call)]
        for multisig in [false, true] {
          // Only run the multisig variant if multisig is enabled
          if multisig {
            #[cfg(not(feature = "multisig"))]
            continue;
          }

          let spend = Zeroizing::new(Scalar::random(&mut OsRng));
          #[cfg(feature = "multisig")]
          let keys = key_gen::<_, Ed25519>(&mut OsRng);

          let spend_pub = if !multisig {
            spend.deref() * ED25519_BASEPOINT_TABLE
          } else {
            #[cfg(not(feature = "multisig"))]
            panic!("Multisig branch called without the multisig feature");
            #[cfg(feature = "multisig")]
            keys[&Participant::new(1).unwrap()].group_key().0
          };

          let rpc = rpc().await;

          let view_priv = Zeroizing::new(Scalar::random(&mut OsRng));
          let mut outgoing_view = Zeroizing::new([0; 32]);
          OsRng.fill_bytes(outgoing_view.as_mut());
          let view = ViewPair::new(spend_pub, view_priv.clone());
          let addr = view.legacy_address(Network::Mainnet);

          let miner_tx = get_miner_tx_output(&rpc, &view).await;

          let rct_type = match rpc.get_hardfork_version().await.unwrap() {
            14 => RctType::ClsagBulletproof,
            15 | 16 => RctType::ClsagBulletproofPlus,
            _ => panic!("unrecognized hardfork version"),
          };

          let builder = SignableTransactionBuilder::new(
            rct_type,
            outgoing_view,
            Change::new(
              &ViewPair::new(
                &Scalar::random(&mut OsRng) * ED25519_BASEPOINT_TABLE,
                Zeroizing::new(Scalar::random(&mut OsRng))
              ),
            ),
            rpc.get_fee_rate(FeePriority::Unimportant).await.unwrap(),
          );

          let sign = |tx: SignableTransaction| {
            let spend = spend.clone();
            #[cfg(feature = "multisig")]
            let keys = keys.clone();

            let eventuality = Eventuality::from(tx.clone());

            let tx = if !multisig {
              tx.sign(&mut OsRng, &spend).unwrap()
            } else {
              #[cfg(not(feature = "multisig"))]
              panic!("multisig branch called without the multisig feature");
              #[cfg(feature = "multisig")]
              {
                let mut machines = HashMap::new();
                for i in (1 ..= THRESHOLD).map(|i| Participant::new(i).unwrap()) {
                  machines.insert(i, tx.clone().multisig(&keys[&i]).unwrap());
                }

                frost::tests::sign_without_caching(&mut OsRng, machines, &[])
              }
            };

            assert_eq!(&eventuality.extra(), &tx.prefix().extra);
            assert!(eventuality.matches(&tx));

            tx
          };

          // TODO: Generate a distinct wallet for each transaction to prevent overlap
          let next_addr = addr;

          let temp = Box::new({
            let mut builder = builder.clone();

            let decoys = Decoys::fingerprintable_canonical_select(
              &mut OsRng,
              &rpc,
              ring_len(rct_type),
              rpc.get_height().await.unwrap(),
              &[miner_tx.clone()],
            )
            .await
            .unwrap();
            builder.add_input((miner_tx, decoys.first().unwrap().clone()));

            let (tx, state) = ($first_tx)(rpc.clone(), builder, next_addr).await;
            let fee_rate = tx.fee_rate().clone();
            let signed = sign(tx);
            rpc.publish_transaction(&signed).await.unwrap();
            let block =
              mine_until_unlocked(&rpc, &random_address().2, signed.hash()).await;
            let tx = rpc.get_transaction(signed.hash()).await.unwrap();
            check_weight_and_fee(&tx, fee_rate);
            let scanner = Scanner::new(view.clone());
            ($first_checks)(rpc.clone(), block, tx, scanner, state).await
          });
          #[allow(unused_variables, unused_mut, unused_assignments)]
          let mut carried_state: Box<dyn Any> = temp;

          $(
            let (tx, state) = ($tx)(
              rct_type,
              rpc.clone(),
              builder.clone(),
              next_addr,
              *carried_state.downcast().unwrap()
            ).await;
            let fee_rate = tx.fee_rate().clone();
            let signed = sign(tx);
            rpc.publish_transaction(&signed).await.unwrap();
            let block =
              mine_until_unlocked(&rpc, &random_address().2, signed.hash()).await;
            let tx = rpc.get_transaction(signed.hash()).await.unwrap();
            if stringify!($name) != "spend_one_input_to_two_outputs_no_change" {
              // Skip weight and fee check for the above test because when there is no change,
              // the change is added to the fee
              check_weight_and_fee(&tx, fee_rate);
            }
            #[allow(unused_assignments)]
            {
              let scanner = Scanner::new(view.clone());
              carried_state = Box::new(($checks)(rpc.clone(), block, tx, scanner, state).await);
            }
          )*
        }
      }
    }
  }
}
