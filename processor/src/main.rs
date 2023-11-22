use std::{time::Duration, collections::HashMap};

use zeroize::{Zeroize, Zeroizing};

use transcript::{Transcript, RecommendedTranscript};
use ciphersuite::{group::GroupEncoding, Ciphersuite};

use log::{info, warn};
use tokio::time::sleep;

use serai_client::{
  primitives::{BlockHash, NetworkId},
  validator_sets::primitives::{ValidatorSet, KeyPair},
};

use messages::{
  coordinator::{
    SubstrateSignableId, PlanMeta, CoordinatorMessage as CoordinatorCoordinatorMessage,
  },
  CoordinatorMessage,
};

use serai_env as env;

use message_queue::{Service, client::MessageQueue};

mod plan;
pub use plan::*;

mod networks;
use networks::{Block, Network};
#[cfg(feature = "bitcoin")]
use networks::Bitcoin;
#[cfg(feature = "monero")]
use networks::Monero;

mod additional_key;
pub use additional_key::additional_key;

mod db;
pub use db::*;

mod coordinator;
pub use coordinator::*;

mod key_gen;
use key_gen::{KeyConfirmed, KeyGen};

mod signer;
use signer::Signer;

mod cosigner;
use cosigner::Cosigner;

mod batch_signer;
use batch_signer::BatchSigner;

mod multisigs;
use multisigs::{MultisigEvent, MultisigManager};

#[cfg(test)]
mod tests;

// Items which are mutably borrowed by Tributary.
// Any exceptions to this have to be carefully monitored in order to ensure consistency isn't
// violated.
struct TributaryMutable<N: Network, D: Db> {
  // The following are actually mutably borrowed by Substrate as well.
  // - Substrate triggers key gens, and determines which to use.
  // - SubstrateBlock events cause scheduling which causes signing.
  //
  // This is still considered Tributary-mutable as most mutation (preprocesses/shares) happens by
  // the Tributary.
  //
  // Creation of tasks is by Substrate, yet this is safe since the mutable borrow is transferred to
  // Tributary.
  //
  // Tributary stops mutating a key gen attempt before Substrate is made aware of it, ensuring
  // Tributary drops its mutable borrow before Substrate acquires it. Tributary will maintain a
  // mutable borrow on the *key gen task*, yet the finalization code can successfully run for any
  // attempt.
  //
  // The only other note is how the scanner may cause a signer task to be dropped, effectively
  // invalidating the Tributary's mutable borrow. The signer is coded to allow for attempted usage
  // of a dropped task.
  key_gen: KeyGen<N, D>,
  signers: HashMap<Vec<u8>, Signer<N, D>>,

  // This is also mutably borrowed by the Scanner.
  // The Scanner starts new sign tasks.
  // The Tributary mutates already-created signed tasks, potentially completing them.
  // Substrate may mark tasks as completed, invalidating any existing mutable borrows.
  // The safety of this follows as written above.

  // There should only be one BatchSigner at a time (see #277)
  batch_signer: Option<BatchSigner<D>>,

  // Solely mutated by the tributary.
  cosigner: Option<Cosigner>,
}

// Items which are mutably borrowed by Substrate.
// Any exceptions to this have to be carefully monitored in order to ensure consistency isn't
// violated.

/*
  The MultisigManager contains the Scanner and Schedulers.

  The scanner is expected to autonomously operate, scanning blocks as they appear. When a block is
  sufficiently confirmed, the scanner causes the Substrate signer to sign a batch. It itself only
  mutates its list of finalized blocks, to protect against re-orgs, and its in-memory state though.

  Disk mutations to the scan-state only happens once the relevant `Batch` is included on Substrate.
  It can't be mutated as soon as the `Batch` is signed as we need to know the order of `Batch`s
  relevant to `Burn`s.

  Schedulers take in new outputs, confirmed in `Batch`s, and outbound payments, triggered by
  `Burn`s.

  Substrate also decides when to move to a new multisig, hence why this entire object is
  Substate-mutable.

  Since MultisigManager should always be verifiable, and the Tributary is temporal, MultisigManager
  being entirely SubstrateMutable shows proper data pipe-lining.
*/

type SubstrateMutable<N, D> = MultisigManager<D, N>;

async fn handle_coordinator_msg<D: Db, N: Network, Co: Coordinator>(
  txn: &mut D::Transaction<'_>,
  network: &N,
  coordinator: &mut Co,
  tributary_mutable: &mut TributaryMutable<N, D>,
  substrate_mutable: &mut SubstrateMutable<N, D>,
  msg: &Message,
) {
  // If this message expects a higher block number than we have, halt until synced
  async fn wait<N: Network, D: Db>(
    txn: &D::Transaction<'_>,
    substrate_mutable: &SubstrateMutable<N, D>,
    block_hash: &BlockHash,
  ) {
    let mut needed_hash = <N::Block as Block<N>>::Id::default();
    needed_hash.as_mut().copy_from_slice(&block_hash.0);

    loop {
      // Ensure our scanner has scanned this block, which means our daemon has this block at
      // a sufficient depth
      if substrate_mutable.block_number(txn, &needed_hash).await.is_none() {
        warn!(
          "node is desynced. we haven't scanned {} which should happen after {} confirms",
          hex::encode(&needed_hash),
          N::CONFIRMATIONS,
        );
        sleep(Duration::from_secs(10)).await;
        continue;
      };
      break;
    }

    // TODO2: Sanity check we got an AckBlock (or this is the AckBlock) for the block in question

    /*
    let synced = |context: &SubstrateContext, key| -> Result<(), ()> {
      // Check that we've synced this block and can actually operate on it ourselves
      let latest = scanner.latest_scanned(key);
      if usize::try_from(context.network_latest_finalized_block).unwrap() < latest {
        log::warn!(
          "external network node disconnected/desynced from rest of the network. \
          our block: {latest:?}, network's acknowledged: {}",
          context.network_latest_finalized_block,
        );
        Err(())?;
      }
      Ok(())
    };
    */
  }

  if let Some(required) = msg.msg.required_block() {
    // wait only reads from, it doesn't mutate, substrate_mutable
    wait(txn, substrate_mutable, &required).await;
  }

  async fn activate_key<N: Network, D: Db>(
    network: &N,
    substrate_mutable: &mut SubstrateMutable<N, D>,
    tributary_mutable: &mut TributaryMutable<N, D>,
    txn: &mut D::Transaction<'_>,
    set: ValidatorSet,
    key_pair: KeyPair,
    activation_number: usize,
  ) {
    info!("activating {set:?}'s keys at {activation_number}");

    let network_key = <N as Network>::Curve::read_G::<&[u8]>(&mut key_pair.1.as_ref())
      .expect("Substrate finalized invalid point as a network's key");

    if tributary_mutable.key_gen.in_set(&set) {
      // See TributaryMutable's struct definition for why this block is safe
      let KeyConfirmed { substrate_keys, network_keys } =
        tributary_mutable.key_gen.confirm(txn, set, key_pair.clone()).await;
      if set.session.0 == 0 {
        tributary_mutable.batch_signer = Some(BatchSigner::new(N::NETWORK, substrate_keys));
      }
      tributary_mutable
        .signers
        .insert(key_pair.1.into(), Signer::new(network.clone(), network_keys));
    }

    substrate_mutable.add_key(txn, activation_number, network_key).await;
  }

  match msg.msg.clone() {
    CoordinatorMessage::KeyGen(msg) => {
      coordinator.send(tributary_mutable.key_gen.handle(txn, msg).await).await;
    }

    CoordinatorMessage::Sign(msg) => {
      if let Some(msg) = tributary_mutable
        .signers
        .get_mut(msg.key())
        .expect("coordinator told us to sign with a signer we don't have")
        .handle(txn, msg)
        .await
      {
        coordinator.send(msg).await;
      }
    }

    CoordinatorMessage::Coordinator(msg) => {
      let is_batch = match msg {
        CoordinatorCoordinatorMessage::CosignSubstrateBlock { .. } => false,
        CoordinatorCoordinatorMessage::SubstratePreprocesses { ref id, .. } => {
          matches!(&id.id, SubstrateSignableId::Batch(_))
        }
        CoordinatorCoordinatorMessage::SubstrateShares { ref id, .. } => {
          matches!(&id.id, SubstrateSignableId::Batch(_))
        }
        CoordinatorCoordinatorMessage::BatchReattempt { .. } => true,
      };
      if is_batch {
        if let Some(msg) = tributary_mutable
          .batch_signer
          .as_mut()
          .expect(
            "coordinator told us to sign a batch when we don't currently have a Substrate signer",
          )
          .handle(txn, msg)
          .await
        {
          coordinator.send(msg).await;
        }
      } else {
        match msg {
          CoordinatorCoordinatorMessage::CosignSubstrateBlock { id, block_number } => {
            let SubstrateSignableId::CosigningSubstrateBlock(block) = id.id else {
              panic!("CosignSubstrateBlock id didn't have a CosigningSubstrateBlock")
            };
            let Some(keys) = tributary_mutable.key_gen.substrate_keys_by_substrate_key(&id.key)
            else {
              panic!("didn't have key shares for the key we were told to cosign with");
            };
            if let Some((cosigner, msg)) = Cosigner::new(txn, keys, block_number, block, id.attempt)
            {
              tributary_mutable.cosigner = Some(cosigner);
              coordinator.send(msg).await;
            } else {
              log::warn!("Cosigner::new returned None");
            }
          }
          _ => {
            if let Some(cosigner) = tributary_mutable.cosigner.as_mut() {
              if let Some(msg) = cosigner.handle(txn, msg).await {
                coordinator.send(msg).await;
              }
            } else {
              log::warn!(
                "received message for cosigner yet didn't have a cosigner. {}",
                "this is an error if we didn't reboot",
              );
            }
          }
        }
      }
    }

    CoordinatorMessage::Substrate(msg) => {
      match msg {
        messages::substrate::CoordinatorMessage::ConfirmKeyPair { context, set, key_pair } => {
          // This is the first key pair for this network so no block has been finalized yet
          // TODO: Write documentation for this in docs/
          // TODO: Use an Option instead of a magic?
          if context.network_latest_finalized_block.0 == [0; 32] {
            assert!(tributary_mutable.signers.is_empty());
            assert!(tributary_mutable.batch_signer.is_none());
            assert!(tributary_mutable.cosigner.is_none());
            // We can't check this as existing is no longer pub
            // assert!(substrate_mutable.existing.as_ref().is_none());

            // Wait until a network's block's time exceeds Serai's time
            // These time calls are extremely expensive for what they do, yet they only run when
            // confirming the first key pair, before any network activity has occurred, so they
            // should be fine

            // If the latest block number is 10, then the block indexed by 1 has 10 confirms
            // 10 + 1 - 10 = 1
            let mut block_i;
            while {
              block_i = (network.get_latest_block_number_with_retries().await + 1)
                .saturating_sub(N::CONFIRMATIONS);
              network.get_block_with_retries(block_i).await.time(network).await < context.serai_time
            } {
              info!(
                "serai confirmed the first key pair for a set. {} {}",
                "we're waiting for a network's finalized block's time to exceed unix time ",
                context.serai_time,
              );
              sleep(Duration::from_secs(5)).await;
            }

            // Find the first block to do so
            let mut earliest = block_i;
            // earliest > 0 prevents a panic if Serai creates keys before the genesis block
            // which... should be impossible
            // Yet a prevented panic is a prevented panic
            while (earliest > 0) &&
              (network.get_block_with_retries(earliest - 1).await.time(network).await >=
                context.serai_time)
            {
              earliest -= 1;
            }

            // Use this as the activation block
            let activation_number = earliest;

            activate_key(
              network,
              substrate_mutable,
              tributary_mutable,
              txn,
              set,
              key_pair,
              activation_number,
            )
            .await;
          } else {
            let mut block_before_queue_block = <N::Block as Block<N>>::Id::default();
            block_before_queue_block
              .as_mut()
              .copy_from_slice(&context.network_latest_finalized_block.0);
            // We can't set these keys for activation until we know their queue block, which we
            // won't until the next Batch is confirmed
            // Set this variable so when we get the next Batch event, we can handle it
            PendingActivationsDb::set_pending_activation::<N>(
              txn,
              block_before_queue_block,
              set,
              key_pair,
            );
          }
        }

        messages::substrate::CoordinatorMessage::SubstrateBlock {
          context,
          network: network_id,
          block: substrate_block,
          burns,
          batches,
        } => {
          assert_eq!(network_id, N::NETWORK, "coordinator sent us data for another network");

          if let Some((block, set, key_pair)) = PendingActivationsDb::pending_activation::<N>(txn) {
            // Only run if this is a Batch belonging to a distinct block
            if context.network_latest_finalized_block.as_ref() != block.as_ref() {
              let mut queue_block = <N::Block as Block<N>>::Id::default();
              queue_block.as_mut().copy_from_slice(context.network_latest_finalized_block.as_ref());

              let activation_number = substrate_mutable
                .block_number(txn, &queue_block)
                .await
                .expect("KeyConfirmed from context we haven't synced") +
                N::CONFIRMATIONS;

              activate_key(
                network,
                substrate_mutable,
                tributary_mutable,
                txn,
                set,
                key_pair,
                activation_number,
              )
              .await;
              //clear pending activation
              txn.del(PendingActivationsDb::key());
            }
          }

          // Since this block was acknowledged, we no longer have to sign the batches within it
          if let Some(batch_signer) = tributary_mutable.batch_signer.as_mut() {
            for batch_id in batches {
              batch_signer.batch_signed(txn, batch_id);
            }
          }

          let (acquired_lock, to_sign) =
            substrate_mutable.substrate_block(txn, network, context, burns).await;

          // Send SubstrateBlockAck, with relevant plan IDs, before we trigger the signing of these
          // plans
          if !tributary_mutable.signers.is_empty() {
            coordinator
              .send(messages::coordinator::ProcessorMessage::SubstrateBlockAck {
                network: N::NETWORK,
                block: substrate_block,
                plans: to_sign
                  .iter()
                  .map(|signable| PlanMeta {
                    key: signable.0.to_bytes().as_ref().to_vec(),
                    id: signable.1,
                  })
                  .collect(),
              })
              .await;
          }

          // See commentary in TributaryMutable for why this is safe
          let signers = &mut tributary_mutable.signers;
          for (key, id, tx, eventuality) in to_sign {
            if let Some(signer) = signers.get_mut(key.to_bytes().as_ref()) {
              if let Some(msg) = signer.sign_transaction(txn, id, tx, eventuality).await {
                coordinator.send(msg).await;
              }
            }
          }

          // This is not premature, even if this block had multiple `Batch`s created, as the first
          // `Batch` alone will trigger all Plans/Eventualities/Signs
          if acquired_lock {
            substrate_mutable.release_scanner_lock().await;
          }
        }
      }
    }
  }
}

async fn boot<N: Network, D: Db, Co: Coordinator>(
  raw_db: &mut D,
  network: &N,
  coordinator: &mut Co,
) -> (D, TributaryMutable<N, D>, SubstrateMutable<N, D>) {
  let mut entropy_transcript = {
    let entropy = Zeroizing::new(env::var("ENTROPY").expect("entropy wasn't specified"));
    if entropy.len() != 64 {
      panic!("entropy isn't the right length");
    }
    let mut bytes =
      Zeroizing::new(hex::decode(entropy).map_err(|_| ()).expect("entropy wasn't hex-formatted"));
    if bytes.len() != 32 {
      bytes.zeroize();
      panic!("entropy wasn't 32 bytes");
    }
    let mut entropy = Zeroizing::new([0; 32]);
    let entropy_mut: &mut [u8] = entropy.as_mut();
    entropy_mut.copy_from_slice(bytes.as_ref());

    let mut transcript = RecommendedTranscript::new(b"Serai Processor Entropy");
    transcript.append_message(b"entropy", entropy);
    transcript
  };

  // TODO: Save a hash of the entropy to the DB and make sure the entropy didn't change

  let mut entropy = |label| {
    let mut challenge = entropy_transcript.challenge(label);
    let mut res = Zeroizing::new([0; 32]);
    let res_mut: &mut [u8] = res.as_mut();
    res_mut.copy_from_slice(&challenge[.. 32]);
    challenge.zeroize();
    res
  };

  // We don't need to re-issue GenerateKey orders because the coordinator is expected to
  // schedule/notify us of new attempts
  // TODO: Is this above comment still true? Not at all due to the planned lack of DKG timeouts?
  let key_gen = KeyGen::<N, _>::new(raw_db.clone(), entropy(b"key-gen_entropy"));

  let (multisig_manager, current_keys, actively_signing) =
    MultisigManager::new(raw_db, network).await;

  let mut batch_signer = None;
  let mut signers = HashMap::new();

  for (i, key) in current_keys.iter().enumerate() {
    let Some((substrate_keys, network_keys)) = key_gen.keys(key) else { continue };
    let network_key = network_keys[0].group_key();

    // If this is the oldest key, load the BatchSigner for it as the active BatchSigner
    // The new key only takes responsibility once the old key is fully deprecated
    //
    // We don't have to load any state for this since the Scanner will re-fire any events
    // necessary, only no longer scanning old blocks once Substrate acks them
    if i == 0 {
      batch_signer = Some(BatchSigner::new(N::NETWORK, substrate_keys));
    }

    // The Scanner re-fires events as needed for batch_signer yet not signer
    // This is due to the transactions which we start signing from due to a block not being
    // guaranteed to be signed before we stop scanning the block on reboot
    // We could simplify the Signer flow by delaying when it acks a block, yet that'd:
    // 1) Increase the startup time
    // 2) Cause re-emission of Batch events, which we'd need to check the safety of
    //    (TODO: Do anyways?)
    // 3) Violate the attempt counter (TODO: Is this already being violated?)
    let mut signer = Signer::new(network.clone(), network_keys);

    // Sign any TXs being actively signed
    let key = key.to_bytes();
    for (plan, tx, eventuality) in &actively_signing {
      if plan.key == network_key {
        let mut txn = raw_db.txn();
        if let Some(msg) =
          signer.sign_transaction(&mut txn, plan.id(), tx.clone(), eventuality.clone()).await
        {
          coordinator.send(msg).await;
        }
        // This should only have re-writes of existing data
        drop(txn);
      }
    }

    signers.insert(key.as_ref().to_vec(), signer);
  }

  // Spawn a task to rebroadcast signed TXs yet to be mined into a finalized block
  // This hedges against being dropped due to full mempools, temporarily too low of a fee...
  tokio::spawn(Signer::<N, D>::rebroadcast_task(raw_db.clone(), network.clone()));

  (
    raw_db.clone(),
    TributaryMutable { key_gen, batch_signer, cosigner: None, signers },
    multisig_manager,
  )
}

#[allow(clippy::await_holding_lock)] // Needed for txn, unfortunately can't be down-scoped
async fn run<N: Network, D: Db, Co: Coordinator>(mut raw_db: D, network: N, mut coordinator: Co) {
  // We currently expect a contextless bidirectional mapping between these two values
  // (which is that any value of A can be interpreted as B and vice versa)
  // While we can write a contextual mapping, we have yet to do so
  // This check ensures no network which doesn't have a bidirectional mapping is defined
  assert_eq!(<N::Block as Block<N>>::Id::default().as_ref().len(), BlockHash([0u8; 32]).0.len());

  let (main_db, mut tributary_mutable, mut substrate_mutable) =
    boot(&mut raw_db, &network, &mut coordinator).await;

  // We can't load this from the DB as we can't guarantee atomic increments with the ack function
  // TODO: Load with a slight tolerance
  let mut last_coordinator_msg = None;

  loop {
    let mut txn = raw_db.txn();

    let mut outer_msg = None;

    tokio::select! {
      // This blocks the entire processor until it finishes handling this message
      // KeyGen specifically may take a notable amount of processing time
      // While that shouldn't be an issue in practice, as after processing an attempt it'll handle
      // the other messages in the queue, it may be beneficial to parallelize these
      // They could likely be parallelized by type (KeyGen, Sign, Substrate) without issue
      msg = coordinator.recv() => {
        assert_eq!(msg.id, (last_coordinator_msg.unwrap_or(msg.id - 1) + 1));
        last_coordinator_msg = Some(msg.id);


        // Only handle this if we haven't already
        if HandledMessageDb::get(&main_db, msg.id).is_none() {
          HandledMessageDb::set(&mut txn, msg.id, &());

          // This is isolated to better think about how its ordered, or rather, about how the other
          // cases aren't ordered
          //
          // While the coordinator messages are ordered, they're not deterministically ordered
          // Tributary-caused messages are deterministically ordered, and Substrate-caused messages
          // are deterministically-ordered, yet they're both shoved into a singular queue
          // The order at which they're shoved in together isn't deterministic
          //
          // This is safe so long as Tributary and Substrate messages don't both expect mutable
          // references over the same data
          handle_coordinator_msg(
            &mut txn,
            &network,
            &mut coordinator,
            &mut tributary_mutable,
            &mut substrate_mutable,
            &msg,
          ).await;
        }

        outer_msg = Some(msg);
      },

      scanner_event = substrate_mutable.next_scanner_event() => {
        let msg = substrate_mutable.scanner_event_to_multisig_event(
          &mut txn,
          &network,
          scanner_event
        ).await;

        match msg {
          MultisigEvent::Batches(retired_key_new_key, batches) => {
            // Start signing this batch
            for batch in batches {
              info!("created batch {} ({} instructions)", batch.id, batch.instructions.len());

              // The coordinator expects BatchPreprocess to immediately follow Batch
              coordinator.send(
                messages::substrate::ProcessorMessage::Batch { batch: batch.clone() }
              ).await;

              if let Some(batch_signer) = tributary_mutable.batch_signer.as_mut() {
                if let Some(msg) = batch_signer.sign(&mut txn, batch).await {
                  coordinator.send(msg).await;
                }
              }
            }

            if let Some((retired_key, new_key)) = retired_key_new_key {
              // Safe to mutate since all signing operations are done and no more will be added
              tributary_mutable.signers.remove(retired_key.to_bytes().as_ref());
              tributary_mutable.batch_signer.take();
              if let Some((substrate_keys, _)) = tributary_mutable.key_gen.keys(&new_key) {
                tributary_mutable.batch_signer =
                  Some(BatchSigner::new(N::NETWORK, substrate_keys));
              }
            }
          },
          MultisigEvent::Completed(key, id, tx) => {
            if let Some(signer) = tributary_mutable.signers.get_mut(&key) {
              if let Some(msg) = signer.completed(&mut txn, id, tx) {
                coordinator.send(msg).await;
              }
            }
          }
        }
      },
    }

    txn.commit();
    if let Some(msg) = outer_msg {
      coordinator.ack(msg).await;
    }
  }
}

#[tokio::main]
async fn main() {
  // Override the panic handler with one which will panic if any tokio task panics
  {
    let existing = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic| {
      existing(panic);
      const MSG: &str = "exiting the process due to a task panicking";
      println!("{MSG}");
      log::error!("{MSG}");
      std::process::exit(1);
    }));
  }

  if std::env::var("RUST_LOG").is_err() {
    std::env::set_var("RUST_LOG", serai_env::var("RUST_LOG").unwrap_or_else(|| "info".to_string()));
  }
  env_logger::init();

  let db = serai_db::new_rocksdb(&env::var("DB_PATH").expect("path to DB wasn't specified"));

  // Network configuration
  let url = {
    let login = env::var("NETWORK_RPC_LOGIN").expect("network RPC login wasn't specified");
    let hostname = env::var("NETWORK_RPC_HOSTNAME").expect("network RPC hostname wasn't specified");
    let port = env::var("NETWORK_RPC_PORT").expect("network port domain wasn't specified");
    "http://".to_string() + &login + "@" + &hostname + ":" + &port
  };
  let network_id = match env::var("NETWORK").expect("network wasn't specified").as_str() {
    "bitcoin" => NetworkId::Bitcoin,
    "monero" => NetworkId::Monero,
    _ => panic!("unrecognized network"),
  };

  let coordinator = MessageQueue::from_env(Service::Processor(network_id));

  match network_id {
    #[cfg(feature = "bitcoin")]
    NetworkId::Bitcoin => run(db, Bitcoin::new(url).await, coordinator).await,
    #[cfg(feature = "monero")]
    NetworkId::Monero => run(db, Monero::new(url).await, coordinator).await,
    _ => panic!("spawning a processor for an unsupported network"),
  }
}
