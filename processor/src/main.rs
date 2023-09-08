use std::{time::Duration, collections::HashMap};

use zeroize::{Zeroize, Zeroizing};

use transcript::{Transcript, RecommendedTranscript};
use ciphersuite::group::GroupEncoding;

use log::{info, warn};
use tokio::time::sleep;

use serai_client::primitives::{BlockHash, NetworkId};

use messages::{CoordinatorMessage, ProcessorMessage};

use serai_env as env;

use message_queue::{Service, client::MessageQueue};

mod plan;
pub use plan::*;

mod networks;
use networks::{PostFeeBranch, Block, Network, get_latest_block_number, get_block};
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
use signer::{SignerEvent, Signer};

mod substrate_signer;
use substrate_signer::{SubstrateSignerEvent, SubstrateSigner};

mod multisigs;
use multisigs::{MultisigEvent, MultisigManager};
// TODO: Get rid of these
use multisigs::{
  scanner::{Scanner, ScannerHandle},
  Scheduler, get_fee, prepare_send,
};

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

  // There should only be one SubstrateSigner at a time (see #277)
  substrate_signer: Option<SubstrateSigner<D>>,
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
  async fn wait<N: Network, D: Db>(scanner: &ScannerHandle<N, D>, block_hash: &BlockHash) {
    let mut needed_hash = <N::Block as Block<N>>::Id::default();
    needed_hash.as_mut().copy_from_slice(&block_hash.0);

    let block_number = loop {
      // Ensure our scanner has scanned this block, which means our daemon has this block at
      // a sufficient depth
      // The block_number may be set even if scanning isn't complete
      let Some(block_number) = scanner.block_number(&needed_hash).await else {
        warn!(
          "node is desynced. we haven't scanned {} which should happen after {} confirms",
          hex::encode(&needed_hash),
          N::CONFIRMATIONS,
        );
        sleep(Duration::from_secs(10)).await;
        continue;
      };
      break block_number;
    };

    // While the scanner has cemented this block, that doesn't mean it's been scanned for all
    // keys
    // ram_scanned will return the lowest scanned block number out of all keys
    // This is a safe call which fulfills the unfulfilled safety requirements from the prior call
    while scanner.ram_scanned().await < block_number {
      sleep(Duration::from_secs(1)).await;
    }

    // TODO: Sanity check we got an AckBlock (or this is the AckBlock) for the block in
    // question

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
    // wait only reads from, it doesn't mutate, the scanner
    wait(&substrate_mutable.scanner, &required).await;
  }

  // TODO: Shouldn't we create a txn here and pass it around as needed?
  // The txn would ack this message ID. If we detect this message ID as handled in the DB,
  // we'd move on here. Only after committing the TX would we report it as acked.

  match msg.msg.clone() {
    CoordinatorMessage::KeyGen(msg) => {
      coordinator
        .send(ProcessorMessage::KeyGen(tributary_mutable.key_gen.handle(txn, msg).await))
        .await;
    }

    CoordinatorMessage::Sign(msg) => {
      tributary_mutable.signers.get_mut(msg.key()).unwrap().handle(txn, msg).await;
    }

    CoordinatorMessage::Coordinator(msg) => {
      if let Some(substrate_signer) = tributary_mutable.substrate_signer.as_mut() {
        substrate_signer.handle(txn, msg).await;
      }
    }

    CoordinatorMessage::Substrate(msg) => {
      match msg {
        messages::substrate::CoordinatorMessage::ConfirmKeyPair { context, set, key_pair } => {
          // This is the first key pair for this network so no block has been finalized yet
          let activation_number = if context.network_latest_finalized_block.0 == [0; 32] {
            assert!(tributary_mutable.signers.is_empty());
            assert!(tributary_mutable.substrate_signer.is_none());
            assert!(substrate_mutable.existing.as_ref().is_none());

            // Wait until a network's block's time exceeds Serai's time
            // TODO: This assumes the network has a monotonic clock for its blocks' times, which
            // isn't a viable assumption

            // If the latest block number is 10, then the block indexed by 1 has 10 confirms
            // 10 + 1 - 10 = 1
            while get_block(
              network,
              (get_latest_block_number(network).await + 1).saturating_sub(N::CONFIRMATIONS),
            )
            .await
            .time() <
              context.serai_time
            {
              info!(
                "serai confirmed the first key pair for a set. {} {}",
                "we're waiting for a network's finalized block's time to exceed unix time ",
                context.serai_time,
              );
              sleep(Duration::from_secs(5)).await;
            }

            // Find the first block to do so
            let mut earliest =
              (get_latest_block_number(network).await + 1).saturating_sub(N::CONFIRMATIONS);
            assert!(get_block(network, earliest).await.time() >= context.serai_time);
            // earliest > 0 prevents a panic if Serai creates keys before the genesis block
            // which... should be impossible
            // Yet a prevented panic is a prevented panic
            while (earliest > 0) &&
              (get_block(network, earliest - 1).await.time() >= context.serai_time)
            {
              earliest -= 1;
            }

            // Use this as the activation block
            earliest
          } else {
            let mut activation_block = <N::Block as Block<N>>::Id::default();
            activation_block.as_mut().copy_from_slice(&context.network_latest_finalized_block.0);
            // This block_number call is safe since it unwraps
            substrate_mutable
              .block_number(&activation_block)
              .await
              .expect("KeyConfirmed from context we haven't synced")
          };

          info!("activating {set:?}'s keys at {activation_number}");

          // See TributaryMutable's struct definition for why this block is safe
          let KeyConfirmed { substrate_keys, network_keys } =
            tributary_mutable.key_gen.confirm(txn, set, key_pair).await;
          // TODO2: Don't immediately set this, set it once it's active
          tributary_mutable.substrate_signer =
            Some(SubstrateSigner::new(N::NETWORK, substrate_keys));

          let key = network_keys.group_key();

          substrate_mutable.add_key(txn, activation_number, key).await;

          tributary_mutable
            .signers
            .insert(key.to_bytes().as_ref().to_vec(), Signer::new(network.clone(), network_keys));
        }

        messages::substrate::CoordinatorMessage::SubstrateBlock {
          context,
          network: network_id,
          block: substrate_block,
          burns,
          batches,
        } => {
          assert_eq!(network_id, N::NETWORK, "coordinator sent us data for another network");

          // Since this block was acknowledged, we no longer have to sign the batches for it
          if let Some(substrate_signer) = tributary_mutable.substrate_signer.as_mut() {
            for batch_id in batches {
              substrate_signer.batch_signed(txn, batch_id);
            }
          }

          let plans = substrate_mutable.substrate_block(txn, context, burns).await;

          coordinator
            .send(ProcessorMessage::Coordinator(
              messages::coordinator::ProcessorMessage::SubstrateBlockAck {
                network: N::NETWORK,
                block: substrate_block,
                plans: plans.iter().map(|plan| plan.id()).collect(),
              },
            ))
            .await;

          substrate_mutable
            .sign_plans(
              txn,
              network,
              context,
              // See commentary in TributaryMutable for why this is safe
              &mut tributary_mutable.signers,
              plans,
            )
            .await;
        }
      }
    }
  }
}

async fn boot<N: Network, D: Db>(
  raw_db: &mut D,
  network: &N,
) -> (MainDb<N, D>, TributaryMutable<N, D>, SubstrateMutable<N, D>) {
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
  let key_gen = KeyGen::<N, _>::new(raw_db.clone(), entropy(b"key-gen_entropy"));
  // The scanner has no long-standing orders to re-issue
  let (mut scanner, active_keys) = Scanner::new(network.clone(), raw_db.clone());

  let mut schedulers = HashMap::<Vec<u8>, Scheduler<N>>::new();
  let mut substrate_signer = None;
  let mut signers = HashMap::new();

  let main_db = MainDb::<N, _>::new(raw_db.clone());

  for key in &active_keys {
    schedulers.insert(key.to_bytes().as_ref().to_vec(), Scheduler::from_db(raw_db, *key).unwrap());

    let (substrate_keys, network_keys) = key_gen.keys(key);

    // We don't have to load any state for this since the Scanner will re-fire any events
    // necessary
    // TODO2: This uses most recent as signer, use the active one
    substrate_signer = Some(SubstrateSigner::new(N::NETWORK, substrate_keys));

    let mut signer = Signer::new(network.clone(), network_keys);

    // Load any TXs being actively signed
    // TODO: Move this into MultisigManager?
    let key = key.to_bytes();
    for (block_number, plan) in main_db.signing(key.as_ref()) {
      let block_number = block_number.try_into().unwrap();

      let fee = get_fee(network, block_number).await;

      let id = plan.id();
      info!("reloading plan {}: {:?}", hex::encode(id), plan);

      let key_bytes = plan.key.to_bytes();

      let (Some((tx, eventuality)), _) = prepare_send(network, block_number, fee, plan).await
      else {
        panic!("previously created transaction is no longer being created")
      };

      scanner.register_eventuality(key_bytes.as_ref(), block_number, id, eventuality.clone()).await;
      // TODO: Reconsider if the Signer should have the eventuality, or if just the network/scanner
      // should
      let mut txn = raw_db.txn();
      signer.sign_transaction(&mut txn, id, tx, eventuality).await;
      // This should only have re-writes of existing data
      drop(txn);
    }

    signers.insert(key.as_ref().to_vec(), signer);
  }

  (
    main_db,
    TributaryMutable { key_gen, substrate_signer, signers },
    MultisigManager::new(scanner, schedulers),
  )
}

async fn run<N: Network, D: Db, Co: Coordinator>(mut raw_db: D, network: N, mut coordinator: Co) {
  // We currently expect a contextless bidirectional mapping between these two values
  // (which is that any value of A can be interpreted as B and vice versa)
  // While we can write a contextual mapping, we have yet to do so
  // This check ensures no network which doesn't have a bidirectional mapping is defined
  assert_eq!(<N::Block as Block<N>>::Id::default().as_ref().len(), BlockHash([0u8; 32]).0.len());

  let (mut main_db, mut tributary_mutable, mut substrate_mutable) =
    boot(&mut raw_db, &network).await;

  // We can't load this from the DB as we can't guarantee atomic increments with the ack function
  let mut last_coordinator_msg = None;

  loop {
    // Check if the signers have events
    // The signers will only have events after the following select executes, which will then
    // trigger the loop again, hence why having the code here with no timer is fine
    for (key, signer) in tributary_mutable.signers.iter_mut() {
      while let Some(msg) = signer.events.pop_front() {
        match msg {
          SignerEvent::ProcessorMessage(msg) => {
            coordinator.send(ProcessorMessage::Sign(msg)).await;
          }

          SignerEvent::SignedTransaction { id, tx } => {
            coordinator
              .send(ProcessorMessage::Sign(messages::sign::ProcessorMessage::Completed {
                key: key.clone(),
                id,
                tx: tx.as_ref().to_vec(),
              }))
              .await;

            let mut txn = raw_db.txn();
            main_db.finish_signing(&mut txn, key, id);
            txn.commit();
          }
        }
      }
    }

    if let Some(signer) = tributary_mutable.substrate_signer.as_mut() {
      while let Some(msg) = signer.events.pop_front() {
        match msg {
          SubstrateSignerEvent::ProcessorMessage(msg) => {
            coordinator.send(ProcessorMessage::Coordinator(msg)).await;
          }
          SubstrateSignerEvent::SignedBatch(batch) => {
            coordinator
              .send(ProcessorMessage::Substrate(messages::substrate::ProcessorMessage::Update {
                batch,
              }))
              .await;
          }
        }
      }
    }

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
        if !main_db.handled_message(msg.id) {
          let mut txn = raw_db.txn();
          MainDb::<N, D>::handle_message(&mut txn, msg.id);

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

          txn.commit();
        }

        coordinator.ack(msg).await;
      },

      // TODO: Replace this with proper channel management
      msg = substrate_mutable.scanner.events.recv() => {
        let mut txn = raw_db.txn();

        match substrate_mutable.scanner_event(&mut txn, msg.unwrap()) {
          MultisigEvent::Batches(batches) => {
            // Start signing this batch
            for batch in batches {
              info!("created batch {} ({} instructions)", batch.id, batch.instructions.len());

              if let Some(substrate_signer) = tributary_mutable.substrate_signer.as_mut() {
                substrate_signer
                  .sign(&mut txn, batch)
                  .await;
              }
            }
          },
          MultisigEvent::Completed(key, id, tx) => {
            if let Some(signer) = tributary_mutable.signers.get_mut(&key) {
              if signer.eventuality_completion(&mut txn, id, &tx).await {
                log::warn!(
                  "informed of eventuality completion for {} {}",
                  hex::encode(id),
                  "by blockchain instead of by signing/P2P",
                );
              }
            }
          }
        }

        txn.commit();
      },
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
    NetworkId::Monero => run(db, Monero::new(url), coordinator).await,
    _ => panic!("spawning a processor for an unsupported network"),
  }
}
