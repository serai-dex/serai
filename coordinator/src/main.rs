#![allow(clippy::std_instead_of_alloc, clippy::std_instead_of_core)]

use core::{ops::Deref as _, str::FromStr as _, time::Duration};
use std::{sync::Arc, collections::HashMap, time::Instant};

use zeroize::{Zeroize as _, Zeroizing};
use rand_core::{RngCore as _, OsRng};

use dalek_ff_group::Ristretto;
use ciphersuite::{
  group::{ff::PrimeField as _, GroupEncoding as _},
  *,
};

use borsh::BorshDeserialize as _;

use tokio::sync::mpsc;

use serai_client_serai::{
  abi::primitives::{
    BlockHash,
    crypto::{Public, ExternalKey, KeyPair},
    network_id::ExternalNetworkId,
    validator_sets::ExternalValidatorSet,
    address::SeraiAddress,
  },
  Serai,
};
use message_queue::{Service, client::MessageQueue};

use serai_task::{Task, TaskHandle, ContinuallyRan as _};

use serai_cosign::{Faulted, SignedCosign, Cosigning};
use serai_coordinator_substrate::{
  CanonicalEventStream, EphemeralEventStream, SignSlashReport, SetKeysTask, SignedBatches,
  PublishBatchTask, SlashReports, PublishSlashReportTask,
};
use serai_coordinator_tributary::{SigningProtocolRound, Signed, Transaction, SubstrateBlockPlans};

mod db;
use db::*;

mod tributary;
mod dkg_confirmation;

mod substrate;
use substrate::SubstrateTask;

mod p2p {
  pub use serai_coordinator_p2p::*;
  pub use serai_coordinator_libp2p_p2p::Libp2p;
}

// Use a zeroizing allocator for this entire application
// While secrets should already be zeroized, the presence of secret keys in a networked application
// (at increased risk of OOB reads) justifies the performance hit in case any secrets weren't
// already
#[global_allocator]
static ALLOCATOR: zalloc::ZeroizingAlloc<std::alloc::System> =
  zalloc::ZeroizingAlloc(std::alloc::System);

async fn serai() -> Arc<Serai> {
  const SERAI_CONNECTION_DELAY: Duration = Duration::from_secs(10);
  const MAX_SERAI_CONNECTION_DELAY: Duration = Duration::from_mins(5);

  let mut delay = SERAI_CONNECTION_DELAY;
  loop {
    let Ok(serai) = Serai::new(format!(
      "http://{}:9944",
      serai_env::var("SERAI_HOSTNAME").expect("Serai hostname wasn't provided")
    )) else {
      log::error!("couldn't connect to the Serai node");
      tokio::time::sleep(delay).await;
      delay = (delay + SERAI_CONNECTION_DELAY).min(MAX_SERAI_CONNECTION_DELAY);
      continue;
    };
    log::info!("made initial connection to Serai node");
    return Arc::new(serai);
  }
}

fn spawn_cosigning<D: serai_db::Db>(
  mut db: D,
  serai: Arc<Serai>,
  p2p: impl p2p::P2p,
  tasks_to_run_upon_cosigning: Vec<TaskHandle>,
  mut p2p_cosigns: mpsc::UnboundedReceiver<SignedCosign>,
) {
  let mut cosigning = Cosigning::spawn(db.clone(), serai, p2p.clone(), tasks_to_run_upon_cosigning);
  tokio::spawn(async move {
    const COSIGN_LOOP_INTERVAL: Duration = Duration::from_secs(5);

    let last_cosign_rebroadcast = Instant::now();
    loop {
      // Intake our own cosigns
      match Cosigning::<D>::latest_cosigned_block_number(&db) {
        Ok(latest_cosigned_block_number) => {
          let mut txn = db.txn();
          // The cosigns we prior tried to intake yet failed to
          let mut cosigns = ErroneousCosigns::get(&txn).unwrap_or(vec![]);
          // The cosigns we have yet to intake
          while let Some(cosign) = SignedCosigns::try_recv(&mut txn) {
            cosigns.push(cosign);
          }

          let mut erroneous = vec![];
          for cosign in cosigns {
            // If this cosign is stale, move on
            if cosign.cosign.block_number <= latest_cosigned_block_number {
              continue;
            }

            match cosigning.intake_cosign(&cosign) {
              // Publish this cosign
              Ok(()) => p2p.publish_cosign(cosign).await,
              Err(e) => {
                assert!(e.temporal(), "signed an invalid cosign: {e:?}");
                // Since this had a temporal error, queue it to try again later
                erroneous.push(cosign);
              }
            }
          }

          // Save the cosigns with temporal errors to the database
          ErroneousCosigns::set(&mut txn, &erroneous);

          txn.commit();
        }
        Err(Faulted) => {
          // We don't panic here as the following code rebroadcasts our cosigns which is
          // necessary to inform other coordinators of the faulty cosigns
          log::error!("cosigning faulted");
        }
      }

      let time_till_cosign_rebroadcast = (last_cosign_rebroadcast +
        serai_cosign::BROADCAST_FREQUENCY)
        .saturating_duration_since(Instant::now());
      tokio::select! {
        () = tokio::time::sleep(time_till_cosign_rebroadcast) => {
          for cosign in cosigning.cosigns_to_rebroadcast() {
            p2p.publish_cosign(cosign).await;
          }
        }
        cosign = p2p_cosigns.recv() => {
          let cosign = cosign.expect("p2p cosigns channel was dropped?");
          if cosigning.intake_cosign(&cosign).is_ok() {
            p2p.publish_cosign(cosign).await;
          }
        }
        // Make sure this loop runs at least this often
        () = tokio::time::sleep(COSIGN_LOOP_INTERVAL) => {}
      }
    }
  });
}

async fn handle_network(
  mut db: impl serai_db::Db,
  message_queue: Arc<MessageQueue>,
  serai: Arc<Serai>,
  network: ExternalNetworkId,
) {
  // Spawn the task to publish batches for this network
  {
    let (publish_batch_task_def, publish_batch_task) = Task::new();
    tokio::spawn(
      PublishBatchTask::new(db.clone(), serai.clone(), network)
        .continually_run(publish_batch_task_def, vec![]),
    );
    // Forget its handle so it always runs in the background
    core::mem::forget(publish_batch_task);
  }

  // Handle Processor messages
  loop {
    let (msg_id, msg) = {
      let msg = message_queue.next(Service::Processor(network)).await;
      // Check this message's sender is as expected
      assert_eq!(msg.from, Service::Processor(network));

      // Check this message's ID is as expected
      let last = LastProcessorMessage::get(&db, network);
      let next = last.map(|id| id + 1).unwrap_or(0);
      // This should either be the last message's ID, if we committed but didn't send our ACK, or
      // the expected next message's ID
      assert!((Some(msg.id) == last) || (msg.id == next));

      // TODO: Check msg.sig

      // If this is the message we already handled, and just failed to ACK, ACK it now and move on
      if Some(msg.id) == last {
        message_queue.ack(Service::Processor(network), msg.id).await;
        continue;
      }

      (msg.id, messages::ProcessorMessage::deserialize(&mut msg.msg.as_slice()).unwrap())
    };

    let mut txn = db.txn();

    match msg {
      messages::ProcessorMessage::KeyGen(msg) => match msg {
        messages::key_gen::ProcessorMessage::Participation { session, participation } => {
          let set = ExternalValidatorSet { network, session };
          TributaryTransactionsFromProcessorMessages::send(
            &mut txn,
            set,
            &Transaction::DkgParticipation { participation, signed: Signed::default() },
          );
        }
        messages::key_gen::ProcessorMessage::GeneratedKeyPair {
          session,
          substrate_key,
          network_key,
        } => {
          KeysToConfirm::set(
            &mut txn,
            ExternalValidatorSet { network, session },
            &KeyPair(
              Public(substrate_key),
              ExternalKey(
                network_key
                  .try_into()
                  .expect("generated a network key which exceeds the maximum key length"),
              ),
            ),
          );
        }
        messages::key_gen::ProcessorMessage::Blame { session, participant } => {
          RemoveParticipant::send(&mut txn, ExternalValidatorSet { network, session }, participant);
        }
      },
      messages::ProcessorMessage::Sign(msg) => match msg {
        messages::sign::ProcessorMessage::InvalidParticipant { session, participant } => {
          RemoveParticipant::send(&mut txn, ExternalValidatorSet { network, session }, participant);
        }
        messages::sign::ProcessorMessage::Preprocesses { id, preprocesses } => {
          let set = ExternalValidatorSet { network, session: id.session };
          if id.attempt == 0 {
            // Batches are declared by their intent to be signed
            if let messages::sign::VariantSignId::Batch(hash) = id.id {
              TributaryTransactionsFromProcessorMessages::send(
                &mut txn,
                set,
                &Transaction::Batch { hash },
              );
            }
          }

          TributaryTransactionsFromProcessorMessages::send(
            &mut txn,
            set,
            &Transaction::Sign {
              id: id.id,
              attempt: id.attempt,
              round: SigningProtocolRound::Preprocess,
              data: preprocesses,
              signed: Signed::default(),
            },
          );
        }
        messages::sign::ProcessorMessage::Shares { id, shares } => {
          let set = ExternalValidatorSet { network, session: id.session };
          TributaryTransactionsFromProcessorMessages::send(
            &mut txn,
            set,
            &Transaction::Sign {
              id: id.id,
              attempt: id.attempt,
              round: SigningProtocolRound::Share,
              data: shares,
              signed: Signed::default(),
            },
          );
        }
      },
      messages::ProcessorMessage::Coordinator(msg) => match msg {
        messages::coordinator::ProcessorMessage::CosignedBlock { cosign } => {
          SignedCosigns::send(&mut txn, &cosign);
        }
        messages::coordinator::ProcessorMessage::SignedBatch { batch } => {
          SignedBatches::send(&mut txn, &batch);
        }
        messages::coordinator::ProcessorMessage::SignedSlashReport {
          session,
          slash_report,
          signature,
        } => {
          SlashReports::set(
            &mut txn,
            ExternalValidatorSet { network, session },
            slash_report,
            signature,
          );
        }
      },
      messages::ProcessorMessage::Substrate(msg) => match msg {
        messages::substrate::ProcessorMessage::SubstrateBlockAck { block, plans } => {
          let block = BlockHash(block);
          let mut by_session = HashMap::new();
          for plan in plans {
            by_session
              .entry(plan.session)
              .or_insert_with(|| Vec::with_capacity(1))
              .push(plan.transaction_plan_id);
          }
          for (session, plans) in by_session {
            let set = ExternalValidatorSet { network, session };
            SubstrateBlockPlans::set(&mut txn, set, block, &plans);
            TributaryTransactionsFromProcessorMessages::send(
              &mut txn,
              set,
              &Transaction::SubstrateBlock { hash: block },
            );
          }
        }
      },
    }

    // Mark this as the last handled message
    LastProcessorMessage::set(&mut txn, network, &msg_id);
    // Commit the txn
    txn.commit();
    // Now that we won't handle this message again, acknowledge it so we won't see it again
    message_queue.ack(Service::Processor(network), msg_id).await;
  }
}

#[tokio::main]
async fn main() {
  // Initialize the logger
  env_logger::builder()
    .filter_level(
      log::LevelFilter::from_str(&serai_env::var("RUST_LOG").unwrap_or_else(|| "info".to_owned()))
        .expect("`RUST_LOG` environment variable had an invalid filter"),
    )
    .init();
  log::info!("starting coordinator service...");

  // Read the Serai key from the env
  let serai_key = {
    let mut key_hex = serai_env::var("SERAI_KEY").expect("Serai key wasn't provided");
    let mut key_vec = hex::decode(&key_hex).map_err(|_| ()).expect("Serai key wasn't hex-encoded");
    key_hex.zeroize();
    if key_vec.len() != 32 {
      key_vec.zeroize();
      panic!("Serai key had an invalid length");
    }
    let mut key_bytes = [0; 32];
    key_bytes.copy_from_slice(&key_vec);
    key_vec.zeroize();
    let key = Zeroizing::new(<Ristretto as WrappedGroup>::F::from_repr(key_bytes).unwrap());
    key_bytes.zeroize();
    key
  };

  // Open the database
  let mut db = coordinator_db();

  let existing_tributaries_at_boot = {
    let mut txn = db.txn();

    // Cleanup all historic Tributaries
    while let Some(to_cleanup) = TributaryCleanup::try_recv(&mut txn) {
      prune_tributary_db(to_cleanup);
      // Remove the keys to confirm for this network
      KeysToConfirm::take(&mut txn, to_cleanup);
      KeySet::take(&mut txn, to_cleanup);
      // Drain the cosign intents created for this set
      while !Cosigning::<Db>::intended_cosigns(&mut txn, to_cleanup).is_empty() {}
      // Drain the transactions to publish for this set
      while TributaryTransactionsFromProcessorMessages::try_recv(&mut txn, to_cleanup).is_some() {}
      while TributaryTransactionsFromDkgConfirmation::try_recv(&mut txn, to_cleanup).is_some() {}
      // Drain the participants to remove for this set
      while RemoveParticipant::try_recv(&mut txn, to_cleanup).is_some() {}
      // Remove the SignSlashReport notification
      SignSlashReport::try_recv(&mut txn, to_cleanup);
    }

    // Remove retired Tributaries from ActiveTributaries
    let mut active_tributaries = ActiveTributaries::get(&txn).unwrap_or(vec![]);
    active_tributaries.retain(|tributary| {
      RetiredTributary::get(&txn, tributary.set.network).map(|session| session.0) <
        Some(tributary.set.session.0)
    });
    ActiveTributaries::set(&mut txn, &active_tributaries);

    txn.commit();

    active_tributaries
  };

  // Connect to the message-queue
  let message_queue = Arc::new(MessageQueue::from_env(Service::Coordinator));

  // Connect to the Serai node
  let serai = serai().await;

  let (p2p_add_tributary_send, p2p_add_tributary_recv) = mpsc::unbounded_channel();
  let (p2p_retire_tributary_send, p2p_retire_tributary_recv) = mpsc::unbounded_channel();
  let (p2p_cosigns_send, p2p_cosigns_recv) = mpsc::unbounded_channel();

  // Spawn the P2P network
  let p2p = {
    let serai_keypair = {
      let mut key_bytes = serai_key.to_bytes();
      // Schnorrkel SecretKey is the key followed by 32 bytes of entropy for nonces
      let mut expanded_key = Zeroizing::new([0; 64]);
      expanded_key.as_mut_slice()[.. 32].copy_from_slice(&key_bytes);
      OsRng.fill_bytes(&mut expanded_key.as_mut_slice()[32 ..]);
      key_bytes.zeroize();
      Zeroizing::new(
        schnorrkel::SecretKey::from_bytes(expanded_key.as_slice()).unwrap().to_keypair(),
      )
    };
    let p2p = p2p::Libp2p::new(&serai_keypair, serai.clone());
    tokio::spawn(p2p::run::<Db, Transaction, _>(
      db.clone(),
      p2p.clone(),
      p2p_add_tributary_recv,
      p2p_retire_tributary_recv,
      p2p_cosigns_send,
    ));
    p2p
  };

  // Spawn the Substrate scanners
  let (substrate_task_def, substrate_task) = Task::new();
  let (substrate_canonical_task_def, substrate_canonical_task) = Task::new();
  tokio::spawn(
    CanonicalEventStream::new(db.clone(), serai.clone())
      .continually_run(substrate_canonical_task_def, vec![substrate_task.clone()]),
  );
  let (substrate_ephemeral_task_def, substrate_ephemeral_task) = Task::new();
  tokio::spawn(
    EphemeralEventStream::new(
      db.clone(),
      serai.clone(),
      SeraiAddress((<Ristretto as WrappedGroup>::generator() * serai_key.deref()).to_bytes()),
    )
    .continually_run(substrate_ephemeral_task_def, vec![substrate_task]),
  );

  // Spawn the cosign handler
  spawn_cosigning(
    db.clone(),
    serai.clone(),
    p2p.clone(),
    // Run the Substrate scanners once we cosign new blocks
    vec![substrate_canonical_task, substrate_ephemeral_task],
    p2p_cosigns_recv,
  );

  // Spawn all Tributaries on-disk
  for tributary in existing_tributaries_at_boot {
    crate::tributary::spawn_tributary(
      db.clone(),
      message_queue.clone(),
      p2p.clone(),
      &p2p_add_tributary_send,
      tributary,
      serai_key.clone(),
    )
    .await;
  }

  // Handle the events from the Substrate scanner
  tokio::spawn(
    (SubstrateTask {
      serai_key: serai_key.clone(),
      db: db.clone(),
      message_queue: message_queue.clone(),
      p2p: p2p.clone(),
      p2p_add_tributary: p2p_add_tributary_send.clone(),
      p2p_retire_tributary: p2p_retire_tributary_send.clone(),
    })
    .continually_run(substrate_task_def, vec![]),
  );

  // Handle each of the networks
  for network in ExternalNetworkId::all() {
    tokio::spawn(handle_network(db.clone(), message_queue.clone(), serai.clone(), network));
  }

  // Spawn the task to set keys
  {
    let (set_keys_task_def, set_keys_task) = Task::new();
    tokio::spawn(
      SetKeysTask::new(db.clone(), serai.clone()).continually_run(set_keys_task_def, vec![]),
    );
    // Forget its handle so it always runs in the background
    core::mem::forget(set_keys_task);
  }

  // Spawn the task to publish slash reports
  {
    let (publish_slash_report_task_def, publish_slash_report_task) = Task::new();
    tokio::spawn(
      PublishSlashReportTask::new(db, serai).continually_run(publish_slash_report_task_def, vec![]),
    );
    // Always have this run in the background
    core::mem::forget(publish_slash_report_task);
  }

  // Run the spawned tasks ad-infinitum
  core::future::pending::<()>().await;
}
