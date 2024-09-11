use messages::{
  coordinator::{
    SubstrateSignableId, PlanMeta, CoordinatorMessage as CoordinatorCoordinatorMessage,
  },
  CoordinatorMessage,
};

use serai_env as env;

use message_queue::{Service, client::MessageQueue};

mod db;
pub use db::*;

mod coordinator;
pub use coordinator::*;

mod multisigs;
use multisigs::{MultisigEvent, MultisigManager};

#[cfg(test)]
mod tests;

async fn handle_coordinator_msg<D: Db, N: Network, Co: Coordinator>(
  txn: &mut D::Transaction<'_>,
  network: &N,
  coordinator: &mut Co,
  tributary_mutable: &mut TributaryMutable<N, D>,
  substrate_mutable: &mut SubstrateMutable<N, D>,
  msg: &Message,
) {
  match msg.msg.clone() {
    CoordinatorMessage::Substrate(msg) => {
      match msg {
        messages::substrate::CoordinatorMessage::SubstrateBlock {
          context,
          block: substrate_block,
          burns,
          batches,
        } => {
          // Send SubstrateBlockAck, with relevant plan IDs, before we trigger the signing of these
          // plans
          if !tributary_mutable.signers.is_empty() {
            coordinator
              .send(messages::coordinator::ProcessorMessage::SubstrateBlockAck {
                block: substrate_block,
                plans: to_sign
                  .iter()
                  .filter_map(|signable| {
                    SessionDb::get(txn, signable.0.to_bytes().as_ref())
                      .map(|session| PlanMeta { session, id: signable.1 })
                  })
                  .collect(),
              })
              .await;
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
  fn read_key_from_env<C: Ciphersuite>(label: &'static str) -> Zeroizing<C::F> {
    let key_hex =
      Zeroizing::new(env::var(label).unwrap_or_else(|| panic!("{label} wasn't provided")));
    let bytes = Zeroizing::new(
      hex::decode(key_hex).unwrap_or_else(|_| panic!("{label} wasn't a valid hex string")),
    );

    let mut repr = <C::F as PrimeField>::Repr::default();
    if repr.as_ref().len() != bytes.len() {
      panic!("{label} wasn't the correct length");
    }
    repr.as_mut().copy_from_slice(bytes.as_slice());
    let res = Zeroizing::new(
      Option::from(<C::F as PrimeField>::from_repr(repr))
        .unwrap_or_else(|| panic!("{label} wasn't a valid scalar")),
    );
    repr.as_mut().zeroize();
    res
  }

  let key_gen = KeyGen::<N, _>::new(
    raw_db.clone(),
    read_key_from_env::<<Ristretto as EvrfCurve>::EmbeddedCurve>("SUBSTRATE_EVRF_KEY"),
    read_key_from_env::<<N::Curve as EvrfCurve>::EmbeddedCurve>("NETWORK_EVRF_KEY"),
  );

  let (multisig_manager, current_keys, actively_signing) =
    MultisigManager::new(raw_db, network).await;

  let mut batch_signer = None;
  let mut signers = HashMap::new();

  for (i, key) in current_keys.iter().enumerate() {
    let Some((session, (substrate_keys, network_keys))) = key_gen.keys(key) else { continue };
    let network_key = network_keys[0].group_key();

    // If this is the oldest key, load the BatchSigner for it as the active BatchSigner
    // The new key only takes responsibility once the old key is fully deprecated
    //
    // We don't have to load any state for this since the Scanner will re-fire any events
    // necessary, only no longer scanning old blocks once Substrate acks them
    if i == 0 {
      batch_signer = Some(BatchSigner::new(N::NETWORK, session, substrate_keys));
    }

    // The Scanner re-fires events as needed for batch_signer yet not signer
    // This is due to the transactions which we start signing from due to a block not being
    // guaranteed to be signed before we stop scanning the block on reboot
    // We could simplify the Signer flow by delaying when it acks a block, yet that'd:
    // 1) Increase the startup time
    // 2) Cause re-emission of Batch events, which we'd need to check the safety of
    //    (TODO: Do anyways?)
    // 3) Violate the attempt counter (TODO: Is this already being violated?)
    let mut signer = Signer::new(network.clone(), session, network_keys);

    // Sign any TXs being actively signed
    for (plan, tx, eventuality) in &actively_signing {
      if plan.key == network_key {
        let mut txn = raw_db.txn();
        if let Some(msg) =
          signer.sign_transaction(&mut txn, plan.id(), tx.clone(), eventuality).await
        {
          coordinator.send(msg).await;
        }
        // This should only have re-writes of existing data
        drop(txn);
      }
    }

    signers.insert(session, signer);
  }

  // Spawn a task to rebroadcast signed TXs yet to be mined into a finalized block
  // This hedges against being dropped due to full mempools, temporarily too low of a fee...
  tokio::spawn(Signer::<N, D>::rebroadcast_task(raw_db.clone(), network.clone()));

  (
    raw_db.clone(),
    TributaryMutable { key_gen, batch_signer, cosigner: None, slash_report_signer: None, signers },
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

    log::trace!("new db txn in run");

    let mut outer_msg = None;

    tokio::select! {
      // This blocks the entire processor until it finishes handling this message
      // KeyGen specifically may take a notable amount of processing time
      // While that shouldn't be an issue in practice, as after processing an attempt it'll handle
      // the other messages in the queue, it may be beneficial to parallelize these
      // They could potentially be parallelized by type (KeyGen, Sign, Substrate) without issue
      msg = coordinator.recv() => {
        if let Some(last_coordinator_msg) = last_coordinator_msg {
          assert_eq!(msg.id, last_coordinator_msg + 1);
        }
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
                if let Some(msg) = batch_signer.sign(&mut txn, batch) {
                  coordinator.send(msg).await;
                }
              }
            }

            if let Some((retired_key, new_key)) = retired_key_new_key {
              // Safe to mutate since all signing operations are done and no more will be added
              if let Some(retired_session) = SessionDb::get(&txn, retired_key.to_bytes().as_ref()) {
                tributary_mutable.signers.remove(&retired_session);
              }
              tributary_mutable.batch_signer.take();
              let keys = tributary_mutable.key_gen.keys(&new_key);
              if let Some((session, (substrate_keys, _))) = keys {
                tributary_mutable.batch_signer =
                  Some(BatchSigner::new(N::NETWORK, session, substrate_keys));
              }
            }
          },
          MultisigEvent::Completed(key, id, tx) => {
            if let Some(session) = SessionDb::get(&txn, &key) {
              let signer = tributary_mutable.signers.get_mut(&session).unwrap();
              if let Some(msg) = signer.completed(&mut txn, id, &tx) {
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

  #[allow(unused_variables, unreachable_code)]
  let db = {
    #[cfg(all(feature = "parity-db", feature = "rocksdb"))]
    panic!("built with parity-db and rocksdb");
    #[cfg(all(feature = "parity-db", not(feature = "rocksdb")))]
    let db =
      serai_db::new_parity_db(&serai_env::var("DB_PATH").expect("path to DB wasn't specified"));
    #[cfg(feature = "rocksdb")]
    let db =
      serai_db::new_rocksdb(&serai_env::var("DB_PATH").expect("path to DB wasn't specified"));
    db
  };

  // Network configuration
  let url = {
    let login = env::var("NETWORK_RPC_LOGIN").expect("network RPC login wasn't specified");
    let hostname = env::var("NETWORK_RPC_HOSTNAME").expect("network RPC hostname wasn't specified");
    let port = env::var("NETWORK_RPC_PORT").expect("network port domain wasn't specified");
    "http://".to_string() + &login + "@" + &hostname + ":" + &port
  };
  let network_id = match env::var("NETWORK").expect("network wasn't specified").as_str() {
    "bitcoin" => NetworkId::Bitcoin,
    "ethereum" => NetworkId::Ethereum,
    "monero" => NetworkId::Monero,
    _ => panic!("unrecognized network"),
  };

  let coordinator = MessageQueue::from_env(Service::Processor(network_id));

  match network_id {
    #[cfg(feature = "bitcoin")]
    NetworkId::Bitcoin => run(db, Bitcoin::new(url).await, coordinator).await,
    #[cfg(feature = "ethereum")]
    NetworkId::Ethereum => {
      let relayer_hostname = env::var("ETHEREUM_RELAYER_HOSTNAME")
        .expect("ethereum relayer hostname wasn't specified")
        .to_string();
      let relayer_port =
        env::var("ETHEREUM_RELAYER_PORT").expect("ethereum relayer port wasn't specified");
      let relayer_url = relayer_hostname + ":" + &relayer_port;
      run(db.clone(), Ethereum::new(db, url, relayer_url).await, coordinator).await
    }
    #[cfg(feature = "monero")]
    NetworkId::Monero => run(db, Monero::new(url).await, coordinator).await,
    _ => panic!("spawning a processor for an unsupported network"),
  }
}
