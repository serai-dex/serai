use std::{
  time::Duration,
  collections::{VecDeque, HashMap},
};

use zeroize::{Zeroize, Zeroizing};

use transcript::{Transcript, RecommendedTranscript};
use ciphersuite::group::GroupEncoding;
use frost::{curve::Ciphersuite, ThresholdKeys};

use log::{info, warn, error};
use tokio::time::sleep;

use scale::{Encode, Decode};

use serai_client::{
  primitives::{MAX_DATA_LEN, BlockHash, NetworkId},
  tokens::primitives::{OutInstruction, OutInstructionWithBalance},
  in_instructions::primitives::{
    Shorthand, RefundableInInstruction, InInstructionWithBalance, Batch, MAX_BATCH_SIZE,
  },
};

use messages::{SubstrateContext, CoordinatorMessage, ProcessorMessage};

use serai_env as env;

use message_queue::{Service, client::MessageQueue};

mod plan;
pub use plan::*;

mod networks;
use networks::{OutputType, Output, PostFeeBranch, Block, Network};
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

mod scanner;
use scanner::{ScannerEvent, Scanner, ScannerHandle};

mod scheduler;
use scheduler::Scheduler;

#[cfg(test)]
mod tests;

async fn get_latest_block_number<N: Network>(network: &N) -> usize {
  loop {
    match network.get_latest_block_number().await {
      Ok(number) => {
        return number;
      }
      Err(e) => {
        error!(
          "couldn't get the latest block number in main's error-free get_block. {} {}",
          "this should only happen if the node is offline. error: ", e
        );
        sleep(Duration::from_secs(10)).await;
      }
    }
  }
}

async fn get_block<N: Network>(network: &N, block_number: usize) -> N::Block {
  loop {
    match network.get_block(block_number).await {
      Ok(block) => {
        return block;
      }
      Err(e) => {
        error!("couldn't get block {block_number} in main's error-free get_block. error: {}", e);
        sleep(Duration::from_secs(10)).await;
      }
    }
  }
}

async fn get_fee<N: Network>(network: &N, block_number: usize) -> N::Fee {
  // TODO2: Use an fee representative of several blocks
  get_block(network, block_number).await.median_fee()
}

async fn prepare_send<N: Network>(
  network: &N,
  keys: ThresholdKeys<N::Curve>,
  block_number: usize,
  fee: N::Fee,
  plan: Plan<N>,
) -> (Option<(N::SignableTransaction, N::Eventuality)>, Vec<PostFeeBranch>) {
  loop {
    match network.prepare_send(keys.clone(), block_number, plan.clone(), fee).await {
      Ok(prepared) => {
        return prepared;
      }
      Err(e) => {
        error!("couldn't prepare a send for plan {}: {e}", hex::encode(plan.id()));
        // The processor is either trying to create an invalid TX (fatal) or the node went
        // offline
        // The former requires a patch, the latter is a connection issue
        // If the latter, this is an appropriate sleep. If the former, we should panic, yet
        // this won't flood the console ad infinitum
        sleep(Duration::from_secs(60)).await;
      }
    }
  }
}

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

  // TODO: There should only be one SubstrateSigner at a time (see #277)
  substrate_signers: HashMap<Vec<u8>, SubstrateSigner<D>>,
}

// Items which are mutably borrowed by Substrate.
// Any exceptions to this have to be carefully monitored in order to ensure consistency isn't
// violated.
struct SubstrateMutable<N: Network, D: Db> {
  // The scanner is expected to autonomously operate, scanning blocks as they appear.
  // When a block is sufficiently confirmed, the scanner mutates the signer to try and get a Batch
  // signed.
  // The scanner itself only mutates its list of finalized blocks and in-memory state though.
  // Disk mutations to the scan-state only happen when Substrate says to.

  // This can't be mutated as soon as a Batch is signed since the mutation which occurs then is
  // paired with the mutations caused by Burn events. Substrate's ordering determines if such a
  // pairing exists.
  scanner: ScannerHandle<N, D>,

  // Schedulers take in new outputs, from the scanner, and payments, from Burn events on Substrate.
  // These are paired when possible, in the name of efficiency. Accordingly, both mutations must
  // happen by Substrate.
  schedulers: HashMap<Vec<u8>, Scheduler<N>>,
}

async fn sign_plans<N: Network, D: Db>(
  txn: &mut D::Transaction<'_>,
  network: &N,
  substrate_mutable: &mut SubstrateMutable<N, D>,
  signers: &mut HashMap<Vec<u8>, Signer<N, D>>,
  context: SubstrateContext,
  plans: Vec<Plan<N>>,
) {
  let mut plans = VecDeque::from(plans);

  let mut block_hash = <N::Block as Block<N>>::Id::default();
  block_hash.as_mut().copy_from_slice(&context.network_latest_finalized_block.0);
  // block_number call is safe since it unwraps
  let block_number = substrate_mutable
    .scanner
    .block_number(&block_hash)
    .await
    .expect("told to sign_plans on a context we're not synced to");

  let fee = get_fee(network, block_number).await;

  while let Some(plan) = plans.pop_front() {
    let id = plan.id();
    info!("preparing plan {}: {:?}", hex::encode(id), plan);

    let key = plan.key.to_bytes();
    MainDb::<N, D>::save_signing(txn, key.as_ref(), block_number.try_into().unwrap(), &plan);
    let (tx, branches) =
      prepare_send(network, signers.get_mut(key.as_ref()).unwrap().keys(), block_number, fee, plan)
        .await;

    for branch in branches {
      substrate_mutable
        .schedulers
        .get_mut(key.as_ref())
        .expect("didn't have a scheduler for a key we have a plan for")
        .created_output::<D>(txn, branch.expected, branch.actual);
    }

    if let Some((tx, eventuality)) = tx {
      substrate_mutable.scanner.register_eventuality(block_number, id, eventuality.clone()).await;
      signers.get_mut(key.as_ref()).unwrap().sign_transaction(txn, id, tx, eventuality).await;
    }

    // TODO: If the TX is None, should we restore its inputs to the scheduler?
  }
}

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
      tributary_mutable.substrate_signers.get_mut(msg.key()).unwrap().handle(txn, msg).await;
    }

    CoordinatorMessage::Substrate(msg) => {
      match msg {
        messages::substrate::CoordinatorMessage::ConfirmKeyPair { context, set, key_pair } => {
          // This is the first key pair for this network so no block has been finalized yet
          let activation_number = if context.network_latest_finalized_block.0 == [0; 32] {
            assert!(tributary_mutable.signers.is_empty());
            assert!(tributary_mutable.substrate_signers.is_empty());
            assert!(substrate_mutable.schedulers.is_empty());

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
              .scanner
              .block_number(&activation_block)
              .await
              .expect("KeyConfirmed from context we haven't synced")
          };

          info!("activating {set:?}'s keys at {activation_number}");

          // See TributaryMutable's struct definition for why this block is safe
          let KeyConfirmed { substrate_keys, network_keys } =
            tributary_mutable.key_gen.confirm(txn, set, key_pair).await;
          tributary_mutable.substrate_signers.insert(
            substrate_keys.group_key().to_bytes().to_vec(),
            SubstrateSigner::new(substrate_keys),
          );

          let key = network_keys.group_key();

          substrate_mutable.scanner.rotate_key(txn, activation_number, key).await;
          substrate_mutable
            .schedulers
            .insert(key.to_bytes().as_ref().to_vec(), Scheduler::<N>::new::<D>(txn, key));

          tributary_mutable
            .signers
            .insert(key.to_bytes().as_ref().to_vec(), Signer::new(network.clone(), network_keys));
        }

        messages::substrate::CoordinatorMessage::SubstrateBlock {
          context,
          network: network_id,
          block,
          key: key_vec,
          burns,
        } => {
          assert_eq!(network_id, N::NETWORK, "coordinator sent us data for another network");

          let mut block_id = <N::Block as Block<N>>::Id::default();
          block_id.as_mut().copy_from_slice(&context.network_latest_finalized_block.0);

          let key = <N::Curve as Ciphersuite>::read_G::<&[u8]>(&mut key_vec.as_ref()).unwrap();

          // We now have to acknowledge every block for this key up to the acknowledged block
          let (blocks, outputs) =
            substrate_mutable.scanner.ack_up_to_block(txn, key, block_id).await;
          // Since this block was acknowledged, we no longer have to sign the batch for it
          for block in blocks {
            for (_, signer) in tributary_mutable.substrate_signers.iter_mut() {
              signer.batch_signed(txn, block);
            }
          }

          let mut payments = vec![];
          for out in burns {
            let OutInstructionWithBalance {
              instruction: OutInstruction { address, data },
              balance,
            } = out;
            assert_eq!(balance.coin.network(), N::NETWORK);

            if let Ok(address) = N::Address::try_from(address.consume()) {
              // TODO: Add coin to payment
              payments.push(Payment {
                address,
                data: data.map(|data| data.consume()),
                amount: balance.amount.0,
              });
            }
          }

          let plans = substrate_mutable
            .schedulers
            .get_mut(&key_vec)
            .expect("key we don't have a scheduler for acknowledged a block")
            .schedule::<D>(txn, outputs, payments);

          coordinator
            .send(ProcessorMessage::Coordinator(
              messages::coordinator::ProcessorMessage::SubstrateBlockAck {
                network: N::NETWORK,
                block,
                plans: plans.iter().map(|plan| plan.id()).collect(),
              },
            ))
            .await;

          sign_plans(
            txn,
            network,
            substrate_mutable,
            // See commentary in TributaryMutable for why this is safe
            &mut tributary_mutable.signers,
            context,
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
  let mut substrate_signers = HashMap::new();
  let mut signers = HashMap::new();

  let main_db = MainDb::new(raw_db.clone());

  for key in &active_keys {
    schedulers.insert(key.to_bytes().as_ref().to_vec(), Scheduler::from_db(raw_db, *key).unwrap());

    let (substrate_keys, network_keys) = key_gen.keys(key);

    let substrate_key = substrate_keys.group_key();
    let substrate_signer = SubstrateSigner::new(substrate_keys);
    // We don't have to load any state for this since the Scanner will re-fire any events
    // necessary
    substrate_signers.insert(substrate_key.to_bytes().to_vec(), substrate_signer);

    let mut signer = Signer::new(network.clone(), network_keys);

    // Load any TXs being actively signed
    let key = key.to_bytes();
    for (block_number, plan) in main_db.signing(key.as_ref()) {
      let block_number = block_number.try_into().unwrap();

      let fee = get_fee(network, block_number).await;

      let id = plan.id();
      info!("reloading plan {}: {:?}", hex::encode(id), plan);

      let (Some((tx, eventuality)), _) =
        prepare_send(network, signer.keys(), block_number, fee, plan).await
      else {
        panic!("previously created transaction is no longer being created")
      };

      scanner.register_eventuality(block_number, id, eventuality.clone()).await;
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
    TributaryMutable { key_gen, substrate_signers, signers },
    SubstrateMutable { scanner, schedulers },
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
            // This does mutate the Scanner, yet the eventuality protocol is only run to mutate
            // the signer, which is Tributary mutable (and what's currently being mutated)
            substrate_mutable.scanner.drop_eventuality(id).await;
            main_db.finish_signing(&mut txn, key, id);
            txn.commit();
          }
        }
      }
    }

    for (key, signer) in tributary_mutable.substrate_signers.iter_mut() {
      while let Some(msg) = signer.events.pop_front() {
        match msg {
          SubstrateSignerEvent::ProcessorMessage(msg) => {
            coordinator.send(ProcessorMessage::Coordinator(msg)).await;
          }
          SubstrateSignerEvent::SignedBatch(batch) => {
            coordinator
              .send(ProcessorMessage::Substrate(messages::substrate::ProcessorMessage::Update {
                key: key.clone(),
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

      msg = substrate_mutable.scanner.events.recv() => {
        let mut txn = raw_db.txn();

        match msg.unwrap() {
          ScannerEvent::Block { key, block, batch, outputs } => {
            let mut block_hash = [0; 32];
            block_hash.copy_from_slice(block.as_ref());

            let mut batches = vec![];
            let mut ins = vec![];
            let mut batch_size: usize = 0;
            for output in outputs {
              // If these aren't externally received funds, don't handle it as an instruction
              if output.kind() != OutputType::External {
                continue;
              }

              let mut data = output.data();
              let max_data_len = MAX_DATA_LEN.try_into().unwrap();
              if data.len() > max_data_len {
                error!(
                  "data in output {} exceeded MAX_DATA_LEN ({MAX_DATA_LEN}): {}",
                  hex::encode(output.id()),
                  data.len(),
                );
                data = &data[.. max_data_len];
              }

              let Ok(shorthand) = Shorthand::decode(&mut data) else { continue };
              let Ok(instruction) = RefundableInInstruction::try_from(shorthand) else { continue };

              // TODO2: Set instruction.origin if not set (and handle refunds in general)
              let in_ins = InInstructionWithBalance {
                instruction: instruction.instruction,
                balance: output.balance(),
              };
              let ins_size = in_ins.encode().len();

              // batch has 38 bytes of other data
              // TODO: should we make another const for this 38?
              if batch_size + ins_size > MAX_BATCH_SIZE - 38 {
                // TODO: should we check other ins in the vec that would potentially fit or
                // that would be too slow and not worth it?
                // batch is full
                batches.push(Batch {
                  network: N::NETWORK,
                  id: batch,
                  block: BlockHash(block_hash),
                  instructions: ins.clone()
                });

                ins.clear();
                batch_size = 0;
                continue;
              }

              ins.push(in_ins);
              batch_size += ins_size;
            }

            info!("created batch {} ({} instructions)", batch.id, batch.instructions.len());

            // Start signing this batch
            for batch in batches {
              // TODO: Don't reload both sets of keys in full just to get the Substrate public key
              tributary_mutable
                .substrate_signers
                .get_mut(tributary_mutable.key_gen.keys(&key).0.group_key().to_bytes().as_slice())
                .unwrap()
                .sign(&mut txn, batch)
                .await;
            }
          },

          ScannerEvent::Completed(id, tx) => {
            // We don't know which signer had this plan, so inform all of them
            for (_, signer) in tributary_mutable.signers.iter_mut() {
              signer.eventuality_completion(&mut txn, id, &tx).await;
            }
          },
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
