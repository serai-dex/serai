use std::{
  env,
  time::Duration,
  collections::{VecDeque, HashMap},
};

use zeroize::{Zeroize, Zeroizing};

use transcript::{Transcript, RecommendedTranscript};
use group::GroupEncoding;
use frost::curve::Ciphersuite;

use log::{info, warn, error};
use tokio::time::sleep;

use scale::Decode;

use serai_client::{
  primitives::{MAX_DATA_LEN, BlockHash},
  tokens::primitives::{OutInstruction, OutInstructionWithBalance},
  in_instructions::primitives::{
    Shorthand, RefundableInInstruction, InInstructionWithBalance, Batch,
  },
};

use messages::{SubstrateContext, CoordinatorMessage, ProcessorMessage};

mod plan;
pub use plan::*;

mod db;
pub use db::*;

mod coordinator;
pub use coordinator::*;

mod coins;
use coins::{OutputType, Output, PostFeeBranch, Block, Coin};
#[cfg(feature = "bitcoin")]
use coins::Bitcoin;
#[cfg(feature = "monero")]
use coins::Monero;

mod key_gen;
use key_gen::{KeyGenEvent, KeyGen};

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

// Generate a static additional key for a given chain in a globally consistent manner
// Doesn't consider the current group key to increase the simplicity of verifying Serai's status
// Takes an index, k, to support protocols which use multiple secondary keys
// Presumably a view key
pub(crate) fn additional_key<C: Coin>(k: u64) -> <C::Curve as Ciphersuite>::F {
  <C::Curve as Ciphersuite>::hash_to_F(
    b"Serai DEX Additional Key",
    &[C::ID.as_bytes(), &k.to_le_bytes()].concat(),
  )
}

async fn get_fee<C: Coin>(coin: &C, block_number: usize) -> C::Fee {
  loop {
    // TODO2: Use an fee representative of several blocks
    match coin.get_block(block_number).await {
      Ok(block) => {
        return block.median_fee();
      }
      Err(e) => {
        error!(
          "couldn't get block {block_number} in get_fee. {} {}",
          "this should only happen if the node is offline. error: ", e
        );
        // Since this block is considered finalized, we shouldn't be unable to get it unless the
        // node is offline, hence the long sleep
        sleep(Duration::from_secs(60)).await;
      }
    }
  }
}

async fn prepare_send<C: Coin, D: Db>(
  coin: &C,
  signer: &Signer<C, D>,
  block_number: usize,
  fee: C::Fee,
  plan: Plan<C>,
) -> (Option<(C::SignableTransaction, C::Eventuality)>, Vec<PostFeeBranch>) {
  let keys = signer.keys().await;
  loop {
    match coin.prepare_send(keys.clone(), block_number, plan.clone(), fee).await {
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

async fn sign_plans<C: Coin, D: Db>(
  db: &mut MainDb<C, D>,
  coin: &C,
  scanner: &ScannerHandle<C, D>,
  schedulers: &mut HashMap<Vec<u8>, Scheduler<C>>,
  signers: &mut HashMap<Vec<u8>, Signer<C, D>>,
  context: SubstrateContext,
  plans: Vec<Plan<C>>,
) {
  let mut plans = VecDeque::from(plans);

  let mut block_hash = <C::Block as Block<C>>::Id::default();
  block_hash.as_mut().copy_from_slice(&context.coin_latest_finalized_block.0);
  let block_number = scanner
    .block_number(&block_hash)
    .await
    .expect("told to sign_plans on a context we're not synced to");

  let fee = get_fee(coin, block_number).await;

  while let Some(plan) = plans.pop_front() {
    let id = plan.id();
    info!("preparing plan {}: {:?}", hex::encode(id), plan);

    let key = plan.key.to_bytes();
    db.save_signing(key.as_ref(), block_number.try_into().unwrap(), &plan);
    let (tx, branches) =
      prepare_send(coin, signers.get_mut(key.as_ref()).unwrap(), block_number, fee, plan).await;

    // TODO: If we reboot mid-sign_plans, for a DB-backed scheduler, these may be partially
    // executed
    // Global TXN object for the entire coordinator message?
    // Re-ser the scheduler after every sign_plans call?
    // To clarify, the scheduler is distinct as it mutates itself on new data.
    // The key_gen/scanner/signer are designed to be deterministic to new data, irrelevant to prior
    // states.
    for branch in branches {
      schedulers
        .get_mut(key.as_ref())
        .expect("didn't have a scheduler for a key we have a plan for")
        .created_output(branch.expected, branch.actual);
    }

    if let Some((tx, eventuality)) = tx {
      scanner.register_eventuality(block_number, id, eventuality.clone()).await;
      signers.get_mut(key.as_ref()).unwrap().sign_transaction(id, tx, eventuality).await;
    }
  }
}

async fn run<C: Coin, D: Db, Co: Coordinator>(raw_db: D, coin: C, mut coordinator: Co) {
  // We currently expect a contextless bidirectional mapping between these two values
  // (which is that any value of A can be interpreted as B and vice versa)
  // While we can write a contextual mapping, we have yet to do so
  // This check ensures no coin which doesn't have a bidirectional mapping is defined
  assert_eq!(<C::Block as Block<C>>::Id::default().as_ref().len(), BlockHash([0u8; 32]).0.len());

  let mut entropy_transcript = {
    let entropy =
      Zeroizing::new(env::var("ENTROPY").expect("entropy wasn't provided as an env var"));
    if entropy.len() != 64 {
      panic!("entropy isn't the right length");
    }
    let bytes = Zeroizing::new(hex::decode(entropy).expect("entropy wasn't hex-formatted"));
    let mut entropy = Zeroizing::new([0; 32]);
    let entropy_mut: &mut [u8] = entropy.as_mut();
    entropy_mut.copy_from_slice(bytes.as_ref());

    let mut transcript = RecommendedTranscript::new(b"Serai Processor Entropy");
    transcript.append_message(b"entropy", entropy);
    transcript
  };

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
  let mut key_gen = KeyGen::<C, _>::new(raw_db.clone(), entropy(b"key-gen_entropy"));
  // The scanner has no long-standing orders to re-issue
  let (mut scanner, active_keys) = Scanner::new(coin.clone(), raw_db.clone());

  let mut schedulers = HashMap::<Vec<u8>, Scheduler<C>>::new();
  let mut substrate_signers = HashMap::new();
  let mut signers = HashMap::new();

  let mut main_db = MainDb::new(raw_db.clone());

  for key in &active_keys {
    // TODO: Load existing schedulers

    let (substrate_keys, coin_keys) = key_gen.keys(key);

    let substrate_key = substrate_keys.group_key();
    let substrate_signer = SubstrateSigner::new(raw_db.clone(), substrate_keys);
    // We don't have to load any state for this since the Scanner will re-fire any events
    // necessary
    substrate_signers.insert(substrate_key.to_bytes().to_vec(), substrate_signer);

    let mut signer = Signer::new(raw_db.clone(), coin.clone(), coin_keys);

    // Load any TXs being actively signed
    let key = key.to_bytes();
    for (block_number, plan) in main_db.signing(key.as_ref()) {
      let block_number = block_number.try_into().unwrap();

      let fee = get_fee(&coin, block_number).await;

      let id = plan.id();
      info!("reloading plan {}: {:?}", hex::encode(id), plan);

      let (Some((tx, eventuality)), _) =
        prepare_send(&coin, &signer, block_number, fee, plan).await else {
          panic!("previously created transaction is no longer being created")
        };

      scanner.register_eventuality(block_number, id, eventuality.clone()).await;
      // TODO: Reconsider if the Signer should have the eventuality, or if just the coin/scanner
      // should
      signer.sign_transaction(id, tx, eventuality).await;
    }

    signers.insert(key.as_ref().to_vec(), signer);
  }

  // We can't load this from the DB as we can't guarantee atomic increments with the ack function
  let mut last_coordinator_msg = None;

  loop {
    // Check if the signers have events
    // The signers will only have events after the following select executes, which will then
    // trigger the loop again, hence why having the code here with no timer is fine
    for (key, signer) in signers.iter_mut() {
      while let Some(msg) = signer.events.pop_front() {
        match msg {
          SignerEvent::ProcessorMessage(msg) => {
            coordinator.send(ProcessorMessage::Sign(msg)).await;
          }

          SignerEvent::SignedTransaction { id, tx } => {
            // If we die after calling finish_signing, we'll never fire Completed
            // TODO: Is that acceptable? Do we need to fire Completed before firing finish_signing?
            main_db.finish_signing(key, id);
            scanner.drop_eventuality(id).await;
            coordinator
              .send(ProcessorMessage::Sign(messages::sign::ProcessorMessage::Completed {
                key: key.clone(),
                id,
                tx: tx.as_ref().to_vec(),
              }))
              .await;

            // TODO
            // 1) We need to stop signing whenever a peer informs us or the chain has an
            //    eventuality
            // 2) If a peer informed us of an eventuality without an outbound payment, stop
            //    scanning the chain for it (or at least ack it's solely for sanity purposes?)
            // 3) When the chain has an eventuality, if it had an outbound payment, report it up to
            //    Substrate for logging purposes
          }
        }
      }
    }

    for (key, signer) in substrate_signers.iter_mut() {
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

        // If this message expects a higher block number than we have, halt until synced
        async fn wait<C: Coin, D: Db>(
          scanner: &ScannerHandle<C, D>,
          block_hash: &BlockHash
        ) {
          let mut needed_hash = <C::Block as Block<C>>::Id::default();
          needed_hash.as_mut().copy_from_slice(&block_hash.0);

          let block_number;
          loop {
            // Ensure our scanner has scanned this block, which means our daemon has this block at
            // a sufficient depth
            let Some(block_number_inner) = scanner.block_number(&needed_hash).await else {
              warn!(
                "node is desynced. we haven't scanned {} which should happen after {} confirms",
                hex::encode(&needed_hash),
                C::CONFIRMATIONS,
              );
              sleep(Duration::from_secs(10)).await;
              continue;
            };
            block_number = block_number_inner;
            break;
          }

          // While the scanner has cemented this block, that doesn't mean it's been scanned for all
          // keys
          // ram_scanned will return the lowest scanned block number out of all keys
          while scanner.ram_scanned().await < block_number {
            sleep(Duration::from_secs(1)).await;
          }

          // TODO: Sanity check we got an AckBlock (or this is the AckBlock) for the block in
          // question

          /*
          let synced = |context: &SubstrateContext, key| -> Result<(), ()> {
            // Check that we've synced this block and can actually operate on it ourselves
            let latest = scanner.latest_scanned(key);
            if usize::try_from(context.coin_latest_block_number).unwrap() < latest {
              log::warn!(
                "coin node disconnected/desynced from rest of the network. \
                our block: {latest:?}, network's acknowledged: {}",
                context.coin_latest_block_number
              );
              Err(())?;
            }
            Ok(())
          };
          */
        }

        if let Some(required) = msg.msg.required_block() {
          wait(&scanner, &required).await;
        }

        match msg.msg.clone() {
          CoordinatorMessage::KeyGen(msg) => {
            match key_gen.handle(msg).await {
              KeyGenEvent::KeyConfirmed { activation_block, substrate_keys, coin_keys } => {
                substrate_signers.insert(
                  substrate_keys.group_key().to_bytes().to_vec(),
                  SubstrateSigner::new(raw_db.clone(), substrate_keys),
                );

                let key = coin_keys.group_key();

                let mut activation_block_hash = <C::Block as Block<C>>::Id::default();
                activation_block_hash.as_mut().copy_from_slice(&activation_block.0);
                let activation_number =
                  scanner
                    .block_number(&activation_block_hash)
                    .await
                    .expect("KeyConfirmed from context we haven't synced");

                scanner.rotate_key(activation_number, key).await;
                schedulers.insert(key.to_bytes().as_ref().to_vec(), Scheduler::<C>::new(key));
                signers.insert(
                  key.to_bytes().as_ref().to_vec(),
                  Signer::new(raw_db.clone(), coin.clone(), coin_keys)
                );
              },

              // TODO: This may be fired multiple times. What's our plan for that?
              KeyGenEvent::ProcessorMessage(msg) => {
                coordinator.send(ProcessorMessage::KeyGen(msg)).await;
              },
            }
          },

          CoordinatorMessage::Sign(msg) => {
            signers.get_mut(msg.key()).unwrap().handle(msg).await;
          },

          CoordinatorMessage::Coordinator(msg) => {
            substrate_signers.get_mut(msg.key()).unwrap().handle(msg).await;
          },

          CoordinatorMessage::Substrate(msg) => {
            match msg {
              messages::substrate::CoordinatorMessage::SubstrateBlock {
                context,
                key: key_vec,
                burns,
              } => {
                let mut block_id = <C::Block as Block<C>>::Id::default();
                block_id.as_mut().copy_from_slice(&context.coin_latest_finalized_block.0);

                let key =
                  <C::Curve as Ciphersuite>::read_G::<&[u8]>(&mut key_vec.as_ref()).unwrap();

                // We now have to acknowledge every block for this key up to the acknowledged block
                let outputs = scanner.ack_up_to_block(key, block_id).await;

                let mut payments = vec![];
                for out in burns {
                  let OutInstructionWithBalance {
                    instruction: OutInstruction { address, data },
                    balance,
                  } = out;
                  if let Ok(address) = C::Address::try_from(address.consume()) {
                    payments.push(Payment {
                      address,
                      data: data.map(|data| data.consume()),
                      amount: balance.amount.0,
                    });
                  }
                }

                let plans = schedulers
                  .get_mut(&key_vec)
                  .expect("key we don't have a scheduler for acknowledged a block")
                  .schedule(outputs, payments);

                sign_plans(
                  &mut main_db,
                  &coin,
                  &scanner,
                  &mut schedulers,
                  &mut signers,
                  context,
                  plans
                ).await;
              }
            }
          }
        }

        coordinator.ack(msg).await;
      },

      msg = scanner.events.recv() => {
        match msg.unwrap() {
          ScannerEvent::Block { key, block, batch, outputs } => {
            let key = key.to_bytes().as_ref().to_vec();

            let mut block_hash = [0; 32];
            block_hash.copy_from_slice(block.as_ref());

            let batch = Batch {
              network: C::NETWORK,
              id: batch,
              block: BlockHash(block_hash),
              instructions: outputs.iter().filter_map(|output| {
                // If these aren't externally received funds, don't handle it as an instruction
                if output.kind() != OutputType::External {
                  return None;
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

                let shorthand = Shorthand::decode(&mut data).ok()?;
                let instruction = RefundableInInstruction::try_from(shorthand).ok()?;
                // TODO2: Set instruction.origin if not set (and handle refunds in general)
                Some(InInstructionWithBalance {
                  instruction: instruction.instruction,
                  balance: output.balance(),
                })
              }).collect()
            };

            substrate_signers.get_mut(&key).unwrap().sign(batch).await;
          },

          ScannerEvent::Completed(id, tx) => {
            // We don't know which signer had this plan, so inform all of them
            for (_, signer) in signers.iter_mut() {
              signer.eventuality_completion(id, &tx).await;
            }
          },
        }
      },
    }
  }
}

#[tokio::main]
async fn main() {
  let db = MemDb::new(); // TODO
  let coordinator = MemCoordinator::new(); // TODO
  let url = env::var("COIN_RPC").expect("coin rpc wasn't specified as an env var");
  match env::var("COIN").expect("coin wasn't specified as an env var").as_str() {
    #[cfg(feature = "bitcoin")]
    "bitcoin" => run(db, Bitcoin::new(url).await, coordinator).await,
    #[cfg(feature = "monero")]
    "monero" => run(db, Monero::new(url), coordinator).await,
    _ => panic!("unrecognized coin"),
  }
}
