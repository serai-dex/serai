use std::{
  env,
  pin::Pin,
  task::{Poll, Context},
  future::Future,
  time::{Duration, SystemTime},
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
  primitives::{Amount, WithAmount},
  tokens::primitives::OutInstruction,
  in_instructions::primitives::{Shorthand, RefundableInInstruction},
};

use messages::{SubstrateContext, substrate, CoordinatorMessage, ProcessorMessage};

mod db;
pub use db::*;

mod coordinator;
pub use coordinator::*;

mod coins;
use coins::{OutputType, Output, Block, Coin};
#[cfg(feature = "bitcoin")]
use coins::Bitcoin;
#[cfg(feature = "monero")]
use coins::Monero;

mod key_gen;
use key_gen::{KeyGenEvent, KeyGen};

mod signer;
use signer::{SignerOrder, SignerEvent, Signer, SignerHandle};

mod scanner;
use scanner::{ScannerEvent, Scanner, ScannerHandle};

mod scheduler;
use scheduler::Scheduler;

#[cfg(test)]
mod tests;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Payment<C: Coin> {
  address: C::Address,
  data: Option<Vec<u8>>,
  amount: u64,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Plan<C: Coin> {
  pub key: <C::Curve as Ciphersuite>::G,
  pub inputs: Vec<C::Output>,
  pub payments: Vec<Payment<C>>,
  pub change: Option<<C::Curve as Ciphersuite>::G>,
}

impl<C: Coin> Plan<C> {
  fn transcript(&self) -> RecommendedTranscript {
    let mut transcript = RecommendedTranscript::new(b"Serai Processor Plan ID");
    transcript.domain_separate(b"meta");
    transcript.append_message(b"key", self.key.to_bytes());

    transcript.domain_separate(b"inputs");
    for input in &self.inputs {
      transcript.append_message(b"input", input.id());
    }

    transcript.domain_separate(b"payments");
    for payment in &self.payments {
      transcript.append_message(b"address", payment.address.to_string().as_bytes());
      if let Some(data) = payment.data.as_ref() {
        transcript.append_message(b"data", data);
      }
      transcript.append_message(b"amount", payment.amount.to_le_bytes());
    }

    if let Some(change) = self.change {
      transcript.append_message(b"change", change.to_bytes());
    }

    transcript
  }

  fn id(&self) -> [u8; 32] {
    let challenge = self.transcript().challenge(b"id");
    let mut res = [0; 32];
    res.copy_from_slice(&challenge[.. 32]);
    res
  }
}

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

struct SignerMessageFuture<'a, C: Coin, D: Db>(&'a mut HashMap<Vec<u8>, SignerHandle<C, D>>);
impl<'a, C: Coin, D: Db> Future for SignerMessageFuture<'a, C, D> {
  type Output = (Vec<u8>, SignerEvent<C>);
  fn poll(mut self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Self::Output> {
    for (key, signer) in self.0.iter_mut() {
      match signer.events.poll_recv(ctx) {
        Poll::Ready(event) => return Poll::Ready((key.clone(), event.unwrap())),
        Poll::Pending => {}
      }
    }
    Poll::Pending
  }
}

async fn sign_plans<C: Coin, D: Db>(
  coin: &C,
  key_gen: &KeyGen<C, D>,
  schedulers: &mut HashMap<Vec<u8>, Scheduler<C>>,
  signers: &HashMap<Vec<u8>, SignerHandle<C, D>>,
  context: SubstrateContext,
  plans: Vec<Plan<C>>,
) {
  let mut plans = VecDeque::from(plans);
  let start = SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(context.time)).unwrap();
  let block_number = context.coin_latest_block_number.try_into().unwrap();

  let fee;
  loop {
    // TODO2: Use an fee representative of several blocks
    match coin.get_block(block_number).await {
      Ok(block) => {
        fee = block.median_fee();
        break;
      }
      Err(e) => {
        error!("couldn't get block {}: {e}", block_number);
        // Since this block is considered finalized, we shouldn't be unable to get it unless the
        // node is offline, hence the long sleep
        sleep(Duration::from_secs(60)).await;
      }
    }
  }

  while let Some(plan) = plans.pop_front() {
    let id = plan.id();
    info!("preparing plan {}: {:?}", hex::encode(id), plan);

    let keys = key_gen.keys(&plan.key);
    let tx;
    let branches;
    loop {
      match coin.prepare_send(keys.clone(), block_number, plan.clone(), fee).await {
        Ok(prepared) => {
          (tx, branches) = prepared;
          break;
        }
        Err(e) => {
          error!("couldn't prepare a send for plan {}: {e}", hex::encode(id));
          // The processor is either trying to create an invalid TX (fatal) or the node went
          // offline
          // The former requires a patch, the latter is a connection issue
          // If the latter, this is an appropriate sleep. If the former, we should panic, yet
          // this won't flood the console ad infinitum
          sleep(Duration::from_secs(60)).await;
        }
      }
    }

    let key = plan.key.to_bytes();
    for branch in branches {
      schedulers
        .get_mut(key.as_ref())
        .expect("didn't have a scheduler for a key we have a plan for")
        .created_output(branch.expected, branch.actual);
    }

    if let Some((tx, eventuality)) = tx {
      // TODO:
      // 1) Make this a function
      // 2) Have the signer save whatever it's actively signing for
      // 3) Have the signer load active signing sessions on boot
      // 4) Handle detection of already signed TXs (either on-chain or notified by a peer)
      signers[key.as_ref()]
        .orders
        .send(SignerOrder::SignTransaction { id, start, tx, eventuality })
        .unwrap()
    }
  }
}

async fn run<C: Coin, D: Db, Co: Coordinator>(db: D, coin: C, mut coordinator: Co) {
  let mut entropy_transcript = {
    let entropy =
      Zeroizing::new(env::var("ENTROPY").expect("entropy wasn't provided as an env var"));
    if entropy.len() != 64 {
      panic!("entropy isn't the right length");
    }
    let bytes = Zeroizing::new(hex::decode(entropy).expect("entropy wasn't hex-formatted"));
    let mut entropy = Zeroizing::new([0; 32]);
    entropy.as_mut().copy_from_slice(bytes.as_ref());

    let mut transcript = RecommendedTranscript::new(b"Serai Processor Entropy");
    transcript.append_message(b"entropy", entropy.as_ref());
    transcript
  };

  let mut entropy = |label| {
    let mut challenge = entropy_transcript.challenge(label);
    let mut res = Zeroizing::new([0; 32]);
    res.as_mut().copy_from_slice(&challenge[.. 32]);
    challenge.zeroize();
    res
  };

  // We don't need to re-issue GenerateKey orders because the coordinator is expected to
  // schedule/notify us of new attempts
  let mut key_gen = KeyGen::<C, _>::new(db.clone(), entropy(b"key-gen_entropy"));
  // The scanner has no long-standing orders to re-issue
  let (mut scanner, active_keys) = Scanner::new(coin.clone(), db.clone());

  let mut schedulers = HashMap::<Vec<u8>, Scheduler<C>>::new();
  let mut signers = HashMap::new();

  for key in &active_keys {
    // TODO: Load existing schedulers

    signers.insert(
      key.to_bytes().as_ref().to_vec(),
      Signer::new(db.clone(), coin.clone(), key_gen.keys(key)),
    );
  }

  // TODO: Should this be saved to the DB?
  let mut last_coordinator_msg = None;

  loop {
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
          coin: &C,
          scanner: &ScannerHandle<C, D>,
          context: &SubstrateContext
        ) {
          let needed = usize::try_from(context.coin_latest_block_number).unwrap();

          loop {
            let Ok(actual) = coin.get_latest_block_number().await else {
              error!("couldn't get the latest block number");
              // Sleep for a minute as node errors should be incredibly uncommon yet take multiple
              // seconds to resolve
              sleep(Duration::from_secs(60)).await;
              continue;
            };

            // Check our daemon has this block
            // CONFIRMATIONS - 1 since any block's TXs have one confirmation (the block itself)
            let confirmed = actual.saturating_sub(C::CONFIRMATIONS - 1);
            if needed > confirmed {
              // This may occur within some natural latency window
              warn!(
                "node is desynced. need block {}, have {}",
                // Print the block needed for the needed block to be confirmed
                needed + (C::CONFIRMATIONS - 1),
                actual,
              );
              // Sleep for one second per needed block
              // If the node is disconnected from the network, this will be faster than it should
              // be, yet presumably it just neeeds a moment to sync up
              sleep(Duration::from_secs((needed - confirmed).try_into().unwrap())).await;
            }

            // Check our scanner has scanned it
            // This check does void the need for the last one, yet it provides a bit better
            // debugging
            let ram_scanned = scanner.ram_scanned().await;
            if ram_scanned < needed {
              warn!("scanner is behind. need block {}, scanned up to {}", needed, ram_scanned);
              sleep(Duration::from_secs((needed - ram_scanned).try_into().unwrap())).await;
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

            break;
          }
        }

        match &msg.msg {
          CoordinatorMessage::KeyGen(_) => {},
          CoordinatorMessage::Sign(_) => {},
          CoordinatorMessage::Substrate(msg) => {
            match msg {
              substrate::CoordinatorMessage::BlockAcknowledged { context, .. } => {
                wait(&coin, &scanner, context).await;
              },
              substrate::CoordinatorMessage::Burns { context, .. } => {
                wait(&coin, &scanner, context).await;
              },
            }
          },
        }

        match msg.msg.clone() {
          CoordinatorMessage::KeyGen(msg) => {
            match key_gen.handle(msg).await {
              KeyGenEvent::KeyConfirmed { activation_number, keys } => {
                let key = keys.group_key();
                scanner.rotate_key(activation_number, key).await;
                schedulers.insert(key.to_bytes().as_ref().to_vec(), Scheduler::<C>::new(key));
                signers.insert(
                  keys.group_key().to_bytes().as_ref().to_vec(),
                  Signer::new(db.clone(), coin.clone(), keys)
                );
              },

              // TODO: This may be fired multiple times. What's our plan for that?
              KeyGenEvent::ProcessorMessage(msg) => {
                coordinator.send(ProcessorMessage::KeyGen(msg)).await;
              },
            }
          }

          CoordinatorMessage::Sign(msg) => {
            signers[msg.key()].handle(msg).await;
          }

          CoordinatorMessage::Substrate(msg) => {
            match msg {
              substrate::CoordinatorMessage::BlockAcknowledged { context, key: key_vec, block } => {
                let key =
                  <C::Curve as Ciphersuite>::read_G::<&[u8]>(&mut key_vec.as_ref()).unwrap();
                let mut block_id = <C::Block as Block<C>>::Id::default();
                block_id.as_mut().copy_from_slice(&block);

                let plans = schedulers
                  .get_mut(&key_vec)
                  .expect("key we don't have a scheduler for acknowledged a block")
                  .add_outputs(scanner.ack_block(key, block_id).await);
                sign_plans(&coin, &key_gen, &mut schedulers, &signers, context, plans).await;
              }

              substrate::CoordinatorMessage::Burns { context, burns } => {
                // TODO2: Rewrite rotation documentation
                let schedule_key = active_keys.last().expect("burn event despite no keys");
                let scheduler = schedulers.get_mut(schedule_key.to_bytes().as_ref()).unwrap();

                let mut payments = vec![];
                for out in burns.clone() {
                  let WithAmount { data: OutInstruction { address, data }, amount } = out;
                  if let Ok(address) = C::Address::try_from(address.consume()) {
                    payments.push(Payment {
                      address,
                      data: data.map(|data| data.consume()),
                      amount: amount.0,
                    });
                  }
                }

                let plans = scheduler.schedule(payments);
                sign_plans(&coin, &key_gen, &mut schedulers, &signers, context, plans).await;
              }
            }
          }
        }

        coordinator.ack(msg).await;
      },

      msg = scanner.events.recv() => {
        // These need to be sent to the coordinator which needs to check they aren't replayed
        // TODO
        match msg.unwrap() {
          ScannerEvent::Outputs(key, block, outputs) => {
            coordinator.send(ProcessorMessage::Substrate(substrate::ProcessorMessage::Update {
              key: key.to_bytes().as_ref().to_vec(),
              block: block.as_ref().to_vec(),
              instructions: outputs.iter().filter_map(|output| {
                // If these aren't externally received funds, don't handle it as an instruction
                if output.kind() != OutputType::External {
                  return None;
                }

                let shorthand = Shorthand::decode(&mut output.data()).ok()?;
                let instruction = RefundableInInstruction::try_from(shorthand).ok()?;
                // TODO2: Set instruction.origin if not set (and handle refunds in general)
                Some(WithAmount { data: instruction.instruction, amount: Amount(output.amount()) })
              }).collect(),
            })).await;
          },
        }
      },

      (key, msg) = SignerMessageFuture(&mut signers) => {
        match msg {
          SignerEvent::SignedTransaction { id, tx } => {
            // TODO
            // 1) No longer reload the plan on boot
            // 2) Communicate to other signers
            // 3) We need to stop signing whenever a peer informs us or the chain has an
            //    eventuality
            // 4) If a peer informed us of an eventuality without an outbound payment, stop
            //    scanning the chain (or at least ack it's solely for sanity purposes?)
            // 5) When the chain has an eventuality, if it had an outbound payment, report it up to
            //    Substrate for logging purposes
          },
          SignerEvent::ProcessorMessage(msg) => {
            coordinator.send(ProcessorMessage::Sign(msg)).await;
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
    "bitcoin" => run(db, Bitcoin::new(url), coordinator).await,
    #[cfg(feature = "monero")]
    "monero" => run(db, Monero::new(url), coordinator).await,
    _ => panic!("unrecognized coin"),
  }
}
