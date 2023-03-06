use core::fmt::Debug;
use std::{
  env,
  pin::Pin,
  sync::{Arc, RwLock},
  task::{Poll, Context},
  future::Future,
  time::{Duration, SystemTime, Instant},
  collections::{VecDeque, HashMap},
};

use zeroize::{Zeroize, Zeroizing};

use transcript::{Transcript, RecommendedTranscript};
use group::GroupEncoding;
use frost::curve::Ciphersuite;

use log::{info, error};
use tokio::time::sleep_until;

use scale::Decode;

use serai_client::{
  primitives::{Amount, WithAmount},
  tokens::primitives::OutInstruction,
  in_instructions::primitives::{Shorthand, RefundableInInstruction},
};

use messages::{SubstrateContext, substrate, CoordinatorMessage, ProcessorMessage};

mod coins;
use coins::{OutputType, Output, Block, Coin};
#[cfg(feature = "bitcoin")]
use coins::Bitcoin;
#[cfg(feature = "monero")]
use coins::Monero;

mod key_gen;
use key_gen::{KeyGenOrder, KeyGenEvent, KeyGen, KeyGenHandle};

mod signer;
use signer::{SignerOrder, SignerEvent, Signer, SignerHandle};

mod scanner;
use scanner::{ScannerOrder, ScannerEvent, Scanner, ScannerHandle};

mod scheduler;
use scheduler::Scheduler;

#[cfg(test)]
mod tests;

pub trait DbTxn: Send + Sync + Clone + Debug {
  fn put(&mut self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>);
  fn get(&self, key: impl AsRef<[u8]>) -> Option<Vec<u8>>;
  fn del(&mut self, key: impl AsRef<[u8]>);
  fn commit(self);
}

pub trait Db: 'static + Send + Sync + Clone + Debug {
  type Transaction: DbTxn;
  fn key(db_dst: &'static [u8], item_dst: &'static [u8], key: impl AsRef<[u8]>) -> Vec<u8> {
    let db_len = u8::try_from(db_dst.len()).unwrap();
    let dst_len = u8::try_from(item_dst.len()).unwrap();
    [[db_len].as_ref(), db_dst, [dst_len].as_ref(), item_dst, key.as_ref()].concat().to_vec()
  }
  fn txn(&mut self) -> Self::Transaction;
  fn get(&self, key: impl AsRef<[u8]>) -> Option<Vec<u8>>;
}

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

// TODO: Replace this with RocksDB
#[derive(Clone, Debug)]
struct MemDb(Arc<RwLock<HashMap<Vec<u8>, Vec<u8>>>>);
impl MemDb {
  pub(crate) fn new() -> MemDb {
    MemDb(Arc::new(RwLock::new(HashMap::new())))
  }
}
impl Default for MemDb {
  fn default() -> MemDb {
    MemDb::new()
  }
}

impl DbTxn for MemDb {
  fn put(&mut self, key: impl AsRef<[u8]>, value: impl AsRef<[u8]>) {
    self.0.write().unwrap().insert(key.as_ref().to_vec(), value.as_ref().to_vec());
  }
  fn get(&self, key: impl AsRef<[u8]>) -> Option<Vec<u8>> {
    self.0.read().unwrap().get(key.as_ref()).cloned()
  }
  fn del(&mut self, key: impl AsRef<[u8]>) {
    self.0.write().unwrap().remove(key.as_ref());
  }
  fn commit(self) {}
}

impl Db for MemDb {
  type Transaction = MemDb;
  fn txn(&mut self) -> MemDb {
    Self(self.0.clone())
  }
  fn get(&self, key: impl AsRef<[u8]>) -> Option<Vec<u8>> {
    self.0.read().unwrap().get(key.as_ref()).cloned()
  }
}

struct SignerMessageFuture<'a, C: Coin>(&'a mut HashMap<Vec<u8>, SignerHandle<C>>);
impl<'a, C: Coin> Future for SignerMessageFuture<'a, C> {
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
  key_gen: &KeyGenHandle<C, D>,
  schedulers: &mut HashMap<Vec<u8>, Scheduler<C>>,
  signers: &HashMap<Vec<u8>, SignerHandle<C>>,
  plans: &mut VecDeque<(SubstrateContext, VecDeque<Plan<C>>)>,
  timer: &mut Option<Instant>,
) {
  // Clear the timer
  *timer = None;

  // Iterate over all plans
  while let Some((context, mut these_plans)) = plans.pop_front() {
    let start = SystemTime::UNIX_EPOCH.checked_add(Duration::from_secs(context.time)).unwrap();
    let block_number = context.coin_latest_block_number.try_into().unwrap();

    while let Some(plan) = these_plans.pop_front() {
      let id = plan.id();
      info!("preparing plan {}: {:?}", hex::encode(id), plan);

      let prepare_plan = |keys| async {
        // TODO2: Use an fee representative of several blocks
        let fee = coin.get_block(block_number).await?.median_fee();
        coin.prepare_send(keys, block_number, plan.clone(), fee).await
      };

      match prepare_plan(key_gen.keys(&plan.key)).await {
        Ok((tx, branches)) => {
          let key = plan.key.to_bytes();
          for branch in branches {
            schedulers
              .get_mut(key.as_ref())
              .expect("didn't have a scheduler for a key we have a plan for")
              .created_output(branch.expected, branch.actual);
          }

          if let Some((tx, eventuality)) = tx {
            signers[key.as_ref()]
              .orders
              .send(SignerOrder::SignTransaction { id, start, tx, eventuality })
              .unwrap()
          }
        }

        Err(e) => {
          error!("couldn't prepare a send for plan {}: {e}", hex::encode(id));
          // Add back this plan/these plans
          these_plans.push_front(plan);
          plans.push_front((context, these_plans));
          // Try again in 30 seconds
          *timer = Some(Instant::now().checked_add(Duration::from_secs(30)).unwrap());
          return;
        }
      }
    }
  }
}

// These messages require a sufficiently synced coin node
#[allow(clippy::too_many_arguments)]
async fn handle_substrate_message<C: Coin, D: Db>(
  coin: &C,
  key_gen: &KeyGenHandle<C, D>,
  scanner: &ScannerHandle<C, D>,
  schedulers: &mut HashMap<Vec<u8>, Scheduler<C>>,
  signers: &HashMap<Vec<u8>, SignerHandle<C>>,
  active_keys: &[<C::Curve as Ciphersuite>::G],
  plans: &mut VecDeque<(SubstrateContext, VecDeque<Plan<C>>)>,
  plans_timer: &mut Option<Instant>,
  msg: &substrate::CoordinatorMessage,
) -> Result<(), ()> {
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

  match msg {
    substrate::CoordinatorMessage::BlockAcknowledged { context, key: key_vec, block } => {
      let key = <C::Curve as Ciphersuite>::read_G::<&[u8]>(&mut key_vec.as_ref()).unwrap();
      synced(context, key)?;
      let mut block_id = <C::Block as Block<C>>::Id::default();
      block_id.as_mut().copy_from_slice(block);

      scanner.orders.send(ScannerOrder::AckBlock(key, block_id.clone())).unwrap();

      plans.push_back((
        *context,
        VecDeque::from(
          schedulers
            .get_mut(key_vec)
            .expect("key we don't have a scheduler for acknowledged a block")
            .add_outputs(scanner.outputs(&key, &block_id)),
        ),
      ));
      sign_plans(coin, key_gen, schedulers, signers, plans, plans_timer).await;
    }

    substrate::CoordinatorMessage::Burns { context, burns } => {
      // TODO2: Rewrite rotation documentation
      let schedule_key = active_keys.last().expect("burn event despite no keys");
      synced(context, *schedule_key)?;
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

      plans.push_back((*context, VecDeque::from(scheduler.schedule(payments))));
      sign_plans(coin, key_gen, schedulers, signers, plans, plans_timer).await;
    }
  }

  Ok(())
}

async fn run<C: Coin, D: Db>(db: D, coin: C) {
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

  let mut key_gen = KeyGen::<C, _>::new(db.clone(), entropy(b"key-gen_entropy"));
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

  let track_key = |schedulers: &mut HashMap<_, _>, activation_number, key| {
    scanner.orders.send(ScannerOrder::RotateKey { activation_number, key }).unwrap();
    schedulers.insert(key.to_bytes().as_ref().to_vec(), Scheduler::<C>::new(key));
  };

  let (to_coordinator, _fake_coordinator_recv) =
    tokio::sync::mpsc::unbounded_channel::<ProcessorMessage>();
  let (_fake_coordinator_send, mut from_coordinator) =
    tokio::sync::mpsc::unbounded_channel::<CoordinatorMessage>();

  // TODO: Reload these/re-issue any orders
  let mut substrate_messages = vec![];
  let mut substrate_timer = None;

  // TODO: Reload plans/re-issue SignTransaction orders
  let mut plans = VecDeque::new();
  let mut plans_timer = None;

  loop {
    // This should be long enough a timer using this shouldn't trigger unless it's actually set
    let minutes = Instant::now().checked_add(Duration::from_secs(365 * 24 * 60 * 60)).unwrap();
    let this_plans_timer = plans_timer.unwrap_or(minutes);
    let this_substrate_timer = substrate_timer.unwrap_or(minutes);

    tokio::select! {
      _ = sleep_until(this_substrate_timer.into()) => {
        let msg = substrate_messages.pop().expect("went a year with no events in the main loop");
        if handle_substrate_message(
          &coin,
          &key_gen,
          &scanner,
          &mut schedulers,
          &signers,
          &active_keys,
          &mut plans,
          &mut plans_timer,
          &msg,
        ).await.is_err() {
          // Push the message back, reset the timer
          substrate_messages.push(msg);
          substrate_timer = Some(Instant::now().checked_add(Duration::from_secs(30)).unwrap())
        }
      },
      _ = sleep_until(this_plans_timer.into()) => {
        sign_plans(&coin, &key_gen, &mut schedulers, &signers, &mut plans, &mut plans_timer).await;
      },

      msg = from_coordinator.recv() => {
        match msg.expect("Coordinator channel was dropped. Shutting down?") {
          CoordinatorMessage::KeyGen(msg) => {
            key_gen.orders.send(KeyGenOrder::CoordinatorMessage(msg)).unwrap()
          }
          CoordinatorMessage::Sign(msg) => {
            signers[msg.key()].orders.send(SignerOrder::CoordinatorMessage(msg)).unwrap()
          }
          CoordinatorMessage::Substrate(msg) => {
            substrate_messages.push(msg);
          }
        }
      },

      msg = key_gen.events.recv() => {
        match msg.unwrap() {
          KeyGenEvent::KeyConfirmed { activation_number, keys } => {
            track_key(&mut schedulers, activation_number, keys.group_key());
            signers.insert(
              keys.group_key().to_bytes().as_ref().to_vec(),
              Signer::new(db.clone(), coin.clone(), keys)
            );
          },
          KeyGenEvent::ProcessorMessage(msg) => {
            to_coordinator.send(ProcessorMessage::KeyGen(msg)).unwrap();
          },
        }
      },

      msg = scanner.events.recv() => {
        // These need to be sent to the coordinator which needs to check they aren't replayed
        // TODO
        match msg.unwrap() {
          ScannerEvent::Outputs(key, block, outputs) => {
            to_coordinator.send(ProcessorMessage::Substrate(substrate::ProcessorMessage::Update {
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
            })).unwrap();
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
            to_coordinator.send(ProcessorMessage::Sign(msg)).unwrap();
          },
        }
      },
    }
  }
}

#[tokio::main]
async fn main() {
  let db = MemDb::new(); // TODO
  let url = env::var("COIN_RPC").expect("coin rpc wasn't specified as an env var");
  match env::var("COIN").expect("coin wasn't specified as an env var").as_str() {
    #[cfg(feature = "bitcoin")]
    "bitcoin" => run(db, Bitcoin::new(url)).await,
    #[cfg(feature = "monero")]
    "monero" => run(db, Monero::new(url)).await,
    _ => panic!("unrecognized coin"),
  }
}
