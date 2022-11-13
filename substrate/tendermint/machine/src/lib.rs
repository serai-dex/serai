use core::fmt::Debug;

use std::{
  sync::Arc,
  time::{SystemTime, Instant, Duration},
  collections::VecDeque,
};

use parity_scale_codec::{Encode, Decode};

use futures::{
  FutureExt, StreamExt,
  future::{self, Fuse},
  channel::mpsc,
};
use tokio::time::sleep;

mod time;
use time::{sys_time, CanonicalInstant};

mod round;

mod block;
use block::BlockData;

pub(crate) mod message_log;

/// Traits and types of the external network being integrated with to provide consensus over.
pub mod ext;
use ext::*;

pub(crate) fn commit_msg(end_time: u64, id: &[u8]) -> Vec<u8> {
  [&end_time.to_le_bytes(), id].concat().to_vec()
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Encode, Decode)]
enum Step {
  Propose,
  Prevote,
  Precommit,
}

#[derive(Clone, Debug, Encode, Decode)]
enum Data<B: Block, S: Signature> {
  Proposal(Option<RoundNumber>, B),
  Prevote(Option<B::Id>),
  Precommit(Option<(B::Id, S)>),
}

impl<B: Block, S: Signature> PartialEq for Data<B, S> {
  fn eq(&self, other: &Data<B, S>) -> bool {
    match (self, other) {
      (Data::Proposal(r, b), Data::Proposal(r2, b2)) => (r == r2) && (b == b2),
      (Data::Prevote(i), Data::Prevote(i2)) => i == i2,
      (Data::Precommit(None), Data::Precommit(None)) => true,
      (Data::Precommit(Some((i, _))), Data::Precommit(Some((i2, _)))) => i == i2,
      _ => false,
    }
  }
}

impl<B: Block, S: Signature> Data<B, S> {
  fn step(&self) -> Step {
    match self {
      Data::Proposal(..) => Step::Propose,
      Data::Prevote(..) => Step::Prevote,
      Data::Precommit(..) => Step::Precommit,
    }
  }
}

#[derive(Clone, PartialEq, Debug, Encode, Decode)]
struct Message<V: ValidatorId, B: Block, S: Signature> {
  sender: V,

  number: BlockNumber,
  round: RoundNumber,

  data: Data<B, S>,
}

/// A signed Tendermint consensus message to be broadcast to the other validators.
#[derive(Clone, PartialEq, Debug, Encode, Decode)]
pub struct SignedMessage<V: ValidatorId, B: Block, S: Signature> {
  msg: Message<V, B, S>,
  sig: S,
}

impl<V: ValidatorId, B: Block, S: Signature> SignedMessage<V, B, S> {
  /// Number of the block this message is attempting to add to the chain.
  pub fn number(&self) -> BlockNumber {
    self.msg.number
  }

  #[must_use]
  pub fn verify_signature<Scheme: SignatureScheme<ValidatorId = V, Signature = S>>(
    &self,
    signer: &Scheme,
  ) -> bool {
    signer.verify(self.msg.sender, &self.msg.encode(), &self.sig)
  }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TendermintError<V: ValidatorId> {
  Malicious(V),
  Temporal,
}

// Type aliases to abstract over generic hell
pub(crate) type DataFor<N> =
  Data<<N as Network>::Block, <<N as Network>::SignatureScheme as SignatureScheme>::Signature>;
pub(crate) type MessageFor<N> = Message<
  <N as Network>::ValidatorId,
  <N as Network>::Block,
  <<N as Network>::SignatureScheme as SignatureScheme>::Signature,
>;
/// Type alias to the SignedMessage type for a given Network
pub type SignedMessageFor<N> = SignedMessage<
  <N as Network>::ValidatorId,
  <N as Network>::Block,
  <<N as Network>::SignatureScheme as SignatureScheme>::Signature,
>;

/// A machine executing the Tendermint protocol.
pub struct TendermintMachine<N: Network> {
  network: N,
  signer: <N::SignatureScheme as SignatureScheme>::Signer,
  validators: N::SignatureScheme,
  weights: Arc<N::Weights>,

  queue: VecDeque<MessageFor<N>>,
  msg_recv: mpsc::UnboundedReceiver<SignedMessageFor<N>>,
  step_recv: mpsc::UnboundedReceiver<(Commit<N::SignatureScheme>, N::Block)>,

  block: BlockData<N>,
}

pub type StepSender<N> =
  mpsc::UnboundedSender<(Commit<<N as Network>::SignatureScheme>, <N as Network>::Block)>;

pub type MessageSender<N> = mpsc::UnboundedSender<SignedMessageFor<N>>;

/// A Tendermint machine and its channel to receive messages from the gossip layer over.
pub struct TendermintHandle<N: Network> {
  /// Channel to trigger the machine to move to the next height.
  /// Takes in the the previous block's commit, along with the new proposal.
  pub step: StepSender<N>,
  /// Channel to send messages received from the P2P layer.
  pub messages: MessageSender<N>,
  /// Tendermint machine to be run on an asynchronous task.
  pub machine: TendermintMachine<N>,
}

impl<N: Network + 'static> TendermintMachine<N> {
  fn broadcast(&mut self, data: DataFor<N>) {
    if let Some(msg) = self.block.message(data) {
      self.queue.push_back(msg);
    }
  }

  // Start a new round. Returns true if we were the proposer
  fn round(&mut self, round: RoundNumber, time: Option<CanonicalInstant>) -> bool {
    if let Some(data) =
      self.block.new_round(round, self.weights.proposer(self.block.number, round), time)
    {
      self.broadcast(data);
      true
    } else {
      false
    }
  }

  // 53-54
  async fn reset(&mut self, end_round: RoundNumber, proposal: N::Block) {
    // Ensure we have the end time data for the last round
    self.block.populate_end_time(end_round);

    // Sleep until this round ends
    let round_end = self.block.end_time[&end_round];
    sleep(round_end.instant().saturating_duration_since(Instant::now())).await;

    // Clear our outbound message queue
    self.queue = VecDeque::new();

    // Create the new block
    self.block = BlockData::new(
      self.weights.clone(),
      BlockNumber(self.block.number.0 + 1),
      self.signer.validator_id().await,
      proposal,
    );

    // Start the first round
    self.round(RoundNumber(0), Some(round_end));
  }

  async fn reset_by_commit(&mut self, commit: Commit<N::SignatureScheme>, proposal: N::Block) {
    let mut round = self.block.round().number;
    // If this commit is for a round we don't have, jump up to it
    while self.block.end_time[&round].canonical() < commit.end_time {
      round.0 += 1;
      self.block.populate_end_time(round);
    }
    // If this commit is for a prior round, find it
    while self.block.end_time[&round].canonical() > commit.end_time {
      if round.0 == 0 {
        panic!("commit isn't for this machine's next block");
      }
      round.0 -= 1;
    }
    debug_assert_eq!(self.block.end_time[&round].canonical(), commit.end_time);

    self.reset(round, proposal).await;
  }

  async fn slash(&mut self, validator: N::ValidatorId) {
    if !self.block.slashes.contains(&validator) {
      self.block.slashes.insert(validator);
      self.network.slash(validator).await;
    }
  }

  /// Create a new Tendermint machine, from the specified point, with the specified block as the
  /// one to propose next. This will return a channel to send messages from the gossip layer and
  /// the machine itself. The machine should have `run` called from an asynchronous task.
  #[allow(clippy::new_ret_no_self)]
  pub async fn new(
    network: N,
    last: (BlockNumber, u64),
    proposal: N::Block,
  ) -> TendermintHandle<N> {
    let (msg_send, msg_recv) = mpsc::unbounded();
    let (step_send, step_recv) = mpsc::unbounded();
    TendermintHandle {
      step: step_send,
      messages: msg_send,
      machine: {
        let last_time = sys_time(last.1);
        // If the last block hasn't ended yet, sleep until it has
        sleep(last_time.duration_since(SystemTime::now()).unwrap_or(Duration::ZERO)).await;

        let signer = network.signer();
        let validators = network.signature_scheme();
        let weights = Arc::new(network.weights());
        let validator_id = signer.validator_id().await;
        // 01-10
        let mut machine = TendermintMachine {
          network,
          signer,
          validators,
          weights: weights.clone(),

          queue: VecDeque::new(),
          msg_recv,
          step_recv,

          block: BlockData::new(weights, BlockNumber(last.0 .0 + 1), validator_id, proposal),
        };

        // The end time of the last block is the start time for this one
        // The Commit explicitly contains the end time, so loading the last commit will provide
        // this. The only exception is for the genesis block, which doesn't have a commit
        // Using the genesis time in place will cause this block to be created immediately
        // after it, without the standard amount of separation (so their times will be
        // equivalent or minimally offset)
        // For callers wishing to avoid this, they should pass (0, GENESIS + N::block_time())
        machine.round(RoundNumber(0), Some(CanonicalInstant::new(last.1)));
        machine
      },
    }
  }

  pub async fn run(mut self) {
    loop {
      // Also create a future for if the queue has a message
      // Does not pop_front as if another message has higher priority, its future will be handled
      // instead in this loop, and the popped value would be dropped with the next iteration
      // While no other message has a higher priority right now, this is a safer practice
      let mut queue_future =
        if self.queue.is_empty() { Fuse::terminated() } else { future::ready(()).fuse() };

      if let Some((broadcast, msg)) = futures::select_biased! {
        // Handle a new height occuring externally (an external sync loop)
        // Has the highest priority as it makes all other futures here irrelevant
        msg = self.step_recv.next() => {
          if let Some((commit, proposal)) = msg {
            self.reset_by_commit(commit, proposal).await;
            None
          } else {
            break;
          }
        },

        // Handle our messages
        _ = queue_future => {
          Some((true, self.queue.pop_front().unwrap()))
        },

        // Handle any timeouts
        step = self.block.round().timeout_future().fuse() => {
          // Remove the timeout so it doesn't persist, always being the selected future due to bias
          // While this does enable the timeout to be entered again, the timeout setting code will
          // never attempt to add a timeout after its timeout has expired
          self.block.round_mut().timeouts.remove(&step);
          // Only run if it's still the step in question
          if self.block.round().step == step {
            match step {
              Step::Propose => {
                // Slash the validator for not proposing when they should've
                self.slash(
                  self.weights.proposer(self.block.number, self.block.round().number)
                ).await;
                self.broadcast(Data::Prevote(None));
              },
              Step::Prevote => self.broadcast(Data::Precommit(None)),
              Step::Precommit => {
                self.round(RoundNumber(self.block.round().number.0 + 1), None);
                continue;
              }
            }
          }
          None
        },

        // Handle any received messages
        msg = self.msg_recv.next() => {
          if let Some(msg) = msg {
            if !msg.verify_signature(&self.validators) {
              continue;
            }
            Some((false, msg.msg))
          } else {
            break;
          }
        }
      } {
        let res = self.message(msg.clone()).await;
        if res.is_err() && broadcast {
          panic!("honest node had invalid behavior");
        }

        match res {
          Ok(None) => (),
          Ok(Some(block)) => {
            let mut validators = vec![];
            let mut sigs = vec![];
            // Get all precommits for this round
            for (validator, msgs) in &self.block.log.log[&msg.round] {
              if let Some(Data::Precommit(Some((id, sig)))) = msgs.get(&Step::Precommit) {
                // If this precommit was for this block, include it
                if id == &block.id() {
                  validators.push(*validator);
                  sigs.push(sig.clone());
                }
              }
            }

            let commit = Commit {
              end_time: self.block.end_time[&msg.round].canonical(),
              validators,
              signature: N::SignatureScheme::aggregate(&sigs),
            };
            debug_assert!(self.network.verify_commit(block.id(), &commit));

            let proposal = self.network.add_block(block, commit).await;
            self.reset(msg.round, proposal).await;
          }
          Err(TendermintError::Malicious(validator)) => {
            self.slash(validator).await;
          }
          Err(TendermintError::Temporal) => (),
        }

        if broadcast {
          let sig = self.signer.sign(&msg.encode()).await;
          self.network.broadcast(SignedMessage { msg, sig }).await;
        }
      }
    }
  }

  // Returns Ok(true) if this was a Precommit which had its signature validated
  // Returns Ok(false) if the signature wasn't validated yet
  // Returns Err if the signature was invalid
  fn verify_precommit_signature(
    &self,
    sender: N::ValidatorId,
    round: RoundNumber,
    data: &DataFor<N>,
  ) -> Result<bool, TendermintError<N::ValidatorId>> {
    Ok(if let Data::Precommit(Some((id, sig))) = data {
      // Also verify the end_time of the commit
      // Only perform this verification if we already have the end_time
      // Else, there's a DoS where we receive a precommit for some round infinitely in the future
      // which forces to calculate every end time
      if let Some(end_time) = self.block.end_time.get(&round) {
        if !self.validators.verify(sender, &commit_msg(end_time.canonical(), id.as_ref()), sig) {
          Err(TendermintError::Malicious(sender))?;
        }
        true
      } else {
        false
      }
    } else {
      false
    })
  }

  async fn message(
    &mut self,
    msg: MessageFor<N>,
  ) -> Result<Option<N::Block>, TendermintError<N::ValidatorId>> {
    if msg.number != self.block.number {
      Err(TendermintError::Temporal)?;
    }

    // If this is a precommit, verify its signature
    self.verify_precommit_signature(msg.sender, msg.round, &msg.data)?;

    // Only let the proposer propose
    if matches!(msg.data, Data::Proposal(..)) &&
      (msg.sender != self.weights.proposer(msg.number, msg.round))
    {
      Err(TendermintError::Malicious(msg.sender))?;
    };

    if !self.block.log.log(msg.clone())? {
      return Ok(None);
    }

    // All functions, except for the finalizer and the jump, are locked to the current round

    // Run the finalizer to see if it applies
    // 49-52
    if matches!(msg.data, Data::Proposal(..)) || matches!(msg.data, Data::Precommit(_)) {
      let proposer = self.weights.proposer(self.block.number, msg.round);

      // Get the proposal
      if let Some(Data::Proposal(_, block)) = self.block.log.get(msg.round, proposer, Step::Propose)
      {
        // Check if it has gotten a sufficient amount of precommits
        // Use a junk signature since message equality disregards the signature
        if self.block.log.has_consensus(
          msg.round,
          Data::Precommit(Some((block.id(), self.signer.sign(&[]).await))),
        ) {
          return Ok(Some(block.clone()));
        }
      }
    }

    // Else, check if we need to jump ahead
    #[allow(clippy::comparison_chain)]
    if msg.round.0 < self.block.round().number.0 {
      // Prior round, disregard if not finalizing
      return Ok(None);
    } else if msg.round.0 > self.block.round().number.0 {
      // 55-56
      // Jump, enabling processing by the below code
      if self.block.log.round_participation(msg.round) > self.weights.fault_thresold() {
        // If this round already has precommit messages, verify their signatures
        let round_msgs = self.block.log.log[&msg.round].clone();
        for (validator, msgs) in &round_msgs {
          if let Some(data) = msgs.get(&Step::Precommit) {
            if let Ok(res) = self.verify_precommit_signature(*validator, msg.round, data) {
              // Ensure this actually verified the signature instead of believing it shouldn't yet
              debug_assert!(res);
            } else {
              // Remove the message so it isn't counted towards forming a commit/included in one
              // This won't remove the fact the precommitted for this block hash in the MessageLog
              self
                .block
                .log
                .log
                .get_mut(&msg.round)
                .unwrap()
                .get_mut(validator)
                .unwrap()
                .remove(&Step::Precommit);
              self.slash(*validator).await;
            }
          }
        }
        // If we're the proposer, return now so we re-run processing with our proposal
        // If we continue now, it'd just be wasted ops
        if self.round(msg.round, None) {
          return Ok(None);
        }
      } else {
        // Future round which we aren't ready to jump to, so return for now
        return Ok(None);
      }
    }

    // The paper executes these checks when the step is prevote. Making sure this message warrants
    // rerunning these checks is a sane optimization since message instances is a full iteration
    // of the round map
    if (self.block.round().step == Step::Prevote) && matches!(msg.data, Data::Prevote(_)) {
      let (participation, weight) =
        self.block.log.message_instances(self.block.round().number, Data::Prevote(None));
      // 34-35
      if participation >= self.weights.threshold() {
        self.block.round_mut().set_timeout(Step::Prevote);
      }

      // 44-46
      if weight >= self.weights.threshold() {
        self.broadcast(Data::Precommit(None));
        return Ok(None);
      }
    }

    // 47-48
    if matches!(msg.data, Data::Precommit(_)) &&
      self.block.log.has_participation(self.block.round().number, Step::Precommit)
    {
      self.block.round_mut().set_timeout(Step::Precommit);
    }

    let proposer = self.weights.proposer(self.block.number, self.block.round().number);
    if let Some(Data::Proposal(vr, block)) =
      self.block.log.get(self.block.round().number, proposer, Step::Propose)
    {
      // 22-33
      if self.block.round().step == Step::Propose {
        // Delay error handling (triggering a slash) until after we vote.
        let (valid, err) = match self.network.validate(block).await {
          Ok(_) => (true, Ok(None)),
          Err(BlockError::Temporal) => (false, Ok(None)),
          Err(BlockError::Fatal) => (false, Err(TendermintError::Malicious(proposer))),
        };
        // Create a raw vote which only requires block validity as a basis for the actual vote.
        let raw_vote = Some(block.id()).filter(|_| valid);

        // If locked is none, it has a round of -1 according to the protocol. That satisfies
        // 23 and 29. If it's some, both are satisfied if they're for the same ID. If it's some
        // with different IDs, the function on 22 rejects yet the function on 28 has one other
        // condition
        let locked = self.block.locked.as_ref().map(|(_, id)| id == &block.id()).unwrap_or(true);
        let mut vote = raw_vote.filter(|_| locked);

        if let Some(vr) = vr {
          // Malformed message
          if vr.0 >= self.block.round().number.0 {
            Err(TendermintError::Malicious(msg.sender))?;
          }

          if self.block.log.has_consensus(*vr, Data::Prevote(Some(block.id()))) {
            // Allow differing locked values if the proposal has a newer valid round
            // This is the other condition described above
            if let Some((locked_round, _)) = self.block.locked.as_ref() {
              vote = vote.or_else(|| raw_vote.filter(|_| locked_round.0 <= vr.0));
            }

            self.broadcast(Data::Prevote(vote));
            return err;
          }
        } else {
          self.broadcast(Data::Prevote(vote));
          return err;
        }
      } else if self
        .block
        .valid
        .as_ref()
        .map(|(round, _)| round != &self.block.round().number)
        .unwrap_or(true)
      {
        // 36-43

        // The run once condition is implemented above. Sinve valid will always be set, it not
        // being set, or only being set historically, means this has yet to be run

        if self.block.log.has_consensus(self.block.round().number, Data::Prevote(Some(block.id())))
        {
          match self.network.validate(block).await {
            Ok(_) => (),
            Err(BlockError::Temporal) => (),
            Err(BlockError::Fatal) => Err(TendermintError::Malicious(proposer))?,
          };

          self.block.valid = Some((self.block.round().number, block.clone()));
          if self.block.round().step == Step::Prevote {
            self.block.locked = Some((self.block.round().number, block.id()));
            self.broadcast(Data::Precommit(Some((
              block.id(),
              self
                .signer
                .sign(&commit_msg(
                  self.block.end_time[&self.block.round().number].canonical(),
                  block.id().as_ref(),
                ))
                .await,
            ))));
            return Ok(None);
          }
        }
      }
    }

    Ok(None)
  }
}
