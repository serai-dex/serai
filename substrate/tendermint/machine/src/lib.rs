use core::fmt::Debug;

use std::{
  sync::Arc,
  time::{UNIX_EPOCH, SystemTime, Instant, Duration},
  collections::{VecDeque, HashSet, HashMap},
};

use parity_scale_codec::{Encode, Decode};

use futures::{
  FutureExt, StreamExt,
  future::{self, Fuse},
  channel::mpsc,
};
use tokio::time::sleep;

/// Traits and types of the external network being integrated with to provide consensus over.
pub mod ext;
use ext::*;

mod message_log;
use message_log::MessageLog;

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
  Proposal(Option<Round>, B),
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
  round: Round,

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

/// A machine executing the Tendermint protocol.
pub struct TendermintMachine<N: Network> {
  network: N,
  signer: <N::SignatureScheme as SignatureScheme>::Signer,
  validators: N::SignatureScheme,
  weights: Arc<N::Weights>,

  validator_id: N::ValidatorId,

  number: BlockNumber,
  canonical_start_time: u64,
  start_time: Instant,
  personal_proposal: N::Block,

  queue:
    VecDeque<Message<N::ValidatorId, N::Block, <N::SignatureScheme as SignatureScheme>::Signature>>,
  msg_recv: mpsc::UnboundedReceiver<
    SignedMessage<N::ValidatorId, N::Block, <N::SignatureScheme as SignatureScheme>::Signature>,
  >,

  log: MessageLog<N>,
  slashes: HashSet<N::ValidatorId>,
  round: Round,
  end_time: HashMap<Round, Instant>,
  step: Step,

  locked: Option<(Round, <N::Block as Block>::Id)>,
  valid: Option<(Round, N::Block)>,

  timeouts: HashMap<Step, Instant>,
}

pub type MessageSender<N> = mpsc::UnboundedSender<
  SignedMessage<
    <N as Network>::ValidatorId,
    <N as Network>::Block,
    <<N as Network>::SignatureScheme as SignatureScheme>::Signature,
  >,
>;

/// A Tendermint machine and its channel to receive messages from the gossip layer over.
pub struct TendermintHandle<N: Network> {
  /// Channel to send messages received from the P2P layer.
  pub messages: MessageSender<N>,
  /// Tendermint machine to be run on an asynchronous task.
  pub machine: TendermintMachine<N>,
}

impl<N: Network + 'static> TendermintMachine<N> {
  // Get the canonical end time for a given round, represented as seconds since the epoch
  // While we have the Instant already in end_time, converting it to a SystemTime would be lossy,
  // potentially enough to cause a consensus failure. Independently tracking this variable ensures
  // that won't happen
  fn canonical_end_time(&self, round: Round) -> u64 {
    let mut time = self.canonical_start_time;
    for r in 0 .. u64::from(round.0 + 1) {
      time += (r + 1) * u64::from(N::block_time());
    }
    time
  }

  fn timeout(&self, step: Step) -> Instant {
    let adjusted_block = N::BLOCK_PROCESSING_TIME * (self.round.0 + 1);
    let adjusted_latency = N::LATENCY_TIME * (self.round.0 + 1);
    let offset = Duration::from_secs(
      (match step {
        Step::Propose => adjusted_block + adjusted_latency,
        Step::Prevote => adjusted_block + (2 * adjusted_latency),
        Step::Precommit => adjusted_block + (3 * adjusted_latency),
      })
      .into(),
    );
    self.start_time + offset
  }

  fn broadcast(
    &mut self,
    data: Data<N::Block, <N::SignatureScheme as SignatureScheme>::Signature>,
  ) {
    let step = data.step();
    // 27, 33, 41, 46, 60, 64
    self.step = step;
    self.queue.push_back(Message {
      sender: self.validator_id,
      number: self.number,
      round: self.round,
      data,
    });
  }

  // 14-21
  fn round_propose(&mut self) -> bool {
    if self.weights.proposer(self.number, self.round) == self.validator_id {
      let (round, block) = self
        .valid
        .clone()
        .map(|(r, b)| (Some(r), b))
        .unwrap_or((None, self.personal_proposal.clone()));
      self.broadcast(Data::Proposal(round, block));
      true
    } else {
      self.timeouts.insert(Step::Propose, self.timeout(Step::Propose));
      false
    }
  }

  fn round(&mut self, round: Round) -> bool {
    // Correct the start time
    for r in self.round.0 .. round.0 {
      let end = self.timeout(Step::Precommit);
      self.end_time.insert(Round(r), end);
      self.start_time = end;
    }

    // 11-13
    // Clear timeouts
    self.timeouts = HashMap::new();

    self.round = round;
    self.end_time.insert(round, self.timeout(Step::Precommit));
    self.step = Step::Propose;
    self.round_propose()
  }

  // 53-54
  async fn reset(&mut self, end_round: Round, proposal: N::Block) {
    // Wait for the next block interval
    let round_end = self.end_time[&end_round];
    sleep(round_end.saturating_duration_since(Instant::now())).await;

    self.validator_id = self.signer.validator_id().await;

    self.number.0 += 1;
    self.canonical_start_time = self.canonical_end_time(end_round);
    self.start_time = round_end;
    self.personal_proposal = proposal;

    self.queue = self.queue.drain(..).filter(|msg| msg.number == self.number).collect();

    self.log = MessageLog::new(self.weights.clone());
    self.slashes = HashSet::new();
    self.end_time = HashMap::new();

    self.locked = None;
    self.valid = None;

    self.round(Round(0));
  }

  async fn slash(&mut self, validator: N::ValidatorId) {
    if !self.slashes.contains(&validator) {
      self.slashes.insert(validator);
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
    TendermintHandle {
      messages: msg_send,
      machine: {
        let last_end = UNIX_EPOCH + Duration::from_secs(last.1);

        // If the last block hasn't ended yet, sleep until it has
        {
          let now = SystemTime::now();
          if last_end > now {
            sleep(last_end.duration_since(now).unwrap_or(Duration::ZERO)).await;
          }
        }

        // Convert the last time to an instant
        // This is imprecise yet should be precise enough, given this library only has
        // second accuracy
        let last_time = {
          let instant_now = Instant::now();
          let sys_now = SystemTime::now();
          instant_now - sys_now.duration_since(last_end).unwrap_or(Duration::ZERO)
        };

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

          validator_id,

          number: BlockNumber(last.0 .0 + 1),
          canonical_start_time: last.1,
          // The end time of the last block is the start time for this one
          // The Commit explicitly contains the end time, so loading the last commit will provide
          // this. The only exception is for the genesis block, which doesn't have a commit
          // Using the genesis time in place will cause this block to be created immediately
          // after it, without the standard amount of separation (so their times will be
          // equivalent or minimally offset)
          // For callers wishing to avoid this, they should pass (0, GENESIS + N::block_time())
          start_time: last_time,
          personal_proposal: proposal,

          queue: VecDeque::new(),
          msg_recv,

          log: MessageLog::new(weights),
          slashes: HashSet::new(),
          round: Round(0),
          end_time: HashMap::new(),
          step: Step::Propose,

          locked: None,
          valid: None,

          timeouts: HashMap::new(),
        };
        machine.round(Round(0));
        machine
      },
    }
  }

  pub async fn run(mut self) {
    self.round(Round(0));

    loop {
      // Create futures for the various timeouts
      let timeout_future = |step| {
        let timeout = self.timeouts.get(&step).copied();
        (async move {
          if let Some(timeout) = timeout {
            sleep(timeout.saturating_duration_since(Instant::now())).await
          } else {
            future::pending::<()>().await
          }
        })
        .fuse()
      };
      let propose_timeout = timeout_future(Step::Propose);
      let prevote_timeout = timeout_future(Step::Prevote);
      let precommit_timeout = timeout_future(Step::Precommit);
      futures::pin_mut!(propose_timeout, prevote_timeout, precommit_timeout);

      // Also create a future for if the queue has a message
      // Does not pop_front as if another message has higher priority, its future will be handled
      // instead in this loop, and the popped value would be dropped with the next iteration
      // While no other message has a higher priority right now, this is a safer practice
      let mut queue_future =
        if self.queue.is_empty() { Fuse::terminated() } else { future::ready(()).fuse() };

      if let Some((broadcast, msg)) = futures::select_biased! {
        // Handle our messages
        _ = queue_future => {
          Some((true, self.queue.pop_front().unwrap()))
        },

        // Handle any timeouts
        _ = &mut propose_timeout => {
          // Remove the timeout so it doesn't persist, always being the selected future due to bias
          // While this does enable the below get_entry calls to enter timeouts again, they'll
          // never attempt to add a timeout after this timeout has expired
          self.timeouts.remove(&Step::Propose);
          if self.step == Step::Propose {
            // Slash the validator for not proposing when they should've
            self.slash(self.weights.proposer(self.number, self.round)).await;
            self.broadcast(Data::Prevote(None));
          }
          None
        },
        _ = &mut prevote_timeout => {
          self.timeouts.remove(&Step::Prevote);
          if self.step == Step::Prevote {
            self.broadcast(Data::Precommit(None));
          }
          None
        },
        _ = &mut precommit_timeout => {
          // Technically unnecessary since round() will clear the timeouts
          self.timeouts.remove(&Step::Precommit);
          self.round(Round(self.round.0.wrapping_add(1)));
          continue;
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
            for (v, sig) in self
              .log
              .precommitted
              .iter()
              .filter_map(|(k, (id, sig))| Some((*k, sig.clone())).filter(|_| id == &block.id()))
            {
              validators.push(v);
              sigs.push(sig);
            }

            let commit = Commit {
              end_time: self.canonical_end_time(msg.round),
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

  async fn message(
    &mut self,
    msg: Message<N::ValidatorId, N::Block, <N::SignatureScheme as SignatureScheme>::Signature>,
  ) -> Result<Option<N::Block>, TendermintError<N::ValidatorId>> {
    if msg.number != self.number {
      Err(TendermintError::Temporal)?;
    }

    // Verify the end time and signature if this is a precommit
    if let Data::Precommit(Some((id, sig))) = &msg.data {
      if !self.validators.verify(
        msg.sender,
        &commit_msg(self.canonical_end_time(msg.round), id.as_ref()),
        sig,
      ) {
        // Since we verified this validator actually sent the message, they're malicious
        Err(TendermintError::Malicious(msg.sender))?;
      }
    }

    // Only let the proposer propose
    if matches!(msg.data, Data::Proposal(..)) &&
      (msg.sender != self.weights.proposer(msg.number, msg.round))
    {
      Err(TendermintError::Malicious(msg.sender))?;
    };

    if !self.log.log(msg.clone())? {
      return Ok(None);
    }

    // All functions, except for the finalizer and the jump, are locked to the current round

    // Run the finalizer to see if it applies
    // 49-52
    if matches!(msg.data, Data::Proposal(..)) || matches!(msg.data, Data::Precommit(_)) {
      let proposer = self.weights.proposer(self.number, msg.round);

      // Get the proposal
      if let Some(Data::Proposal(_, block)) = self.log.get(msg.round, proposer, Step::Propose) {
        // Check if it has gotten a sufficient amount of precommits
        // Use a junk signature since message equality disregards the signature
        if self.log.has_consensus(
          msg.round,
          Data::Precommit(Some((block.id(), self.signer.sign(&[]).await))),
        ) {
          return Ok(Some(block.clone()));
        }
      }
    }

    // Else, check if we need to jump ahead
    #[allow(clippy::comparison_chain)]
    if msg.round.0 < self.round.0 {
      // Prior round, disregard if not finalizing
      return Ok(None);
    } else if msg.round.0 > self.round.0 {
      // 55-56
      // Jump, enabling processing by the below code
      if self.log.round_participation(self.round) > self.weights.fault_thresold() {
        // If we're the proposer, return to avoid a double process
        if self.round(msg.round) {
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
    if (self.step == Step::Prevote) && matches!(msg.data, Data::Prevote(_)) {
      let (participation, weight) = self.log.message_instances(self.round, Data::Prevote(None));
      // 34-35
      if participation >= self.weights.threshold() {
        let timeout = self.timeout(Step::Prevote);
        self.timeouts.entry(Step::Prevote).or_insert(timeout);
      }

      // 44-46
      if weight >= self.weights.threshold() {
        self.broadcast(Data::Precommit(None));
        return Ok(None);
      }
    }

    // 47-48
    if matches!(msg.data, Data::Precommit(_)) &&
      self.log.has_participation(self.round, Step::Precommit)
    {
      let timeout = self.timeout(Step::Precommit);
      self.timeouts.entry(Step::Precommit).or_insert(timeout);
    }

    let proposer = self.weights.proposer(self.number, self.round);
    if let Some(Data::Proposal(vr, block)) = self.log.get(self.round, proposer, Step::Propose) {
      // 22-33
      if self.step == Step::Propose {
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
        let locked = self.locked.as_ref().map(|(_, id)| id == &block.id()).unwrap_or(true);
        let mut vote = raw_vote.filter(|_| locked);

        if let Some(vr) = vr {
          // Malformed message
          if vr.0 >= self.round.0 {
            Err(TendermintError::Malicious(msg.sender))?;
          }

          if self.log.has_consensus(*vr, Data::Prevote(Some(block.id()))) {
            // Allow differing locked values if the proposal has a newer valid round
            // This is the other condition described above
            if let Some((locked_round, _)) = self.locked.as_ref() {
              vote = vote.or_else(|| raw_vote.filter(|_| locked_round.0 <= vr.0));
            }

            self.broadcast(Data::Prevote(vote));
            return err;
          }
        } else {
          self.broadcast(Data::Prevote(vote));
          return err;
        }
      } else if self.valid.as_ref().map(|(round, _)| round != &self.round).unwrap_or(true) {
        // 36-43

        // The run once condition is implemented above. Sinve valid will always be set, it not
        // being set, or only being set historically, means this has yet to be run

        if self.log.has_consensus(self.round, Data::Prevote(Some(block.id()))) {
          match self.network.validate(block).await {
            Ok(_) => (),
            Err(BlockError::Temporal) => (),
            Err(BlockError::Fatal) => Err(TendermintError::Malicious(proposer))?,
          };

          self.valid = Some((self.round, block.clone()));
          if self.step == Step::Prevote {
            self.locked = Some((self.round, block.id()));
            self.broadcast(Data::Precommit(Some((
              block.id(),
              self
                .signer
                .sign(&commit_msg(self.canonical_end_time(self.round), block.id().as_ref()))
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
