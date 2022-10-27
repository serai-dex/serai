use core::fmt::Debug;

use std::{
  sync::Arc,
  time::{UNIX_EPOCH, SystemTime, Instant, Duration},
  collections::HashMap,
};

use parity_scale_codec::{Encode, Decode};

use tokio::{
  task::{JoinHandle, yield_now},
  sync::{
    RwLock,
    mpsc::{self, error::TryRecvError},
  },
  time::sleep,
};

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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TendermintError<V: ValidatorId> {
  Malicious(V),
  Temporal,
}

/// A machine executing the Tendermint protocol.
pub struct TendermintMachine<N: Network> {
  network: Arc<RwLock<N>>,
  signer: Arc<N::SignatureScheme>,
  weights: Arc<N::Weights>,
  proposer: N::ValidatorId,

  number: BlockNumber,
  canonical_start_time: u64,
  start_time: Instant,
  personal_proposal: N::Block,

  queue: Vec<(
    bool,
    Message<N::ValidatorId, N::Block, <N::SignatureScheme as SignatureScheme>::Signature>,
  )>,

  log: MessageLog<N>,
  round: Round,
  end_time: HashMap<Round, Instant>,
  step: Step,

  locked: Option<(Round, <N::Block as Block>::Id)>,
  valid: Option<(Round, N::Block)>,

  timeouts: HashMap<Step, Instant>,
}

/// A handle to an asynchronous task, along with a channel to inform of it of messages received.
pub struct TendermintHandle<N: Network> {
  /// Channel to send messages received from the P2P layer.
  pub messages: mpsc::Sender<
    SignedMessage<N::ValidatorId, N::Block, <N::SignatureScheme as SignatureScheme>::Signature>,
  >,
  /// Handle for the asynchronous task executing the machine. The task will automatically exit
  /// when the channel is dropped.
  pub handle: JoinHandle<()>,
}

impl<N: Network + 'static> TendermintMachine<N> {
  // Get the canonical end time for a given round, represented as seconds since the epoch
  // While we have the Instant already in end_time, converting it to a SystemTime would be lossy,
  // potentially enough to cause a consensus failure. Independently tracking this variable ensures
  // that won't happen
  fn canonical_end_time(&self, round: Round) -> u64 {
    let mut time = self.canonical_start_time;
    for r in 0 .. u64::from(round.0 + 1) {
      time += (r + 1) * u64::from(N::BLOCK_TIME);
    }
    time
  }

  fn timeout(&self, step: Step) -> Instant {
    let mut round_time = Duration::from_secs(N::BLOCK_TIME.into());
    round_time *= self.round.0 + 1;
    let step_time = round_time / 3;

    let offset = match step {
      Step::Propose => step_time,
      Step::Prevote => step_time * 2,
      Step::Precommit => step_time * 3,
    };
    self.start_time + offset
  }

  fn broadcast(
    &mut self,
    data: Data<N::Block, <N::SignatureScheme as SignatureScheme>::Signature>,
  ) {
    let step = data.step();
    // 27, 33, 41, 46, 60, 64
    self.step = step;
    self.queue.push((
      true,
      Message { sender: self.proposer, number: self.number, round: self.round, data },
    ));
  }

  // 14-21
  fn round_propose(&mut self) -> bool {
    if self.weights.proposer(self.number, self.round) == self.proposer {
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

    self.number.0 += 1;
    self.canonical_start_time = self.canonical_end_time(end_round);
    self.start_time = round_end;
    self.personal_proposal = proposal;

    self.queue = self.queue.drain(..).filter(|msg| msg.1.number == self.number).collect();

    self.log = MessageLog::new(self.network.read().await.weights());
    self.end_time = HashMap::new();

    self.locked = None;
    self.valid = None;

    self.round(Round(0));
  }

  /// Create a new Tendermint machine, for the specified proposer, from the specified block, with
  /// the specified block as the one to propose next, returning a handle for the machine.
  #[allow(clippy::new_ret_no_self)]
  pub fn new(
    network: N,
    proposer: N::ValidatorId,
    start: (BlockNumber, u64),
    proposal: N::Block,
  ) -> TendermintHandle<N> {
    // Convert the start time to an instant
    // This is imprecise yet should be precise enough
    let start_time = {
      let instant_now = Instant::now();
      let sys_now = SystemTime::now();
      instant_now -
        sys_now
          .duration_since(UNIX_EPOCH + Duration::from_secs(start.1))
          .unwrap_or(Duration::ZERO)
    };

    let (msg_send, mut msg_recv) = mpsc::channel(100); // Backlog to accept. Currently arbitrary
    TendermintHandle {
      messages: msg_send,
      handle: tokio::spawn(async move {
        let signer = network.signature_scheme();
        let weights = network.weights();
        let network = Arc::new(RwLock::new(network));
        // 01-10
        let mut machine = TendermintMachine {
          network,
          signer,
          weights: weights.clone(),
          proposer,

          number: start.0,
          canonical_start_time: start.1,
          start_time,
          personal_proposal: proposal,

          queue: vec![],

          log: MessageLog::new(weights),
          round: Round(0),
          end_time: HashMap::new(),
          step: Step::Propose,

          locked: None,
          valid: None,

          timeouts: HashMap::new(),
        };
        machine.round(Round(0));

        loop {
          // Check if any timeouts have been triggered
          let now = Instant::now();
          let (t1, t2, t3) = {
            let ready = |step| machine.timeouts.get(&step).unwrap_or(&now) < &now;
            (ready(Step::Propose), ready(Step::Prevote), ready(Step::Precommit))
          };

          // Propose timeout
          if t1 && (machine.step == Step::Propose) {
            machine.broadcast(Data::Prevote(None));
          }

          // Prevote timeout
          if t2 && (machine.step == Step::Prevote) {
            machine.broadcast(Data::Precommit(None));
          }

          // Precommit timeout
          if t3 {
            machine.round(Round(machine.round.0.wrapping_add(1)));
          }

          // Drain the channel of messages
          let mut broken = false;
          loop {
            match msg_recv.try_recv() {
              Ok(msg) => {
                if !machine.signer.verify(msg.msg.sender, &msg.msg.encode(), &msg.sig) {
                  continue;
                }
                machine.queue.push((false, msg.msg));
              }
              Err(TryRecvError::Empty) => break,
              Err(TryRecvError::Disconnected) => broken = true,
            }
          }
          if broken {
            break;
          }

          // Handle the queue
          let mut queue = machine.queue.drain(..).collect::<Vec<_>>();
          for (broadcast, msg) in queue.drain(..) {
            let res = machine.message(msg.clone()).await;
            if res.is_err() && broadcast {
              panic!("honest node had invalid behavior");
            }

            match res {
              Ok(None) => (),
              Ok(Some(block)) => {
                let mut validators = vec![];
                let mut sigs = vec![];
                for (v, sig) in machine.log.precommitted.iter().filter_map(|(k, (id, sig))| {
                  Some((*k, sig.clone())).filter(|_| id == &block.id())
                }) {
                  validators.push(v);
                  sigs.push(sig);
                }

                let commit = Commit {
                  end_time: machine.canonical_end_time(msg.round),
                  validators,
                  signature: N::SignatureScheme::aggregate(&sigs),
                };
                debug_assert!(machine.network.read().await.verify_commit(block.id(), &commit));

                let proposal = machine.network.write().await.add_block(block, commit).await;
                machine.reset(msg.round, proposal).await;
              }
              Err(TendermintError::Malicious(validator)) => {
                machine.network.write().await.slash(validator).await;
              }
              Err(TendermintError::Temporal) => (),
            }

            if broadcast {
              let sig = machine.signer.sign(&msg.encode());
              machine.network.write().await.broadcast(SignedMessage { msg, sig }).await;
            }
          }

          yield_now().await;
        }
      }),
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
      if !self.signer.verify(
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
        if self
          .log
          .has_consensus(msg.round, Data::Precommit(Some((block.id(), self.signer.sign(&[])))))
        {
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
        let (valid, err) = match self.network.write().await.validate(block).await {
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
          match self.network.write().await.validate(block).await {
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
                .sign(&commit_msg(self.canonical_end_time(self.round), block.id().as_ref())),
            ))));
            return Ok(None);
          }
        }
      }
    }

    Ok(None)
  }
}
