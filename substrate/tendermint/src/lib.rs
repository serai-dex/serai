use core::fmt::Debug;

use std::{
  sync::Arc,
  time::{Instant, Duration},
  collections::HashMap,
};

use parity_scale_codec::{Encode, Decode};

use tokio::{
  task::{JoinHandle, yield_now},
  sync::{
    RwLock,
    mpsc::{self, error::TryRecvError},
  },
};

/// Traits and types of the external network being integrated with to provide consensus over.
pub mod ext;
use ext::*;

mod message_log;
use message_log::MessageLog;

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
  start_time: Instant,
  personal_proposal: N::Block,

  log: MessageLog<N>,
  round: Round,
  step: Step,

  locked: Option<(Round, N::Block)>,
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

  #[async_recursion::async_recursion]
  async fn broadcast(
    &mut self,
    data: Data<N::Block, <N::SignatureScheme as SignatureScheme>::Signature>,
  ) -> Option<N::Block> {
    let step = data.step();
    let msg = Message { sender: self.proposer, number: self.number, round: self.round, data };
    let res = self.message(msg.clone()).await.unwrap();
    self.step = step; // TODO: Before or after the above handling call?

    let sig = self.signer.sign(&msg.encode());
    self.network.write().await.broadcast(SignedMessage { msg, sig }).await;
    res
  }

  // 14-21
  async fn round_propose(&mut self) {
    if self.weights.proposer(self.number, self.round) == self.proposer {
      let (round, block) = if let Some((round, block)) = &self.valid {
        (Some(*round), block.clone())
      } else {
        (None, self.personal_proposal.clone())
      };
      debug_assert!(self.broadcast(Data::Proposal(round, block)).await.is_none());
    } else {
      self.timeouts.insert(Step::Propose, self.timeout(Step::Propose));
    }
  }

  // 11-13
  async fn round(&mut self, round: Round) {
    dbg!(round);

    // Correct the start time
    for _ in self.round.0 .. round.0 {
      self.start_time = self.timeout(Step::Precommit);
    }

    // Clear timeouts
    self.timeouts = HashMap::new();

    self.round = round;
    self.step = Step::Propose;
    self.round_propose().await;
  }

  // 1-9
  async fn reset(&mut self, proposal: N::Block) {
    self.number.0 += 1;
    self.start_time = Instant::now();
    self.personal_proposal = proposal;

    self.log = MessageLog::new(self.network.read().await.weights());

    self.locked = None;
    self.valid = None;

    self.round(Round(0)).await;
  }

  /// Create a new Tendermint machine, for the specified proposer, from the specified block, with
  /// the specified block as the one to propose next, returning a handle for the machine.
  // 10
  #[allow(clippy::new_ret_no_self)]
  pub fn new(
    network: N,
    proposer: N::ValidatorId,
    number: BlockNumber,
    proposal: N::Block,
  ) -> TendermintHandle<N> {
    let (msg_send, mut msg_recv) = mpsc::channel(100); // Backlog to accept. Currently arbitrary
    TendermintHandle {
      messages: msg_send,
      handle: tokio::spawn(async move {
        let signer = network.signature_scheme();
        let weights = network.weights();
        let network = Arc::new(RwLock::new(network));
        let mut machine = TendermintMachine {
          network,
          signer,
          weights: weights.clone(),
          proposer,

          number,
          start_time: Instant::now(),
          personal_proposal: proposal,

          log: MessageLog::new(weights),
          round: Round(0),
          step: Step::Propose,

          locked: None,
          valid: None,

          timeouts: HashMap::new(),
        };
        machine.round_propose().await;

        loop {
          // Check if any timeouts have been triggered
          let now = Instant::now();
          let (t1, t2, t3) = {
            let ready = |step| machine.timeouts.get(&step).unwrap_or(&now) < &now;
            (ready(Step::Propose), ready(Step::Prevote), ready(Step::Precommit))
          };

          // Propose timeout
          if t1 && (machine.step == Step::Propose) {
            debug_assert!(machine.broadcast(Data::Prevote(None)).await.is_none());
          }

          // Prevote timeout
          if t2 && (machine.step == Step::Prevote) {
            debug_assert!(machine.broadcast(Data::Precommit(None)).await.is_none());
          }

          // Precommit timeout
          if t3 {
            machine.round(Round(machine.round.0 + 1)).await;
          }

          // If there's a message, handle it
          match msg_recv.try_recv() {
            Ok(msg) => {
              if !machine.signer.verify(msg.msg.sender, &msg.msg.encode(), msg.sig) {
                yield_now().await;
                continue;
              }

              match machine.message(msg.msg).await {
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

                  let commit =
                    Commit { validators, signature: N::SignatureScheme::aggregate(&sigs) };
                  debug_assert!(machine.network.read().await.verify_commit(block.id(), &commit));
                  let proposal = machine.network.write().await.add_block(block, commit);
                  machine.reset(proposal).await
                }
                Err(TendermintError::Malicious(validator)) => {
                  machine.network.write().await.slash(validator).await
                }
                Err(TendermintError::Temporal) => (),
              }
            }
            Err(TryRecvError::Empty) => yield_now().await,
            Err(TryRecvError::Disconnected) => break,
          }
        }
      }),
    }
  }

  // 49-54
  fn check_committed(&mut self, round: Round) -> Option<N::Block> {
    let proposer = self.weights.proposer(self.number, round);

    // Get the proposal
    if let Some(proposal) = self.log.get(round, proposer, Step::Propose) {
      // Destructure
      debug_assert!(matches!(proposal, Data::Proposal(..)));
      if let Data::Proposal(_, block) = proposal {
        // Check if it has gotten a sufficient amount of precommits
        let (participants, weight) = self
          .log
          // Use a junk signature since message equality is irrelevant to the signature
          .message_instances(round, Data::Precommit(Some((block.id(), self.signer.sign(&[])))));

        let threshold = self.weights.threshold();
        if weight >= threshold {
          return Some(block.clone());
        }

        // 47-48
        if participants >= threshold {
          let timeout = self.timeout(Step::Precommit);
          self.timeouts.entry(Step::Precommit).or_insert(timeout);
        }
      }
    }

    None
  }

  async fn message(
    &mut self,
    msg: Message<N::ValidatorId, N::Block, <N::SignatureScheme as SignatureScheme>::Signature>,
  ) -> Result<Option<N::Block>, TendermintError<N::ValidatorId>> {
    if let Data::Precommit(Some((id, sig))) = &msg.data {
      if !self.signer.verify(msg.sender, id.as_ref(), sig.clone()) {
        Err(TendermintError::Malicious(msg.sender))?;
      }
    }

    if msg.number != self.number {
      Err(TendermintError::Temporal)?;
    }

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
    if matches!(msg.data, Data::Proposal(..)) || matches!(msg.data, Data::Precommit(_)) {
      let block = self.check_committed(msg.round);
      if block.is_some() {
        return Ok(block);
      }
    }

    // Else, check if we need to jump ahead
    #[allow(clippy::comparison_chain)]
    if msg.round.0 < self.round.0 {
      return Ok(None);
    } else if msg.round.0 > self.round.0 {
      // 55-56
      if self.log.round_participation(self.round) > self.weights.fault_thresold() {
        self.round(msg.round).await;
      } else {
        return Ok(None);
      }
    }

    let proposal = self
      .log
      .get(self.round, self.weights.proposer(self.number, self.round), Step::Propose)
      .cloned();
    if self.step == Step::Propose {
      if let Some(proposal) = &proposal {
        debug_assert!(matches!(proposal, Data::Proposal(..)));
        if let Data::Proposal(vr, block) = proposal {
          if let Some(vr) = vr {
            // 28-33
            if (vr.0 < self.round.0) && self.log.has_consensus(*vr, Data::Prevote(Some(block.id())))
            {
              debug_assert!(self
                .broadcast(Data::Prevote(Some(block.id()).filter(|_| {
                  self
                    .locked
                    .as_ref()
                    .map(|(round, value)| (round.0 <= vr.0) || (block.id() == value.id()))
                    .unwrap_or(true)
                })))
                .await
                .is_none());
            } else {
              Err(TendermintError::Malicious(msg.sender))?;
            }
          } else {
            // 22-27
            self.network.write().await.validate(block).map_err(|e| match e {
              BlockError::Temporal => TendermintError::Temporal,
              BlockError::Fatal => TendermintError::Malicious(msg.sender),
            })?;
            debug_assert!(self
              .broadcast(Data::Prevote(Some(block.id()).filter(|_| self.locked.is_none() ||
                self.locked.as_ref().map(|locked| locked.1.id()) == Some(block.id()))))
              .await
              .is_none());
          }
        }
      }
    }

    if self.step == Step::Prevote {
      let (participation, weight) = self.log.message_instances(self.round, Data::Prevote(None));
      // 34-35
      if participation >= self.weights.threshold() {
        let timeout = self.timeout(Step::Prevote);
        self.timeouts.entry(Step::Prevote).or_insert(timeout);
      }

      // 44-46
      if weight >= self.weights.threshold() {
        debug_assert!(self.broadcast(Data::Precommit(None)).await.is_none());
      }
    }

    // 36-43
    if (self.valid.is_none()) && ((self.step == Step::Prevote) || (self.step == Step::Precommit)) {
      if let Some(proposal) = proposal {
        debug_assert!(matches!(proposal, Data::Proposal(..)));
        if let Data::Proposal(_, block) = proposal {
          if self.log.has_consensus(self.round, Data::Prevote(Some(block.id()))) {
            self.valid = Some((self.round, block.clone()));
            if self.step == Step::Prevote {
              self.locked = self.valid.clone();
              return Ok(
                self
                  .broadcast(Data::Precommit(Some((
                    block.id(),
                    self.signer.sign(block.id().as_ref()),
                  ))))
                  .await,
              );
            }
          }
        }
      }
    }

    Ok(None)
  }
}
