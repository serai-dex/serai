pub mod ext;
use ext::*;

mod message_log;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Step {
  Propose,
  Prevote,
  Precommit,
}

#[derive(Clone, PartialEq)]
enum Data<B: Block> {
  Proposal(Option<u32>, B),
  Prevote(Option<B::Id>),
  Precommit(Option<B::Id>),
}

impl<B: Block> Data<B> {
  fn step(&self) -> Step {
    match self {
      Data::Proposal(..) => Step::Propose,
      Data::Prevote(..) => Step::Prevote,
      Data::Precommit(..) => Step::Precommit,
    }
  }
}

#[derive(Clone, PartialEq)]
struct Message<V: ValidatorId, B: Block> {
  sender: V,

  number: BlockNumber,
  round: Round,

  data: Data<B>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TendermintError<V: ValidatorId> {
  Malicious(V),
  Offline(V),
  Temporal,
}

/*
use std::collections::HashMap;

use tokio::{
  task::{JoinHandle, spawn},
  sync::mpsc,
};

#[derive(Debug)]
struct TendermintMachine {
  proposer: ValidatorId,
  personal_proposal: Option<Block>,

  number: u32,

  log_map: HashMap<u32, HashMap<ValidatorId, HashMap<Step, Data>>>,
  precommitted: HashMap<ValidatorId, Hash>,

  round: u32,
  step: Step,
  locked: Option<(u32, Block)>,
  valid: Option<(u32, Block)>,

  timeouts: Arc<RwLock<HashMap<Step, Instant>>>, // TODO: Remove Arc RwLock
}

#[derive(Debug)]
struct TendermintHandle {
  block: Arc<RwLock<Option<Block>>>,
  messages: mpsc::Sender<Message>,
  broadcast: mpsc::Receiver<Message>,
  handle: JoinHandle<()>,
}

impl TendermintMachine {
  fn broadcast(&self, data: Data) -> Option<Block> {
    let msg = Message { sender: self.proposer, number: self.number, round: self.round, data };
    let res = self.message(msg).unwrap();
    self.broadcast.send(msg).unwrap();
    res
  }

  // 14-21
  fn round_propose(&mut self) {
    // This will happen if it's a new block and propose hasn't been called yet
    if self.personal_proposal.is_none() {
      // Ensure it's actually a new block. Else, the caller failed to provide necessary data yet
      // is still executing the machine
      debug_assert_eq!(self.round, 0);
      return;
    }

    if proposer(self.number, self.round) == self.proposer {
      let (round, block) = if let Some((round, block)) = self.valid {
        (Some(round), block)
      } else {
        (None, self.personal_proposal.unwrap())
      };
      debug_assert!(self.broadcast(Data::Proposal(round, block)).is_none());
    } else {
      self.timeouts.write().unwrap().insert(Step::Propose, self.timeout(Step::Propose));
    }
  }

  // 11-13
  fn round(&mut self, round: u32) {
    self.round = round;
    self.step = Step::Propose;
    self.round_propose();
  }

  /// Called whenever a new block occurs
  fn propose(&mut self, block: Block) {
    self.personal_proposal = Some(block);
    self.round_propose();
  }

  // 1-9
  fn reset(&mut self) {
    self.personal_proposal = None;

    self.number += 1;

    self.log_map = HashMap::new();
    self.precommitted = HashMap::new();

    self.locked = None;
    self.valid = None;

    self.round(0);
  }

  // 10
  pub fn new(proposer: ValidatorId, number: u32) -> TendermintHandle {
    let block = Arc::new(RwLock::new(None));
    let (msg_send, mut msg_recv) = mpsc::channel(100); // Backlog to accept. Currently arbitrary
    let (broadcast_send, broadcast_recv) = mpsc::channel(5);
    TendermintHandle {
      block: block.clone(),
      messages: msg_send,
      broadcast: broadcast_recv,
      handle: tokio::spawn(async {
        let machine = TendermintMachine {
          proposer,
          personal_proposal: None,

          number,

          log_map: HashMap::new(),
          precommitted: HashMap::new(),

          locked: None,
          valid: None,

          round: 0,
          step: Step::Propose,
        };

        loop {
          if self.personal_proposal.is_none() {
            let block = block.lock().unwrap();
            if block.is_some() {
              self.personal_proposal = Some(block.take());
            } else {
              tokio::yield_now().await;
              continue;
            }
          }

          let now = Instant::now();
          let (t1, t2, t3) = {
            let timeouts = self.timeouts.read().unwrap();
            let ready = |step| timeouts.get(step).unwrap_or(now) < now;
            (ready(Step::Propose), ready(Step::Prevote), ready(Step::Precommit))
          };

          if t1 { // Propose timeout
          }
          if t2 { // Prevote timeout
          }
          if t3 { // Precommit timeout
          }

          match recv.try_recv() {
            Ok(msg) => machine.message(msg),
            Err(TryRecvError::Empty) => tokio::yield_now().await,
            Err(TryRecvError::Disconnected) => break,
          }
        }
      }),
    }
  }

  // 49-54
  fn check_committed(&mut self, round_num: u32) -> Option<Block> {
    let proposer = proposer(self.number, round_num);
    // Safe as we only check for rounds which we received a message for
    let round = self.log_map[&round_num];

    // Get the proposal
    if let Some(proposal) = round.get(&proposer).map(|p| p.get(&Step::Propose)).flatten() {
      // Destructure
      debug_assert!(matches!(proposal, Data::Proposal(..)));
      if let Data::Proposal(_, block) = proposal {
        // Check if it has gotten a sufficient amount of precommits
        let (participants, weight) =
          self.message_instances(round_num, Data::Precommit(Some(block.hash)));

        let threshold = ((VALIDATORS / 3) * 2) + 1;
        if weight >= threshold.into() {
          self.reset();
          return Some(*block);
        }

        // 47-48
        if participants >= threshold.into() {
          let map = self.timeouts.write().unwrap();
          if !map.contains_key(Step::Precommit) {
            map.insert(Step::Precommit, self.timeout(Step::Precommit));
          }
        }
      }
    }

    None
  }

  fn message(&mut self, msg: Message) -> Result<Option<Block>, TendermintError> {
    if msg.number != self.number {
      Err(TendermintError::Temporal)?;
    }

    if matches!(msg.data, Data::Proposal(..)) && (msg.sender != proposer(msg.height, msg.round)) {
      Err(TendermintError::Malicious(msg.sender))?;
    };

    if !self.log(msg)? {
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
    let round = self.log_map[&self.round];
    if msg.round < self.round {
      return Ok(None);
    } else if msg.round > self.round {
      // 55-56
      // TODO: Move to weight
      if round.len() > ((VALIDATORS / 3) + 1).into() {
        self.round(msg.round);
      } else {
        return Ok(None);
      }
    }

    if self.step == Step::Propose {
      if let Some(proposal) =
        round.get(&proposer(self.number, self.round)).map(|p| p.get(&Step::Propose)).flatten()
      {
        debug_assert!(matches!(proposal, Data::Proposal(..)));
        if let Data::Proposal(vr, block) = proposal {
          if let Some(vr) = vr {
            // 28-33
            let vr = *vr;
            if (vr < self.round) && self.has_consensus(vr, Data::Prevote(Some(block.hash))) {
              debug_assert!(self
                .broadcast(Data::Prevote(Some(block.hash).filter(|_| {
                  self
                    .locked
                    .map(|(round, value)| (round <= vr) || (block == &value))
                    .unwrap_or(true)
                })))
                .is_none());
              self.step = Step::Prevote;
            } else {
              Err(TendermintError::Malicious(msg.sender))?;
            }
          } else {
            // 22-27
            valid(&block).map_err(|_| TendermintError::Malicious(msg.sender))?;
            debug_assert!(self
              .broadcast(Data::Prevote(Some(block.hash).filter(
                |_| self.locked.is_none() || self.locked.map(|locked| &locked.1) == Some(block)
              )))
              .is_none());
            self.step = Step::Prevote;
          }
        }
      }
    }

    if self.step == Step::Prevote {
      let (participation, weight) = self.message_instances(self.round, Data::Prevote(None));
      // 34-35
      if participation > (((VALIDATORS / 3) * 2) + 1).into() {
        let map = self.timeouts.write().unwrap();
        if !map.contains_key(Step::Prevote) {
          map.insert(Step::Prevote, self.timeout(Step::Prevote))
        }
      }

      // 44-46
      if (weight > (((VALIDATORS / 3) * 2) + 1).into()) && first {
        debug_assert!(self.broadcast(Data::Precommit(None)).is_none());
        self.step = Step::Precommit;
      }
    }

    Ok(None)
  }
}
*/
