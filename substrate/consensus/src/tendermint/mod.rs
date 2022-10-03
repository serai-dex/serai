use std::collections::HashMap;

type ValidatorId = u16;
const VALIDATORS: ValidatorId = 5;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Hash;
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Block {
  hash: Hash
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum BlockError {
  // Invalid behavior entirely
  Fatal,
  // Potentially valid behavior dependent on unsynchronized state
  Temporal,
}

fn valid(block: &Block) -> Result<(), BlockError> {
  Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Step {
  Propose,
  Prevote,
  Precommit,
}

#[derive(Clone, PartialEq, Eq, Debug)]
enum Data {
  Proposal(Option<u32>, Block),
  Prevote(Option<Hash>),
  Precommit(Option<Hash>),
}

impl Data {
  fn step(&self) -> Step {
    match self {
      Data::Proposal(..) => Step::Propose,
      Data::Prevote(..) => Step::Prevote,
      Data::Precommit(..) => Step::Precommit,
    }
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct Message {
  sender: ValidatorId,

  height: u32,
  round: u32,

  data: Data,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TendermintError {
  MaliciousOrTemporal(u16), // TODO: Remove when we figure this out
  Malicious(u16),
  Offline(u16),
  Temporal,
}

fn proposer(height: u32, round: u32) -> ValidatorId {
  ValidatorId::try_from((height + round) % u32::try_from(VALIDATORS).unwrap()).unwrap()
}

fn broadcast(msg: Message) {
  todo!();
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct TendermintMachine {
  proposer: ValidatorId,
  personal_proposal: Option<Block>,

  height: u32,

  log_map: HashMap<u32, HashMap<ValidatorId, HashMap<Step, Data>>>,
  precommitted: HashMap<ValidatorId, Hash>,

  round: u32,
  step: Step,
  locked: Option<(u32, Block)>,
  valid: Option<(u32, Block)>,
}

impl TendermintMachine {
  fn broadcast(&self, data: Data) -> Option<Block> {
    let msg = Message { sender: self.proposer, height: self.height, round: self.round, data };
    let res = self.message(msg).unwrap();
    broadcast(msg);
    res
  }

  // 14-21
  fn round_propose(&mut self) {
    // This will happen if it's a new height and propose hasn't been called yet
    if self.personal_proposal.is_none() {
      // Ensure it's actually a new height. Else, the caller failed to provide necessary data yet
      // is still executing the machine
      debug_assert_eq!(self.round, 0);
      return;
    }

    if proposer(self.height, self.round) == self.proposer {
      let (round, block) = if let Some((round, block)) = self.valid {
        (Some(round), block)
      } else {
        (None, self.personal_proposal.unwrap())
      };
      debug_assert!(self.broadcast(Data::Proposal(round, block)).is_none());
    } else {
      // TODO schedule timeout propose
    }
  }

  // 11-13
  fn round(&mut self, round: u32) {
    self.round = round;
    self.step = Step::Propose;
    self.round_propose();
  }

  /// Called whenever a new height occurs
  pub fn propose(&mut self, block: Block) {
    self.personal_proposal = Some(block);
    self.round_propose();
  }

  // 1-9
  fn reset(&mut self) {
    self.personal_proposal = None;

    self.height += 1;

    self.log_map = HashMap::new();
    self.precommitted = HashMap::new();

    self.locked = None;
    self.valid = None;

    self.round(0);
  }

  // 10
  pub fn new(proposer: ValidatorId, height: u32) -> TendermintMachine {
    TendermintMachine {
      proposer,
      personal_proposal: None,

      height,

      log_map: HashMap::new(),
      precommitted: HashMap::new(),

      locked: None,
      valid: None,

      round: 0,
      step: Step::Propose
    }
  }

  // Returns true if it's a new message
  fn log(&mut self, msg: Message) -> Result<bool, TendermintError> {
    if matches!(msg.data, Data::Proposal(..)) && (msg.sender != proposer(msg.height, msg.round)) {
      Err(TendermintError::Malicious(msg.sender))?;
    };

    if !self.log_map.contains_key(&msg.round) {
      self.log_map.insert(msg.round, HashMap::new());
    }
    let log = self.log_map.get_mut(&msg.round).unwrap();
    if !log.contains_key(&msg.sender) {
      log.insert(msg.sender, HashMap::new());
    }
    let log = log.get_mut(&msg.sender).unwrap();

    // Handle message replays without issue. It's only multiple messages which is malicious
    let step = msg.data.step();
    if let Some(existing) = log.get(&step) {
      if existing != &msg.data {
        Err(TendermintError::Malicious(msg.sender))?;
      }
      return Ok(false);
    }

    // If they already precommitted to a distinct hash, error
    if let Data::Precommit(Some(hash)) = msg.data {
      if let Some(prev) = self.precommitted.get(&msg.sender) {
        if hash != *prev {
          Err(TendermintError::Malicious(msg.sender))?;
        }
      }
      self.precommitted.insert(msg.sender, hash);
    }

    log.insert(step, msg.data);
    Ok(true)
  }

  fn message_instances(&self, round: u32, data: Data) -> (usize, usize) {
    let participating = 0;
    let weight = 0;
    for participant in self.log_map[&round].values() {
      if let Some(msg) = participant.get(&data.step()) {
        let validator_weight = 1; // TODO
        participating += validator_weight;
        if &data == msg {
          weight += validator_weight;
        }

        // If the msg exists, yet has a distinct hash, this validator is faulty
        // (at least for precommit)
        // TODO
      }
    }
    (participating, weight)
  }

  fn participation(&self, round: u32, step: Step) -> usize {
    let (participating, _) = self.message_instances(round, match step {
      Step::Propose => panic!("Checking for participation on Propose"),
      Step::Prevote => Data::Prevote(None),
      Step::Precommit => Data::Precommit(None),
    });
    participating
  }

  fn has_participation(&self, round: u32, step: Step) -> bool {
    self.participation(round, step) >= ((VALIDATORS / 3 * 2) + 1).into()
  }

  fn has_consensus(&self, round: u32, data: Data) -> bool {
    let (_, weight) = self.message_instances(round, data);
    weight >= ((VALIDATORS / 3 * 2) + 1).into()
  }

  // 49-54
  fn check_committed(&mut self, round_num: u32) -> Option<Block> {
    let proposer = proposer(self.height, round_num);
    // Safe as we only check for rounds which we received a message for
    let round = self.log_map[&round_num];

    // Get the proposal
    if let Some(proposal) = round.get(&proposer).map(|p| p.get(&Step::Propose)).flatten() {
      // Destructure
      debug_assert!(matches!(proposal, Data::Proposal(..)));
      if let Data::Proposal(_, block) = proposal {
        // Check if it has gotten a sufficient amount of precommits
        let (participants, weight) = self.message_instances(round_num, Data::Precommit(Some(block.hash)));

        let threshold = ((VALIDATORS / 3) * 2) + 1;
        if weight >= threshold.into() {
          self.reset();
          return Some(*block);
        }

        if (participants >= threshold.into()) && first {
          schedule timeoutPrecommit(self.height, round);
        }
      }
    }

    None
  }

  pub fn message(&mut self, msg: Message) -> Result<Option<Block>, TendermintError> {
    if msg.height != self.height {
      Err(TendermintError::Temporal)?;
    }

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
      if let Some(proposal) = round.get(&proposer(self.height, self.round)).map(|p| p.get(&Step::Propose)).flatten() {
        debug_assert!(matches!(proposal, Data::Proposal(..)));
        if let Data::Proposal(vr, block) = proposal {
          if let Some(vr) = vr {
            // 28-33
            let vr = *vr;
            if (vr < self.round) && self.has_consensus(vr, Data::Prevote(Some(block.hash))) {
              debug_assert!(self.broadcast(
                Data::Prevote(
                  Some(block.hash).filter(|_| self.locked.map(|(round, value)| (round <= vr) || (block == &value)).unwrap_or(true))
                )
              ).is_none());
              self.step = Step::Prevote;
            } else {
              Err(TendermintError::Malicious(msg.sender))?;
            }
          } else {
            // 22-27
            valid(&block).map_err(|_| TendermintError::Malicious(msg.sender))?;
            debug_assert!(self.broadcast(Data::Prevote(Some(block.hash).filter(|_| self.locked.is_none() || self.locked.map(|locked| &locked.1) == Some(block)))).is_none());
            self.step = Step::Prevote;
          }
        }
      }
    }

    if self.step == Step::Prevote {
      let (participation, weight) = self.message_instances(self.round, Data::Prevote(None));
      // 34-35
      if (participation > (((VALIDATORS / 3) * 2) + 1).into()) && first {
        // TODO: Schedule timeout prevote
      }

      // 44-46
      if (weight > (((VALIDATORS / 3) * 2) + 1).into()) && first {
        debug_assert!(self.broadcast(Data::Precommit(None)).is_none());
        self.step = Step::Precommit;
      }
    }

    // 47-48
    if self.has_participation(self.round, Step::Precommit) && first {
      // TODO: Schedule timeout precommit
    }

    Ok(None)
  }
}
