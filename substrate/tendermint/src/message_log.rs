use std::{sync::Arc, collections::HashMap};

use crate::{ext::*, Round, Step, Data, Message, TendermintError};

pub(crate) struct MessageLog<V: ValidatorId, B: Block, N: Network<V, B>> {
  network: Arc<N>,
  precommitted: HashMap<V, B::Id>,
  log: HashMap<Round, HashMap<V, HashMap<Step, Data<B>>>>,
}

impl<V: ValidatorId, B: Block, N: Network<V, B>> MessageLog<V, B, N> {
  pub(crate) fn new(network: Arc<N>) -> MessageLog<V, B, N> {
    MessageLog { network, precommitted: HashMap::new(), log: HashMap::new() }
  }

  // Returns true if it's a new message
  pub(crate) fn log(&mut self, msg: Message<V, B>) -> Result<bool, TendermintError<V>> {
    let round = self.log.entry(msg.round).or_insert_with(HashMap::new);
    let msgs = round.entry(msg.sender).or_insert_with(HashMap::new);

    // Handle message replays without issue. It's only multiple messages which is malicious
    let step = msg.data.step();
    if let Some(existing) = msgs.get(&step) {
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

    msgs.insert(step, msg.data);
    Ok(true)
  }

  // For a given round, return the participating weight for this step, and the weight agreeing with
  // the data.
  pub(crate) fn message_instances(&self, round: Round, data: Data<B>) -> (u64, u64) {
    let mut participating = 0;
    let mut weight = 0;
    for (participant, msgs) in &self.log[&round] {
      if let Some(msg) = msgs.get(&data.step()) {
        let validator_weight = self.network.weight(*participant);
        participating += validator_weight;
        if &data == msg {
          weight += validator_weight;
        }
      }
    }
    (participating, weight)
  }

  // Get the participation in a given round for a given step.
  pub(crate) fn participation(&self, round: Round, step: Step) -> u64 {
    let (participating, _) = self.message_instances(
      round,
      match step {
        Step::Propose => panic!("Checking for participation on Propose"),
        Step::Prevote => Data::Prevote(None),
        Step::Precommit => Data::Precommit(None),
      },
    );
    participating
  }

  // Check if there's been a BFT level of participation
  pub(crate) fn has_participation(&self, round: Round, step: Step) -> bool {
    self.participation(round, step) >= self.network.threshold()
  }

  // Check if consensus has been reached on a specific piece of data
  pub(crate) fn has_consensus(&self, round: Round, data: Data<B>) -> bool {
    let (_, weight) = self.message_instances(round, data);
    weight >= self.network.threshold()
  }
}
