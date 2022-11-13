use std::{sync::Arc, collections::HashMap};

use crate::{ext::*, RoundNumber, Step, Data, DataFor, MessageFor, TendermintError};

pub(crate) struct MessageLog<N: Network> {
  weights: Arc<N::Weights>,
  pub(crate) precommitted: HashMap<
    N::ValidatorId,
    (<N::Block as Block>::Id, <N::SignatureScheme as SignatureScheme>::Signature),
  >,
  pub(crate) log: HashMap<RoundNumber, HashMap<N::ValidatorId, HashMap<Step, DataFor<N>>>>,
}

impl<N: Network> MessageLog<N> {
  pub(crate) fn new(weights: Arc<N::Weights>) -> MessageLog<N> {
    MessageLog { weights, precommitted: HashMap::new(), log: HashMap::new() }
  }

  // Returns true if it's a new message
  pub(crate) fn log(
    &mut self,
    msg: MessageFor<N>,
  ) -> Result<bool, TendermintError<N::ValidatorId>> {
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
    if let Data::Precommit(Some((hash, sig))) = &msg.data {
      if let Some((prev, _)) = self.precommitted.get(&msg.sender) {
        if hash != prev {
          Err(TendermintError::Malicious(msg.sender))?;
        }
      }
      self.precommitted.insert(msg.sender, (*hash, sig.clone()));
    }

    msgs.insert(step, msg.data);
    Ok(true)
  }

  // For a given round, return the participating weight for this step, and the weight agreeing with
  // the data.
  pub(crate) fn message_instances(&self, round: RoundNumber, data: DataFor<N>) -> (u64, u64) {
    let mut participating = 0;
    let mut weight = 0;
    for (participant, msgs) in &self.log[&round] {
      if let Some(msg) = msgs.get(&data.step()) {
        let validator_weight = self.weights.weight(*participant);
        participating += validator_weight;
        if &data == msg {
          weight += validator_weight;
        }
      }
    }
    (participating, weight)
  }

  // Get the participation in a given round
  pub(crate) fn round_participation(&self, round: RoundNumber) -> u64 {
    let mut weight = 0;
    if let Some(round) = self.log.get(&round) {
      for participant in round.keys() {
        weight += self.weights.weight(*participant);
      }
    };
    weight
  }

  // Check if a supermajority of nodes have participated on a specific step
  pub(crate) fn has_participation(&self, round: RoundNumber, step: Step) -> bool {
    let mut participating = 0;
    for (participant, msgs) in &self.log[&round] {
      if msgs.get(&step).is_some() {
        participating += self.weights.weight(*participant);
      }
    }
    participating >= self.weights.threshold()
  }

  // Check if consensus has been reached on a specific piece of data
  pub(crate) fn has_consensus(&self, round: RoundNumber, data: DataFor<N>) -> bool {
    let (_, weight) = self.message_instances(round, data);
    weight >= self.weights.threshold()
  }

  pub(crate) fn get(
    &self,
    round: RoundNumber,
    sender: N::ValidatorId,
    step: Step,
  ) -> Option<&DataFor<N>> {
    self.log.get(&round).and_then(|round| round.get(&sender).and_then(|msgs| msgs.get(&step)))
  }
}
