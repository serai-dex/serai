use std::{sync::Arc, collections::HashMap};

use log::debug;
use parity_scale_codec::Encode;

use crate::{ext::*, RoundNumber, Step, Data, DataFor, TendermintError, SignedMessageFor, Evidence};

type RoundLog<N> = HashMap<<N as Network>::ValidatorId, HashMap<Step, SignedMessageFor<N>>>;
pub(crate) struct MessageLog<N: Network> {
  weights: Arc<N::Weights>,
  precommitted: HashMap<N::ValidatorId, SignedMessageFor<N>>,
  pub(crate) log: HashMap<RoundNumber, RoundLog<N>>,
}

impl<N: Network> MessageLog<N> {
  pub(crate) fn new(weights: Arc<N::Weights>) -> MessageLog<N> {
    MessageLog { weights, precommitted: HashMap::new(), log: HashMap::new() }
  }

  // Returns true if it's a new message
  pub(crate) fn log(&mut self, signed: SignedMessageFor<N>) -> Result<bool, TendermintError<N>> {
    let msg = &signed.msg;
    // Clarity, and safety around default != new edge cases
    #[allow(clippy::unwrap_or_default)]
    let round = self.log.entry(msg.round).or_insert_with(HashMap::new);
    #[allow(clippy::unwrap_or_default)]
    let msgs = round.entry(msg.sender).or_insert_with(HashMap::new);

    // Handle message replays without issue. It's only multiple messages which is malicious
    let step = msg.data.step();
    if let Some(existing) = msgs.get(&step) {
      if existing.msg.data != msg.data {
        debug!(
          target: "tendermint",
          "Validator sent multiple messages for the same block + round + step"
        );
        Err(TendermintError::Malicious(
          msg.sender,
          Some(Evidence::ConflictingMessages(existing.encode(), signed.clone().encode())),
        ))?;
      }
      return Ok(false);
    }

    // If they already precommitted to a distinct hash, error
    if let Data::Precommit(Some((hash, _))) = msg.data {
      if let Some(prev) = self.precommitted.get(&msg.sender) {
        if let Data::Precommit(Some((prev_hash, _))) = prev.msg.data {
          if hash != prev_hash {
            debug!(target: "tendermint", "Validator precommitted to multiple blocks");
            Err(TendermintError::Malicious(
              msg.sender,
              Some(Evidence::ConflictingPrecommit(prev.encode(), signed.clone().encode())),
            ))?;
          }
        } else {
          panic!("message in precommitted wasn't Precommit");
        }
      }
      self.precommitted.insert(msg.sender, signed.clone());
    }

    msgs.insert(step, signed);
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
        if data == msg.msg.data {
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
  ) -> Option<&SignedMessageFor<N>> {
    self.log.get(&round).and_then(|round| round.get(&sender).and_then(|msgs| msgs.get(&step)))
  }
}
