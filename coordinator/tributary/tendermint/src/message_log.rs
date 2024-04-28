use std::{sync::Arc, collections::HashMap};

use parity_scale_codec::Encode;

use crate::{ext::*, RoundNumber, Step, DataFor, SignedMessageFor, Evidence};

type RoundLog<N> = HashMap<<N as Network>::ValidatorId, HashMap<Step, SignedMessageFor<N>>>;
pub(crate) struct MessageLog<N: Network> {
  weights: Arc<N::Weights>,
  round_participation: HashMap<RoundNumber, u64>,
  participation: HashMap<(RoundNumber, Step), u64>,
  pub(crate) log: HashMap<RoundNumber, RoundLog<N>>,
}

impl<N: Network> MessageLog<N> {
  pub(crate) fn new(weights: Arc<N::Weights>) -> MessageLog<N> {
    MessageLog {
      weights,
      round_participation: HashMap::new(),
      participation: HashMap::new(),
      log: HashMap::new(),
    }
  }

  // Returns true if it's a new message
  pub(crate) fn log(&mut self, signed: SignedMessageFor<N>) -> Result<bool, Evidence> {
    let msg = &signed.msg;
    // Clarity, and safety around default != new edge cases
    let round = self.log.entry(msg.round).or_insert_with(HashMap::new);
    let msgs = round.entry(msg.sender).or_insert_with(HashMap::new);

    // Handle message replays without issue. It's only multiple messages which is malicious
    let step = msg.data.step();
    if let Some(existing) = msgs.get(&step) {
      if existing.msg.data != msg.data {
        log::debug!(
          target: "tendermint",
          "Validator sent multiple messages for the same block + round + step"
        );
        Err(Evidence::ConflictingMessages(existing.encode(), signed.encode()))?;
      }
      return Ok(false);
    }

    // Since we have a new message, update the participation
    let sender_weight = self.weights.weight(msg.sender);
    if msgs.is_empty() {
      *self.round_participation.entry(msg.round).or_insert_with(|| 0) += sender_weight;
    }
    *self.participation.entry((msg.round, step)).or_insert_with(|| 0) += sender_weight;

    msgs.insert(step, signed);
    Ok(true)
  }

  // For a given round, return the weight agreeing with the data
  fn message_instances(&self, round: RoundNumber, data: &DataFor<N>) -> u64 {
    let mut weight = 0;
    let Some(log) = self.log.get(&round) else { return 0 };
    for (participant, msgs) in log {
      if let Some(msg) = msgs.get(&data.step()) {
        let validator_weight = self.weights.weight(*participant);
        if data == &msg.msg.data {
          weight += validator_weight;
        }
      }
    }
    weight
  }

  // Get the participation in a given round
  pub(crate) fn round_participation(&self, round: RoundNumber) -> u64 {
    *self.round_participation.get(&round).unwrap_or(&0)
  }

  // Check if a supermajority of nodes have participated on a specific step
  pub(crate) fn has_participation(&self, round: RoundNumber, step: Step) -> bool {
    *self.participation.get(&(round, step)).unwrap_or(&0) >= self.weights.threshold()
  }

  // Check if consensus has been reached on a specific piece of data
  pub(crate) fn has_consensus(&self, round: RoundNumber, data: &DataFor<N>) -> bool {
    self.message_instances(round, data) >= self.weights.threshold()
  }
}
