use std::{sync::Arc, collections::HashMap};

<<<<<<< HEAD:coordinator/tributary/tendermint/src/message_log.rs
use log::debug;
=======
use crate::{ext::*, RoundNumber, Step, Data, Message, TendermintError};
>>>>>>> 2f3bb887 (Rename Round to RoundNumber):substrate/tendermint/machine/src/message_log.rs

use crate::{ext::*, RoundNumber, Step, Data, DataFor, MessageFor, TendermintError};

type RoundLog<N> = HashMap<<N as Network>::ValidatorId, HashMap<Step, DataFor<N>>>;
pub(crate) struct MessageLog<N: Network> {
  weights: Arc<N::Weights>,
<<<<<<< HEAD:coordinator/tributary/tendermint/src/message_log.rs
  precommitted: HashMap<N::ValidatorId, <N::Block as Block>::Id>,
  pub(crate) log: HashMap<RoundNumber, RoundLog<N>>,
=======
  pub(crate) precommitted: HashMap<
    N::ValidatorId,
    (<N::Block as Block>::Id, <N::SignatureScheme as SignatureScheme>::Signature),
  >,
  pub(crate) log: HashMap<
    RoundNumber,
    HashMap<
      N::ValidatorId,
      HashMap<Step, Data<N::Block, <N::SignatureScheme as SignatureScheme>::Signature>>,
    >,
  >,
>>>>>>> b993ff1c (Provide a dedicated signature in Precommit of just the block hash):substrate/tendermint/src/message_log.rs
}

impl<N: Network> MessageLog<N> {
  pub(crate) fn new(weights: Arc<N::Weights>) -> MessageLog<N> {
    MessageLog { weights, precommitted: HashMap::new(), log: HashMap::new() }
  }

  // Returns true if it's a new message
  pub(crate) fn log(
    &mut self,
<<<<<<< HEAD:coordinator/tributary/tendermint/src/message_log.rs
    msg: MessageFor<N>,
=======
    msg: Message<N::ValidatorId, N::Block, <N::SignatureScheme as SignatureScheme>::Signature>,
>>>>>>> b993ff1c (Provide a dedicated signature in Precommit of just the block hash):substrate/tendermint/src/message_log.rs
  ) -> Result<bool, TendermintError<N::ValidatorId>> {
    let round = self.log.entry(msg.round).or_insert_with(HashMap::new);
    let msgs = round.entry(msg.sender).or_insert_with(HashMap::new);

    // Handle message replays without issue. It's only multiple messages which is malicious
    let step = msg.data.step();
    if let Some(existing) = msgs.get(&step) {
      if existing != &msg.data {
        debug!(
          target: "tendermint",
          "Validator sent multiple messages for the same block + round + step"
        );
        Err(TendermintError::Malicious(msg.sender))?;
      }
      return Ok(false);
    }

    // If they already precommitted to a distinct hash, error
<<<<<<< HEAD:coordinator/tributary/tendermint/src/message_log.rs
    if let Data::Precommit(Some((hash, _))) = &msg.data {
      if let Some(prev) = self.precommitted.get(&msg.sender) {
        if hash != prev {
          debug!(target: "tendermint", "Validator precommitted to multiple blocks");
          Err(TendermintError::Malicious(msg.sender))?;
        }
      }
      self.precommitted.insert(msg.sender, *hash);
=======
    if let Data::Precommit(Some((hash, sig))) = &msg.data {
      if let Some((prev, _)) = self.precommitted.get(&msg.sender) {
        if hash != prev {
          Err(TendermintError::Malicious(msg.sender))?;
        }
      }
      self.precommitted.insert(msg.sender, (*hash, sig.clone()));
>>>>>>> b993ff1c (Provide a dedicated signature in Precommit of just the block hash):substrate/tendermint/src/message_log.rs
    }

    msgs.insert(step, msg.data);
    Ok(true)
  }

  // For a given round, return the participating weight for this step, and the weight agreeing with
  // the data.
<<<<<<< HEAD:coordinator/tributary/tendermint/src/message_log.rs
  pub(crate) fn message_instances(&self, round: RoundNumber, data: DataFor<N>) -> (u64, u64) {
=======
  pub(crate) fn message_instances(
    &self,
    round: RoundNumber,
    data: Data<N::Block, <N::SignatureScheme as SignatureScheme>::Signature>,
  ) -> (u64, u64) {
>>>>>>> b993ff1c (Provide a dedicated signature in Precommit of just the block hash):substrate/tendermint/src/message_log.rs
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

<<<<<<< HEAD:coordinator/tributary/tendermint/src/message_log.rs
<<<<<<< HEAD:coordinator/tributary/tendermint/src/message_log.rs
  // Check if a supermajority of nodes have participated on a specific step
  pub(crate) fn has_participation(&self, round: RoundNumber, step: Step) -> bool {
=======
  // Check if a supermajority of nodes have participated on a specific step
<<<<<<< HEAD:coordinator/tributary/tendermint/src/message_log.rs
  pub(crate) fn has_participation(&self, round: Round, step: Step) -> bool {
>>>>>>> 8b6eb117 (Litany of bug fixes):substrate/tendermint/src/message_log.rs
=======
  pub(crate) fn has_participation(&self, round: RoundNumber, step: Step) -> bool {
>>>>>>> 2f3bb887 (Rename Round to RoundNumber):substrate/tendermint/machine/src/message_log.rs
    let mut participating = 0;
    for (participant, msgs) in &self.log[&round] {
      if msgs.get(&step).is_some() {
        participating += self.weights.weight(*participant);
      }
    }
    participating >= self.weights.threshold()
  }

<<<<<<< HEAD:coordinator/tributary/tendermint/src/message_log.rs
=======
>>>>>>> a0bc9dc3 (Misc cleanup):substrate/tendermint/src/message_log.rs
=======
>>>>>>> 8b6eb117 (Litany of bug fixes):substrate/tendermint/src/message_log.rs
  // Check if consensus has been reached on a specific piece of data
<<<<<<< HEAD:coordinator/tributary/tendermint/src/message_log.rs
  pub(crate) fn has_consensus(&self, round: RoundNumber, data: DataFor<N>) -> bool {
=======
  pub(crate) fn has_consensus(
    &self,
    round: RoundNumber,
    data: Data<N::Block, <N::SignatureScheme as SignatureScheme>::Signature>,
  ) -> bool {
>>>>>>> b993ff1c (Provide a dedicated signature in Precommit of just the block hash):substrate/tendermint/src/message_log.rs
    let (_, weight) = self.message_instances(round, data);
    weight >= self.weights.threshold()
  }

  pub(crate) fn get(
    &self,
    round: RoundNumber,
    sender: N::ValidatorId,
    step: Step,
<<<<<<< HEAD:coordinator/tributary/tendermint/src/message_log.rs
  ) -> Option<&DataFor<N>> {
=======
  ) -> Option<&Data<N::Block, <N::SignatureScheme as SignatureScheme>::Signature>> {
>>>>>>> b993ff1c (Provide a dedicated signature in Precommit of just the block hash):substrate/tendermint/src/message_log.rs
    self.log.get(&round).and_then(|round| round.get(&sender).and_then(|msgs| msgs.get(&step)))
  }
}
