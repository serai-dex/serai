use std::{
  sync::Arc,
  collections::{HashSet, HashMap},
};

use crate::{
  time::CanonicalInstant,
  ext::{RoundNumber, BlockNumber, Block, Network},
  round::RoundData,
  message_log::MessageLog,
  Step, Data, DataFor, Message, MessageFor,
};

pub(crate) struct BlockData<N: Network> {
  pub(crate) number: BlockNumber,
  pub(crate) validator_id: Option<N::ValidatorId>,
  pub(crate) proposal: N::Block,

  pub(crate) log: MessageLog<N>,
  pub(crate) slashes: HashSet<N::ValidatorId>,
  pub(crate) end_time: HashMap<RoundNumber, CanonicalInstant>,

  pub(crate) round: Option<RoundData<N>>,

  pub(crate) locked: Option<(RoundNumber, <N::Block as Block>::Id)>,
  pub(crate) valid: Option<(RoundNumber, N::Block)>,
}

impl<N: Network> BlockData<N> {
  pub(crate) fn new(
    weights: Arc<N::Weights>,
    number: BlockNumber,
    validator_id: Option<N::ValidatorId>,
    proposal: N::Block,
  ) -> BlockData<N> {
    BlockData {
      number,
      validator_id,
      proposal,

      log: MessageLog::new(weights),
      slashes: HashSet::new(),
      end_time: HashMap::new(),

      // The caller of BlockData::new is expected to be populated after by the caller
      round: None,

      locked: None,
      valid: None,
    }
  }

  pub(crate) fn round(&self) -> &RoundData<N> {
    self.round.as_ref().unwrap()
  }

  pub(crate) fn round_mut(&mut self) -> &mut RoundData<N> {
    self.round.as_mut().unwrap()
  }

  pub(crate) fn populate_end_time(&mut self, round: RoundNumber) {
    for r in (self.round().number.0 + 1) .. round.0 {
      self.end_time.insert(
        RoundNumber(r),
        RoundData::<N>::new(RoundNumber(r), self.end_time[&RoundNumber(r - 1)]).end_time(),
      );
    }
  }

  // Start a new round. Optionally takes in the time for when this is the first round, and the time
  // isn't simply the time of the prior round (yet rather the prior block). Returns the proposal
  // data, if we are the proposer.
  pub(crate) fn new_round(
    &mut self,
    round: RoundNumber,
    proposer: N::ValidatorId,
    time: Option<CanonicalInstant>,
  ) -> Option<DataFor<N>> {
    debug_assert_eq!(round.0 == 0, time.is_some());

    // If skipping rounds, populate end_time
    if round.0 != 0 {
      self.populate_end_time(round);
    }

    // 11-13
    self.round = Some(RoundData::<N>::new(
      round,
      time.unwrap_or_else(|| self.end_time[&RoundNumber(round.0 - 1)]),
    ));
    self.end_time.insert(round, self.round().end_time());

    // 14-21
    if Some(proposer) == self.validator_id {
      let (round, block) = if let Some((round, block)) = &self.valid {
        (Some(*round), block.clone())
      } else {
        (None, self.proposal.clone())
      };
      Some(Data::Proposal(round, block))
    } else {
      self.round_mut().set_timeout(Step::Propose);
      None
    }
  }

  // Transform Data into an actual Message, using the contextual data from this block
  pub(crate) fn message(&mut self, data: DataFor<N>) -> Option<MessageFor<N>> {
    debug_assert_eq!(
      self.round().step,
      match data.step() {
        Step::Propose | Step::Prevote => Step::Propose,
        Step::Precommit => Step::Prevote,
      },
    );
    // 27, 33, 41, 46, 60, 64
    self.round_mut().step = data.step();

    // Only return a message to if we're actually a current validator
    self.validator_id.map(|validator_id| Message {
      sender: validator_id,
      number: self.number,
      round: self.round().number,
      data,
    })
  }
}
