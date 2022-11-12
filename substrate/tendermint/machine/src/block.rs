use std::collections::{HashSet, HashMap};

use crate::{
  time::CanonicalInstant,
  ext::{RoundNumber, BlockNumber, Block, Network},
  round::RoundData,
  message_log::MessageLog,
};

pub(crate) struct BlockData<N: Network> {
  pub(crate) number: BlockNumber,
  pub(crate) validator_id: Option<N::ValidatorId>,
  pub(crate) proposal: N::Block,

  pub(crate) log: MessageLog<N>,
  pub(crate) slashes: HashSet<N::ValidatorId>,
  pub(crate) end_time: HashMap<RoundNumber, CanonicalInstant>,

  pub(crate) round: RoundData<N>,

  pub(crate) locked: Option<(RoundNumber, <N::Block as Block>::Id)>,
  pub(crate) valid: Option<(RoundNumber, N::Block)>,
}
