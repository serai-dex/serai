// TODO

use tendermint_machine::ext::{BlockNumber, Round, Weights};

const VALIDATORS: usize = 1;

// TODO: Move to sp_session
pub(crate) struct TendermintWeights;
impl Weights for TendermintWeights {
  type ValidatorId = u16;

  fn total_weight(&self) -> u64 {
    VALIDATORS.try_into().unwrap()
  }
  fn weight(&self, id: u16) -> u64 {
    [1; VALIDATORS][usize::try_from(id).unwrap()]
  }

  fn proposer(&self, number: BlockNumber, round: Round) -> u16 {
    u16::try_from((number.0 + u64::from(round.0)) % u64::try_from(VALIDATORS).unwrap()).unwrap()
  }
}
