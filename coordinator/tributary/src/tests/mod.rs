use serai_primitives::{
  network_id::ExternalNetworkId,
  validator_sets::{ExternalValidatorSet, Session},
};

pub mod transaction;
pub mod db;
pub mod scan_block;

pub(crate) fn default_test_validator_set() -> ExternalValidatorSet {
  // The external validator set does not alter or affect the behavior of the functions being tested
  // this can be used just as a default value any time
  ExternalValidatorSet { network: ExternalNetworkId::Bitcoin, session: Session(0) }
}
