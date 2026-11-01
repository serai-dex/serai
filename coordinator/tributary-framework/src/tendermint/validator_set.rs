use core::num::NonZero;
use alloc::boxed::Box;
use std::collections::HashMap;

use tendermint::{BlockNumber, RoundNumber, ValidatorSet as _};

/// A wrapper around `HashMap` which caches the results of its functions.
#[derive(Clone)]
pub(crate) struct ValidatorSet {
  validators: HashMap<[u8; 32], NonZero<u16>>,
  total_weight: NonZero<u16>,
  proposers: Box<[[u8; 32]]>,
}

impl ValidatorSet {
  pub(crate) fn new(validators: HashMap<[u8; 32], NonZero<u16>>) -> Self {
    let total_weight = validators.total_weight();
    /*
      TODO: This builds the cache by calling the underlying, yet the underlying continually ad-hocs
      builds this information, Directly build the cache here.
    */
    let proposers = {
      let mut proposers = Box::new_uninit_slice(usize::from(u16::from(total_weight)));
      let mut i = 0u16;
      for proposer in &mut proposers {
        i += 1;
        proposer.write(validators.proposer(
          ::tendermint::BlockNumber::from(NonZero::new(u64::from(i)).unwrap()),
          ::tendermint::RoundNumber::from(const { NonZero::new(1u64).unwrap() }),
        ));
      }
      // Safety: We just wrote to every entry of this slice
      unsafe { proposers.assume_init() }
    };

    Self { validators, total_weight, proposers }
  }
}

impl AsRef<HashMap<[u8; 32], NonZero<u16>>> for ValidatorSet {
  fn as_ref(&self) -> &HashMap<[u8; 32], NonZero<u16>> {
    &self.validators
  }
}

impl ::tendermint::ValidatorSet for ValidatorSet {
  type Validator = [u8; 32];

  fn total_weight(&self) -> NonZero<u16> {
    self.total_weight
  }

  fn validators(&self) -> impl IntoIterator<Item = &Self::Validator> {
    self.validators.keys()
  }

  fn weight(&self, validator: &Self::Validator) -> Option<NonZero<u16>> {
    self.validators.get(validator).copied()
  }

  fn proposer(&self, block_number: BlockNumber, round_number: RoundNumber) -> Self::Validator {
    let modulus = u64::from(u16::from(self.total_weight));
    let reduced_block_number = (u64::from(block_number) - 1) % modulus;
    let reduced_round_number = (u64::from(round_number) - 1) % modulus;
    let i = u16::try_from((reduced_block_number + reduced_round_number) % modulus).unwrap();
    self.proposers[usize::from(i)]
  }
}

#[test]
fn validator_set() {
  let underlying = HashMap::from([
    ([1; 32], NonZero::new(1).unwrap()),
    ([2; 32], NonZero::new(2).unwrap()),
    ([3; 32], NonZero::new(1).unwrap()),
  ]);
  let validator_set = ValidatorSet::new(underlying.clone());

  assert_eq!(validator_set.total_weight(), NonZero::new(4).unwrap());
  assert_eq!(validator_set.proposers.len(), 4);
  for block_number in 1 .. 256 {
    for round_number in 1 .. 256 {
      let block_number = BlockNumber::from(NonZero::new(block_number).unwrap());
      let round_number = RoundNumber::from(NonZero::new(round_number).unwrap());
      assert_eq!(
        underlying.proposer(block_number, round_number),
        validator_set.proposer(block_number, round_number)
      );
    }
  }
}
