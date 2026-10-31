use core::num::NonZero;
use alloc::boxed::Box;
use std::collections::HashMap;

/// A wrapper around `HashMap` which caches the results of its functions.
#[derive(Clone)]
pub(crate) struct ValidatorSet {
  validators: HashMap<[u8; 32], NonZero<u16>>,
  total_weight: NonZero<u16>,
  proposers: Box<[[u8; 32]]>,
}

impl ValidatorSet {
  pub(crate) fn new(validators: HashMap<[u8; 32], NonZero<u16>>) -> Self {
    use ::tendermint::ValidatorSet as _;

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

  fn proposer(
    &self,
    block_number: ::tendermint::BlockNumber,
    round_number: ::tendermint::RoundNumber,
  ) -> Self::Validator {
    let i = ((u64::from(block_number) - 1) % u64::from(u16::from(self.total_weight))) +
      ((u64::from(round_number) - 1) % u64::from(u16::from(self.total_weight)));
    let i = u16::try_from(i % u64::from(u16::from(self.total_weight))).unwrap();
    self.proposers[usize::from(i)]
  }
}
