use crate::{BlockNumber, RoundNumber, Validator, ValidatorSet, SignatureScheme, Signer};

/// A commit for a specific block.
///
/// In order for this to be valid, the signature MUST be valid and aggregated from signatures by
/// validators whose weight passes the threshold.
#[derive(Debug)]
#[cfg_attr(feature = "alloc", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct Commit<S: SignatureScheme> {
  /// The block number this is a commit for.
  pub(crate) block_number: BlockNumber,

  /// The round number which is produced a commit.
  ///
  /// This is not a canonical round number and there may be multiple valid commits, for the same
  /// block, with differing `round_number` values, without a break in soundness.
  pub(crate) round_number: RoundNumber,

  /// The aggregate signature by the validators used to create this commit.
  pub(crate) aggregate_signature: S::AggregateSignature,
}

impl<S: SignatureScheme<AggregateSignature: Clone>> Clone for Commit<S> {
  fn clone(&self) -> Self {
    Self {
      block_number: self.block_number,
      round_number: self.round_number,
      aggregate_signature: self.aggregate_signature.clone(),
    }
  }
}

/// Check if a list of validators have a sum weight satisfying the threshold.
///
/// This returns `false` if any validator present was not actually a validator. This DOES NOT check
/// the validators were unique however.
#[must_use]
pub(crate) fn validators_satisfy_threshold<V: Validator>(
  validators: impl IntoIterator<Item = V>,
  validator_set: impl ValidatorSet<Validator = V>,
) -> bool {
  // Ensure every validator is in fact a validator and their sum weight satisfies the threshold
  validators
    .into_iter()
    .try_fold(0u16, |accum, validator| {
      validator_set.weight(&validator).map(|weight| accum + u16::from(weight))
    })
    .is_some_and(|sum| sum >= validator_set.threshold())
}

impl<S: SignatureScheme> Commit<S> {
  /// The block number this commit is for.
  #[must_use]
  pub fn block_number(&self) -> BlockNumber {
    self.block_number
  }

  #[must_use]
  pub(crate) fn signature_message(
    genesis: impl Send + Sync + AsRef<[u8]>,
    block_number: BlockNumber,
    round_number: RoundNumber,
    block_hash: impl Send + Sync + AsRef<[u8]>,
  ) -> [impl Send + AsRef<[u8]>; 5] {
    enum Segment<G: AsRef<[u8]>, B: AsRef<[u8]>> {
      Dst([u8; 1]),
      Genesis(G),
      U64([u8; 8]),
      Block(B),
    }
    impl<G: AsRef<[u8]>, B: AsRef<[u8]>> AsRef<[u8]> for Segment<G, B> {
      fn as_ref(&self) -> &[u8] {
        match self {
          Self::Dst(dst) => dst.as_slice(),
          Self::Genesis(genesis) => genesis.as_ref(),
          Self::U64(number) => number.as_slice(),
          Self::Block(block_hash) => block_hash.as_ref(),
        }
      }
    }

    [
      Segment::Dst([0]),
      Segment::Dst([u8::try_from(genesis.len()).unwrap()]),
      Segment::Genesis(genesis),
      Segment::U64(u64::from(block_number.0).to_le_bytes()),
      Segment::U64(u64::from(round_number.0).to_le_bytes()),
      Segment::Block(block_hash),
    ]
  }

  #[must_use]
  pub(crate) async fn sign(
    signer: &impl Signer<Signature = <S as SignatureScheme>::Signature>,
    genesis: impl Send + Sync + AsRef<[u8]>,
    block_number: BlockNumber,
    round_number: RoundNumber,
    block_hash: impl Send + Sync + AsRef<[u8]>,
  ) -> <S as SignatureScheme>::Signature {
    signer.sign(Self::signature_message(genesis, block_number, round_number, block_hash)).await
  }

  #[must_use]
  pub(crate) fn verify_precommit(
    signature_scheme: &S,
    validator: &S::Validator,
    genesis: impl Send + Sync + AsRef<[u8]>,
    block_number: BlockNumber,
    round_number: RoundNumber,
    block_hash: impl Send + Sync + AsRef<[u8]>,
    signature: &S::Signature,
  ) -> bool {
    signature_scheme.verify(
      validator,
      Self::signature_message(genesis, block_number, round_number, block_hash),
      signature,
    )
  }

  /// Verify a commit.
  #[must_use]
  pub fn verify(
    &self,
    validator_set: &impl ValidatorSet<Validator = S::Validator>,
    signature_scheme: &S,
    genesis: impl Send + Sync + AsRef<[u8]>,
    block_hash: impl Send + Sync + AsRef<[u8]>,
  ) -> bool {
    // Ensure the signature was valid
    let Ok(validators) = signature_scheme.verify_aggregate(
      Self::signature_message(genesis, self.block_number, self.round_number, block_hash),
      &self.aggregate_signature,
    ) else {
      return false;
    };

    // Ensure the signers satisfy the threshold
    validators_satisfy_threshold(validators, validator_set)
  }
}
