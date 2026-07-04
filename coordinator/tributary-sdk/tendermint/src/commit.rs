use crate::{BlockNumber, RoundNumber, ValidatorSet, SignatureScheme, Signer};

/// A commit for a specific block.
///
/// In order for this to be valid, the list of validators MUST have weight exceeding the threshold
/// and the signature MUST be valid.
#[cfg(feature = "alloc")]
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

  /// The validators which participated in creating this commit.
  ///
  /// This is not a canonical list and there may be multiple valid commits, for the same block,
  /// with differing `validators`, without a break in soundness.
  pub(crate) validators: alloc::vec::Vec<S::Validator>,

  /// The aggregate signature to confirm the listed validators actually signed this commit.
  pub(crate) aggregate_signature: S::AggregateSignature,
}

#[cfg(feature = "alloc")]
impl<S: SignatureScheme<AggregateSignature: Clone>> Clone for Commit<S> {
  fn clone(&self) -> Self {
    Self {
      block_number: self.block_number,
      round_number: self.round_number,
      validators: self.validators.clone(),
      aggregate_signature: self.aggregate_signature.clone(),
    }
  }
}

/// A commit for a specific block.
///
/// In order for this to be valid, the list of validators MUST have weight exceeding the threshold
/// and the signature MUST be valid.
#[cfg(not(feature = "alloc"))]
#[derive(Debug, Clone)]
pub struct Commit<S: SignatureScheme> {
  /*
    Preserve the struct definition on `alloc`, for the methods which do not take a `self`
    parameter, but prevent it from being constructed as we do need `alloc` for this.
  */
  _never: core::convert::Infallible,
  _signature_scheme: core::marker::PhantomData<S>,
}

impl<S: SignatureScheme> Commit<S> {
  /// The block number this commit is for.
  #[cfg(feature = "alloc")]
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
  #[cfg(feature = "alloc")]
  #[must_use]
  pub fn verify(
    &self,
    validators: &impl ValidatorSet<Validator = S::Validator>,
    signature_scheme: &S,
    genesis: impl Send + Sync + AsRef<[u8]>,
    block_hash: impl Send + Sync + AsRef<[u8]>,
  ) -> bool {
    /*
      Ensure no validators were present multiple times.

      When `std` is enabled, we use a `HashSet` to perform this check with complexity presumed
      `O(n log n)`. When `std` isn't enabled, we iterate over the allocation to perform this check
      with `O(n^2)` complexity.

      As we assume `alloc`, we _could_ use a `BTreeSet` to still achieve `O(n log n)` complexity
      (ignoring the DoS concerns). This is a fine trade-off for a restricted environment though.
    */
    #[cfg(feature = "std")]
    {
      if self.validators.iter().collect::<std::collections::HashSet<_>>().len() !=
        self.validators.len()
      {
        return false;
      }
    }
    #[cfg(not(feature = "std"))]
    {
      for v in 0 .. self.validators.len() {
        for w in (v + 1) .. self.validators.len() {
          if self.validators[v] == self.validators[w] {
            return false;
          }
        }
      }
    }

    // Ensure the signature was valid
    if !signature_scheme.verify_aggregate(
      &self.validators,
      Self::signature_message(genesis, self.block_number, self.round_number, block_hash),
      &self.aggregate_signature,
    ) {
      return false;
    }

    // Ensure every listed validator was in fact a validator and their weight exceeds the threshold
    self
      .validators
      .iter()
      .try_fold(0u16, |accum, validator| {
        validators.weight(validator).map(|weight| accum + u16::from(weight))
      })
      .is_some_and(|sum| sum >= validators.threshold())
  }
}
