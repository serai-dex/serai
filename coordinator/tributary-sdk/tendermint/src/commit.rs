use crate::{
  BlockNumber, RoundNumber, Validator, ValidatorSet, AggregateSignature, SignatureScheme, Signer,
  Blockchain,
};

/// A commit for a specific block.
///
/// In order for this to be valid, the signature MUST be valid and aggregated from signatures by
/// validators whose weight is sufficient for the threshold. Deserialization or instantiation alone
/// DOES NOT signify validity.
#[derive(Debug)]
#[cfg_attr(feature = "alloc", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct Commit<A: AggregateSignature> {
  /// The block number this is a commit for.
  pub(crate) block_number: BlockNumber,

  /// The round number which produced this commit.
  ///
  /// This is not a canonical round number and there may be multiple valid commits, for the same
  /// block, with differing `round_number` values without implying a break in soundness. This is
  /// only here to provide separation such that precommits from distinct rounds cannot be used in
  /// conjunction with each other.
  pub(crate) round_number: RoundNumber,

  /// The aggregate signature for the validators used to create this commit.
  pub(crate) aggregate_signature: A,
}

/// The [`Commit`] type for a [`Blockchain`].
pub type CommitFor<B> =
  Commit<<<B as Blockchain>::SignatureScheme as SignatureScheme>::AggregateSignature>;

impl<A: AggregateSignature> Clone for Commit<A> {
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
  validator_set: &impl ValidatorSet<Validator = V>,
) -> bool {
  // Ensure every validator is in fact a validator and their sum weight satisfies the threshold
  validators
    .into_iter()
    .try_fold(0u16, |accum, validator| {
      validator_set.weight(&validator).and_then(|weight| accum.checked_add(u16::from(weight)))
    })
    .is_some_and(|sum| sum >= validator_set.threshold())
}

impl<A: AggregateSignature> Commit<A> {
  /// The block number this commit is for.
  #[must_use]
  pub fn block_number(&self) -> BlockNumber {
    self.block_number
  }

  #[must_use]
  pub(crate) fn signature_message(
    genesis: impl AsRef<[u8]>,
    block_number: BlockNumber,
    round_number: RoundNumber,
    block_hash: impl AsRef<[u8]>,
  ) -> impl IntoIterator<Item = impl AsRef<[u8]>> {
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
      /*
        Length-prefix the genesis to prevent one genesis from being a valid prefix of another,
        breaking the intended domain separation of this.
      */
      Segment::Dst([u8::try_from(genesis.as_ref().len()).unwrap()]),
      Segment::Genesis(genesis),
      Segment::U64(u64::from(block_number.0).to_le_bytes()),
      Segment::U64(u64::from(round_number.0).to_le_bytes()),
      /*
        This doesn't length-prefix the block hash as it's presumably fixed-length and is definitely
        unnecessary.
      */
      Segment::Block(block_hash),
    ]
  }

  #[must_use]
  pub(crate) async fn sign<S: SignatureScheme<AggregateSignature = A>>(
    signer: &impl Signer<Signature = <S as SignatureScheme>::Signature>,
    genesis: impl Send + AsRef<[u8]>,
    block_number: BlockNumber,
    round_number: RoundNumber,
    block_hash: impl Send + AsRef<[u8]>,
  ) -> <S as SignatureScheme>::Signature {
    signer.sign(Self::signature_message(genesis, block_number, round_number, block_hash)).await
  }

  #[must_use]
  pub(crate) fn verify_precommit<S: SignatureScheme<AggregateSignature = A>>(
    signature_scheme: &S,
    validator: &S::Validator,
    genesis: impl AsRef<[u8]>,
    block_number: BlockNumber,
    round_number: RoundNumber,
    block_hash: impl AsRef<[u8]>,
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
  pub fn verify<S: SignatureScheme<AggregateSignature = A>>(
    &self,
    validator_set: &impl ValidatorSet<Validator = S::Validator>,
    signature_scheme: &S,
    genesis: impl AsRef<[u8]>,
    block_hash: impl AsRef<[u8]>,
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

#[cfg(test)]
mod tests {
  use super::*;

  struct RandomCommit {
    genesis_len: u8,
    #[expect(clippy::as_conversions)]
    genesis: [u8; u8::MAX as usize],

    block_number: BlockNumber,
    round_number: RoundNumber,

    block_hash_len: u16,
    #[expect(clippy::as_conversions)]
    block_hash: [u8; u16::MAX as usize],
  }

  impl RandomCommit {
    fn new() -> Self {
      use core::num::NonZero;
      use rand_core::{TryRngCore as _, OsRng};

      #[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
      let genesis_len = OsRng.try_next_u64().unwrap() as u8;
      #[expect(clippy::as_conversions)]
      let mut genesis = [0xff; u8::MAX as usize];
      OsRng.try_fill_bytes(&mut genesis[.. usize::from(genesis_len)]).unwrap();

      let block_number =
        BlockNumber(NonZero::new(OsRng.try_next_u64().unwrap().saturating_add(1)).unwrap());
      let round_number =
        RoundNumber(NonZero::new(OsRng.try_next_u64().unwrap().saturating_add(1)).unwrap());

      #[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
      let block_hash_len = OsRng.try_next_u64().unwrap() as u16;
      #[expect(clippy::as_conversions, clippy::large_stack_arrays)]
      let mut block_hash = [0xff; u16::MAX as usize];
      OsRng.try_fill_bytes(&mut block_hash[.. usize::from(block_hash_len)]).unwrap();

      Self { genesis_len, genesis, block_number, round_number, block_hash_len, block_hash }
    }

    fn genesis(&self) -> &[u8] {
      &self.genesis[.. usize::from(self.genesis_len)]
    }

    fn block_hash(&self) -> &[u8] {
      &self.block_hash[.. usize::from(self.block_hash_len)]
    }
  }

  #[cfg(feature = "alloc")]
  #[test]
  fn signature_message() {
    for _ in 0 .. 128 {
      let commit = RandomCommit::new();

      let expected = [
        [0].as_slice(),
        &[commit.genesis_len],
        commit.genesis(),
        &u64::from(commit.block_number).to_le_bytes(),
        &u64::from(commit.round_number).to_le_bytes(),
        commit.block_hash(),
      ]
      .concat();

      let mut concatenated = alloc::vec![];
      for chunk in Commit::<
        <crate::TestSignatureScheme as SignatureScheme>::AggregateSignature
      >::signature_message(
        commit.genesis(),
        commit.block_number,
        commit.round_number,
        commit.block_hash(),
      ) {
        concatenated.extend(chunk.as_ref());
      }

      assert_eq!(expected, concatenated);
    }
  }

  #[test]
  fn sign_and_verify_precommit() {
    use core::{
      pin::pin,
      task::{Poll, Waker, Context},
      future::Future as _,
    };

    use crate::TestSignatureScheme;

    let mut context = Context::from_waker(Waker::noop());
    let signature_scheme = TestSignatureScheme::new();

    for i in 0 .. u8::MAX {
      let signer = signature_scheme.signer(i);
      let commit = RandomCommit::new();
      let Poll::Ready(mut signature) = pin!(Commit::<
        <TestSignatureScheme as SignatureScheme>::AggregateSignature,
      >::sign::<TestSignatureScheme>(
        &signer,
        commit.genesis(),
        commit.block_number,
        commit.round_number,
        commit.block_hash(),
      ))
      .poll(&mut context) else {
        panic!("`TestSignatureScheme::sign` returned `Poll::Pending`")
      };
      assert!(
        Commit::<<TestSignatureScheme as SignatureScheme>::AggregateSignature>::verify_precommit(
          &signature_scheme,
          &i,
          commit.genesis(),
          commit.block_number,
          commit.round_number,
          commit.block_hash(),
          &signature
        )
      );
      signature[0] ^= 1;
      assert!(
        !Commit::<<TestSignatureScheme as SignatureScheme>::AggregateSignature>::verify_precommit(
          &signature_scheme,
          &i,
          commit.genesis(),
          commit.block_number,
          commit.round_number,
          commit.block_hash(),
          &signature
        )
      );
    }
  }
}
