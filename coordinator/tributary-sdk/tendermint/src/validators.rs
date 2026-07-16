use core::{hash::Hash, fmt::Debug, future::Future, num::NonZero};

use crate::{BlockNumber, RoundNumber};

/// A validator ID.
///
/// This is effectively a trait alias where a potential validator ID is any type which satisfies
/// all of these bounds, and this is implemented for all such types.
///
/// The [`BorshSerialize`] implementation MUST be infallible if the underlying writer is
/// infallible. The [`BorshDeserialize`] implementation MUST be infallible if it is deserializing a
/// value which was successfully serialized, from a well-formed reader.
pub trait Validator: Send + Sync + Clone + Copy + PartialEq + Eq + Hash + Debug {}
impl<V: Send + Sync + Clone + Copy + PartialEq + Eq + Hash + Debug> Validator for V {}

/// A representation of a signature.
///
/// This is effectively a trait alias where a potential representation of a signature is any type
/// which satisfies all of these bounds, and this is implemented for all such types.
///
/// The `AsRef<[u8]>` implementation MUST return a slice with a consistent length for _any_
/// value, meaning it's _constant_.
///
/// The [`BorshSerialize`] implementation MUST be infallible if the underlying writer is
/// infallible. The [`BorshDeserialize`] implementation MUST be infallible if it is deserializing a
/// value which was successfully serialized, from a well-formed reader.
pub trait Signature: Send + Clone + AsRef<[u8]> {}
impl<S: Send + Clone + AsRef<[u8]>> Signature for S {}

/// A representation of an aggregate signature.
///
/// This is effectively a trait alias where a potential representation of an aggregate signature is
/// any type which satisfies all of these bounds, and this is implemented for all such types.
///
/// The [`BorshSerialize`] implementation MUST be infallible if the underlying writer is
/// infallible. The [`BorshDeserialize`] implementation MUST be infallible if it is deserializing a
/// value which was successfully serialized, from a well-formed reader.
pub trait AggregateSignature: Send + Clone + AsRef<[u8]> {}
impl<S: Send + Clone + AsRef<[u8]>> AggregateSignature for S {}

/// The aggregate signature was invalid.
#[derive(Debug)]
pub struct InvalidAggregateSignature;

/// A signer for a validator.
pub trait Signer {
  /// The type used to identify validators.
  type Validator: Validator;
  /// The type used to represent signatures.
  type Signature: Signature;

  /// This validator's ID.
  ///
  /// This MUST be consistent and not change across multiple invocations.
  fn validator(&self) -> impl Send + Future<Output = Self::Validator>;

  /// Sign a signature as this validator.
  ///
  /// The message is the concatenation of each byte slice yielded by the iterator.
  fn sign(
    &self,
    message: impl Send + IntoIterator<Item = impl AsRef<[u8]>>,
  ) -> impl Send + Future<Output = Self::Signature>;
}

impl<S: Signer> Signer for &S {
  type Validator = S::Validator;
  type Signature = S::Signature;

  fn validator(&self) -> impl Send + Future<Output = Self::Validator> {
    S::validator(self)
  }

  fn sign(
    &self,
    message: impl Send + IntoIterator<Item = impl AsRef<[u8]>>,
  ) -> impl Send + Future<Output = Self::Signature> {
    S::sign(self, message)
  }
}

/// The signature scheme used for consensus.
///
/// The implementation MUST inherently provide domain separation such that this can be assumed to
/// never conflict with any other protocol. The messages within the Tendermint process, even across
/// blockchains, will be domain-separated however.
///
/// The signature scheme is assumed binding to the validator signing the message.
pub trait SignatureScheme {
  /// The type used to identify validators.
  type Validator: Validator;
  /// The type used to represent signatures.
  type Signature: Signature;
  /// The type used to represent an aggregate signature.
  ///
  /// This may be a one-round threshold signature, an aggregated BLS signature, a
  /// [half-aggregated Schnorr signature](https://eprint.iacr.org/2021/350) (as implemented in the
  /// [`schnorr-signatures`](https://docs.rs/schnorr-signatures) crate), a succinct proof, or
  /// simply the list of individual signatures (without any actual aggregation). It MUST have the
  /// context over _both_ the participating signers _and_ the signatures however.
  type AggregateSignature: AggregateSignature;

  /// Verify a signature from the validator in question.
  ///
  /// The message is the concatenation of each byte slice yielded by the iterator.
  #[must_use]
  fn verify(
    &self,
    validator: &Self::Validator,
    message: impl IntoIterator<Item = impl AsRef<[u8]>>,
    signature: &Self::Signature,
  ) -> bool;

  /// Aggregate signatures from a set of validators of sum weight satisfying the threshold.
  ///
  /// The message is singular, expected to be consistent across all signatures, and the
  /// concatenation of each byte slice yielded by the iterator.
  ///
  /// This MAY panic if a validator/signature pair is invalid.
  #[must_use]
  fn aggregate<'sig>(
    &self,
    message: impl IntoIterator<Item = impl AsRef<[u8]>>,
    signatures: impl IntoIterator<Item = (&'sig Self::Validator, &'sig Self::Signature)>,
  ) -> Self::AggregateSignature
  where
    Self::Validator: 'sig,
    Self::Signature: 'sig;

  /// Verify an aggregate signature.
  ///
  /// The message is the concatenation of each byte slice yielded by the iterator.
  ///
  /// The return result MUST be the set of validators which participated in producing this
  /// signature (in any order, without multiple inclusions). If this is a threshold signature where
  /// the signing key's reconstruction threshold is equal to Tendermint's threshold, this MAY
  /// return any set of validators with weight greater than or equal to Tendermint's threshold,
  /// even if that set was not necessarily the set which participated in producing the aggregate
  /// signature.
  fn verify_aggregate(
    &self,
    message: impl IntoIterator<Item = impl AsRef<[u8]>>,
    aggregate_signature: &Self::AggregateSignature,
  ) -> Result<impl IntoIterator<Item = Self::Validator>, InvalidAggregateSignature>;
}

impl<S: SignatureScheme> SignatureScheme for &S {
  type Validator = S::Validator;
  type Signature = S::Signature;
  type AggregateSignature = S::AggregateSignature;

  fn verify(
    &self,
    validator: &Self::Validator,
    message: impl IntoIterator<Item = impl AsRef<[u8]>>,
    signature: &Self::Signature,
  ) -> bool {
    S::verify(self, validator, message, signature)
  }

  fn aggregate<'sig>(
    &self,
    message: impl IntoIterator<Item = impl AsRef<[u8]>>,
    signatures: impl IntoIterator<Item = (&'sig Self::Validator, &'sig Self::Signature)>,
  ) -> Self::AggregateSignature
  where
    Self::Validator: 'sig,
    Self::Signature: 'sig,
  {
    S::aggregate(self, message, signatures)
  }

  fn verify_aggregate(
    &self,
    message: impl IntoIterator<Item = impl AsRef<[u8]>>,
    aggregate_signature: &Self::AggregateSignature,
  ) -> Result<impl IntoIterator<Item = Self::Validator>, InvalidAggregateSignature> {
    S::verify_aggregate(self, message, aggregate_signature)
  }
}

/// The set of validators
pub trait ValidatorSet: Sync {
  /// The type used to identify validators.
  type Validator: Validator;

  /// The total weight of all validators.
  ///
  /// If this method is incorrect, the Tendermint process MAY panic or be otherwise incorrect.
  fn total_weight(&self) -> NonZero<u16>;

  /// An iterator over every validator.
  ///
  /// The validators MUST be consistent for the lifetime of this blockchain. However, the order
  /// they're yielded in DOES NOT have to be stable. Every validator MUST have weight in the
  /// consensus process.
  ///
  /// If this method is incorrect, the Tendermint process MAY panic or be otherwise incorrect.
  fn validators(&self) -> impl IntoIterator<Item = &Self::Validator>;

  /// The weight for a specific validator.
  ///
  /// This MUST be consistent for the lifetime of this blockchain.
  ///
  /// If this method is incorrect, the Tendermint process MAY panic or be otherwise incorrect.
  fn weight(&self, validator: &Self::Validator) -> Option<NonZero<u16>>;

  /// The threshold of weight needed for consensus.
  ///
  /// This MUST return a value equal to `((self.total_weight() * 2) / 3) + 1`, as the provided
  /// implementation does.
  fn threshold(&self) -> u16 {
    u16::try_from(((u32::from(u16::from(self.total_weight())) * 2) / 3) + 1)
      .expect("threshold is less than or equal to the total weight, which is a `u16`")
  }

  /// The threshold of weight which may be faulty.
  ///
  /// This MUST return a value equal to `self.total_weight() - self.threshold()`, as the provided
  /// implementation does.
  fn fault_threshold(&self) -> u16 {
    u16::from(self.total_weight()) - self.threshold()
  }

  /// The proposer for this block and round number.
  ///
  /// This MUST be deterministic to these two arguments, `block_number` and `round_number`, and
  /// should presumably be a weighted round robin.
  fn proposer(&self, block_number: BlockNumber, round_number: RoundNumber) -> Self::Validator;
}

impl<V: ValidatorSet> ValidatorSet for &V {
  type Validator = V::Validator;

  fn total_weight(&self) -> NonZero<u16> {
    V::total_weight(self)
  }

  fn validators(&self) -> impl IntoIterator<Item = &Self::Validator> {
    V::validators(self)
  }

  fn weight(&self, validator: &Self::Validator) -> Option<NonZero<u16>> {
    V::weight(self, validator)
  }

  fn proposer(&self, block_number: BlockNumber, round_number: RoundNumber) -> Self::Validator {
    V::proposer(self, block_number, round_number)
  }
}

macro_rules! map {
  ($feature: literal, $map: path, $($generics: tt)*) => {
    #[cfg(feature = $feature)]
    impl<$($generics)*> ValidatorSet for $map {
      type Validator = V;

      /// This MAY panic or be incorrect if the values' sum is zero or is not representable in a
      /// `u16`.
      fn total_weight(&self) -> NonZero<u16> {
        NonZero::new(
          self
            .values()
            .try_fold(0u16, |accum, value| accum.checked_add(u16::from(*value)))
            .unwrap(),
        )
        .unwrap()
      }

      fn validators(&self) -> impl IntoIterator<Item = &Self::Validator> {
        self.keys()
      }

      fn weight(&self, validator: &Self::Validator) -> Option<NonZero<u16>> {
        self.get(validator).copied()
      }

      /// This implements a weighted round robin with the validators ordered by the ordinality of
      /// their IDs. This MAY run in time _superlinear_ to the amount of validators, despite
      /// expecting this to be called upon every block proposal. This MAY only make sense for
      /// _small_ validator sets accordingly. For _large_ validator sets, the representation of a
      /// [`ValidatorSet`] SHOULD cache the order of the round robin as to allow executing this
      /// function with a lookup.
      ///
      /// The round robin is initialized with the block number's as the starting index, regardless
      /// of if prior blocks required multiple rounds to achieve consensus. The round robin is
      /// spaced out such that validators with multiple units of weight are not assigned
      /// simultaneous slots within a single iteration of the round robin _unless_ they have more
      /// weight than all other validators. Each validator's slots are _not_ guaranteed to be
      /// uniformly distributed however and MAY grow in density as the round robin approaches its
      /// tail.
      ///
      /// To ensure a random distribution, a random coin would be needed, which Tendermint does not
      /// require (nor provide). A bespoke [`ValidatorSet`] implementation could make use of one
      /// however. Lacking one, this attempts to provide a slightly more fair distribution (as
      /// detailed above), but this is solely on a best-effort basis.
      /*
        TODO: Should we return a `struct` which caches this to resolve the performance concerns?
        Does that work if someone wishes to use this API in conjunction with a PRF to decide the
        proposer? Does that design work today when we don't bound when we call this?
      */
      fn proposer(&self, block_number: BlockNumber, round_number: RoundNumber) -> Self::Validator {
        const {
          // We need `u16::MAX + 1` to be representable in `usize` and `u16::MAX <= isize::MAX`
          assert!(usize::BITS > 16);
        }

        use alloc::vec::Vec;

        let total_weight = u16::from(self.total_weight());

        let i = usize::from({
          // Initialize the round robin's starting index to the starting index of this block
          let block_i = (u64::from(block_number) - 1) % u64::from(total_weight);
          // Offset by the current round number
          let round_i = (u64::from(round_number) - 1) % u64::from(total_weight);
          let i = (block_i + round_i) % u64::from(total_weight);
          u16::try_from(i).expect(
            "`i` indexes a validator by weight, where the weight is representable in a `u16`",
          )
        });

        let mut all_keys = Vec::with_capacity((i + 2).min(usize::from(total_weight)));
        for (key, value) in self {
          let mut insert_at = 0;
          for weight_i in 0 .. u16::from(*value) {
            /*
              Find the index to insert this such that the list remains sorted after insertion.

              We sort first by this unit of weight, so each validator has a turn before any
              validator has additional turns (proportional to their weight), achieving _some_
              distance between each of a validator's slots. We sort secondarily by the validator's
              ID.

              Note when implemented for a `BTreeMap`, this iteration is actually already sorted by
              the validators, but we don't bother to specialize as we do have a slightly distinct
              sorting criteria.
            */
            match all_keys[insert_at ..].binary_search_by(
              |(existing_weight, existing_key): &(u16, &V)| {
                existing_weight.cmp(&weight_i).then((*existing_key).cmp(key))
              },
            ) {
              // This requires `PartialOrd` disagree with `PartialEq`, which would be an invalid
              // implementation of `PartialOrd` as it MUST be consistent with `PartialEq`
              Ok(_index) => {
                panic!("`binary_search_by` located element despite not being already present")
              }
              Err(insert_at_in_slice) => insert_at += insert_at_in_slice,
            }

            /*
              As we need `all_keys[i]`, we don't need any values _after_ `all_keys[i]`, so we
              optimize accordingly. This doesn't affect the _worst_ case of the round robin, as `i`
              approaches `total_weight`, but does improve the average case.
            */
            if insert_at > i {
              break;
            }

            all_keys.insert(insert_at, (weight_i, key));
            insert_at += 1;

            // If one of the keys we shifted is now so unnecessary, truncate it to reclaim our
            // capacity
            all_keys.truncate(i + 1);
          }
        }

        *all_keys[i].1
      }
    }
  };
}

#[cfg(not(target_pointer_width = "16"))]
map!(
  "alloc",
  alloc::collections::BTreeMap<V, NonZero<u16>>,
  V: PartialOrd + Ord + Validator
);

#[cfg(not(target_pointer_width = "16"))]
map!(
  "std",
  std::collections::HashMap<V, NonZero<u16>, H>,
  V: PartialOrd + Ord + Validator, H: Sync + core::hash::BuildHasher
);

#[cfg(test)]
mod tests {
  use super::*;

  pub(crate) struct TestSignatureScheme(u64, u64);
  impl TestSignatureScheme {
    pub(crate) fn new() -> Self {
      use rand_core::{TryRngCore as _, OsRng};
      Self(OsRng.try_next_u64().unwrap(), OsRng.try_next_u64().unwrap())
    }
  }

  impl TestSignatureScheme {
    fn hash(&self, message: impl IntoIterator<Item = impl AsRef<[u8]>>) -> [u8; 8] {
      /*
        We use this as a non-cryptographically secure hash, as we do not require malicious security
        for these tests, to weakly bind signatures to messages without requiring allocating nor a
        third-party dependency (as needed for a cryptographic hash). Any real signature scheme MUST
        be maliciously secure however.
      */
      #[expect(deprecated)]
      use core::hash::{Hasher as _, SipHasher};

      #[expect(deprecated)]
      let mut hasher = SipHasher::new_with_keys(self.0, self.1);
      for chunk in message {
        for byte in chunk.as_ref() {
          // Write as individual `u8`s to ensure the chunk boundaries don't become part of the hash
          hasher.write_u8(*byte);
        }
      }
      hasher.finish().to_le_bytes()
    }
  }

  impl SignatureScheme for TestSignatureScheme {
    type Validator = u8;
    // The validator concatenated with the 8-byte hash of the message
    type Signature = [u8; 1 + 8];
    // The 256-bit bit set concatenated with the 8-byte hash of the message
    type AggregateSignature = [u8; 32 + 8];

    fn verify(
      &self,
      validator: &<Self as SignatureScheme>::Validator,
      message: impl IntoIterator<Item = impl AsRef<[u8]>>,
      signature: &<Self as SignatureScheme>::Signature,
    ) -> bool {
      (validator == &signature[0]) && (self.hash(message) == signature[1 ..])
    }

    fn aggregate<'sig>(
      &self,
      message: impl IntoIterator<Item = impl AsRef<[u8]>>,
      signatures: impl IntoIterator<
        Item = (
          &'sig <Self as SignatureScheme>::Validator,
          &'sig <Self as SignatureScheme>::Signature,
        ),
      >,
    ) -> <Self as SignatureScheme>::AggregateSignature
    where
      <Self as SignatureScheme>::Validator: 'sig,
      <Self as SignatureScheme>::Signature: 'sig,
    {
      let hash = self.hash(message);
      let mut aggregate_signature = [0; 32 + 8];
      for (validator, signature) in signatures {
        assert!((validator == &signature[0]) && (hash == signature[1 ..]));
        // Create the bit set
        aggregate_signature[usize::from(validator / 8)] |= 1 << (validator % 8);
      }
      aggregate_signature[32 ..].copy_from_slice(&hash);
      aggregate_signature
    }

    fn verify_aggregate(
      &self,
      message: impl IntoIterator<Item = impl AsRef<[u8]>>,
      aggregate_signature: &<Self as SignatureScheme>::AggregateSignature,
    ) -> Result<
      impl IntoIterator<Item = <Self as SignatureScheme>::Validator>,
      InvalidAggregateSignature,
    > {
      let hash = self.hash(message);
      if aggregate_signature[32 ..] != hash {
        Err(InvalidAggregateSignature)?;
      }

      // Decompose the bit set into an iterator of validators who had their bits set
      Ok(
        aggregate_signature[.. 32]
          .iter()
          .enumerate()
          .flat_map(|(i, b)| {
            let i = 8 * u8::try_from(i).unwrap();
            core::array::from_fn::<Option<u8>, 8, _>(|j| {
              ((b & (1 << (j % 8))) != 0)
                .then_some(i.checked_add(u8::try_from(j).unwrap()).unwrap())
            })
          })
          .flatten(),
      )
    }
  }

  pub(crate) struct TestSigner {
    signature_scheme: TestSignatureScheme,
    validator: u8,
  }

  impl TestSignatureScheme {
    pub(crate) fn signer(&self, validator: u8) -> TestSigner {
      TestSigner { signature_scheme: TestSignatureScheme(self.0, self.1), validator }
    }
  }

  impl Signer for TestSigner {
    type Validator = u8;
    type Signature = [u8; 1 + 8];
    fn validator(&self) -> impl Send + Future<Output = <Self as Signer>::Validator> {
      core::future::ready(self.validator)
    }
    fn sign(
      &self,
      message: impl Send + IntoIterator<Item = impl AsRef<[u8]>>,
    ) -> impl Send + Future<Output = <Self as Signer>::Signature> {
      let mut result = [0; 1 + 8];
      result[0] = self.validator;
      result[1 ..].copy_from_slice(&self.signature_scheme.hash(message));
      core::future::ready(result)
    }
  }

  #[test]
  fn signature_scheme() {
    use core::{
      pin::pin,
      task::{Poll, Waker, Context},
    };

    let mut context = Context::from_waker(Waker::noop());

    let message = [[12].as_slice(), &[2], &[3]];
    let other_message = [[].as_slice()];
    let signature_scheme = loop {
      let signature_scheme = TestSignatureScheme::new();
      if signature_scheme.hash(message) == signature_scheme.hash(other_message) {
        continue;
      }
      break signature_scheme;
    };

    let aggregated = [3, 101, 135];
    let mut signatures = [None; 3];
    for validator in 0 ..= u8::MAX {
      let Poll::Ready(signature) =
        pin!(signature_scheme.signer(validator).sign(message)).poll(&mut context)
      else {
        panic!("`TestSignatureScheme::sign` returned `Poll::Pending`")
      };
      assert!(signature_scheme.verify(&validator, message, &signature));
      assert!(!signature_scheme.verify(&validator.wrapping_add(1), message, &signature));
      assert!(!signature_scheme.verify(&validator, other_message, &signature));
      if let Some(i) =
        aggregated.iter().position(|validator_in_list| *validator_in_list == validator)
      {
        signatures[i] = Some((validator, signature));
      }
    }

    let aggregate_signature = signature_scheme.aggregate(
      message,
      signatures.iter().map(|signature| {
        let (validator, signature) = signature.as_ref().unwrap();
        (validator, signature)
      }),
    );

    let mut yielded_aggregated =
      signature_scheme.verify_aggregate(message, &aggregate_signature).unwrap().into_iter();
    let mut aggregated = aggregated.into_iter();
    for (i, j) in (&mut yielded_aggregated).zip(&mut aggregated) {
      assert_eq!(i, j);
    }
    assert!(yielded_aggregated.next().is_none());
    assert!(aggregated.next().is_none());
  }
}
#[cfg(test)]
pub(crate) use tests::*;

#[cfg(all(test, any(feature = "alloc", feature = "std")))]
fn test_map<M: FromIterator<(u16, NonZero<u16>)> + ValidatorSet<Validator = u16>>() {
  let test = |pairs: &[(u16, NonZero<u16>)]| {
    let map = pairs.iter().copied().collect::<M>();

    assert_eq!(
      u16::from(map.total_weight()),
      pairs.iter().map(|(_validator, weight)| u16::from(*weight)).sum::<u16>()
    );

    assert_eq!(
      map.validators().into_iter().copied().collect::<alloc::collections::BTreeSet<_>>(),
      pairs
        .iter()
        .map(|(validator, _weight)| validator)
        .copied()
        .collect::<alloc::collections::BTreeSet<_>>()
    );

    /*
      Cache the list of proposers, which is:
      - the sorted list of validators
      - with inclusions proportional to weight
      - sorted first by the number of the inclusion, then by the validator's key
    */
    let proposers = {
      let mut proposers = alloc::vec::Vec::new();
      for (validator, weight) in pairs.iter().copied() {
        let weight = u16::from(weight);
        for w in 0 .. weight {
          proposers.push((validator, w));
        }
      }
      proposers.sort_by(|(a_validator, a_weight), (b_validator, b_weight)| {
        a_weight.cmp(b_weight).then_with(|| a_validator.cmp(b_validator))
      });
      proposers.into_iter().map(|(validator, _weight)| validator).collect::<alloc::vec::Vec<_>>()
    };

    // `(1, 1)`, which is minimal, maps to the `0`th index (which is minimal)
    assert_eq!(map.proposer(BlockNumber::ONE, RoundNumber::ONE), proposers[0]);

    /*
      Test calls to [`ValidatorSet::proposer`] match indexing into the list, despite the
      [`ValidatorSet::proposer`] function ad-hoc generating the (necessary subset of the) list with
      an optimized implementation.
    */
    for i in 0 .. (2 * proposers.len()) {
      /*
        The proposer should be indexed by the _naïve sum_ of the block and round numbers, so they
        should be interchangeable to request proposers via.

        TODO: Should this be a weighted combination so if `(1, 2)` fails, but `(1, 3)` works, we
        don't immediately retry the same proposal with `(2, 1)`?
      */
      assert_eq!(
        map.proposer(
          BlockNumber::from(NonZero::new(1 + u64::try_from(i).unwrap()).unwrap()),
          RoundNumber::ONE
        ),
        proposers[i % proposers.len()]
      );
      assert_eq!(
        map.proposer(
          BlockNumber::ONE,
          RoundNumber(NonZero::new(1 + u64::try_from(i).unwrap()).unwrap())
        ),
        proposers[i % proposers.len()]
      );
    }

    // Ensure the maximum possible values don't trigger an overflow/panic
    assert_eq!(
      map.proposer(
        BlockNumber::from(NonZero::new(u64::MAX).unwrap()),
        RoundNumber(NonZero::new(u64::MAX).unwrap())
      ),
      proposers[usize::try_from(
        // `- 1`, as the minimal `(1, 1)` corresponds to the minimal `[0]`
        (2 * u128::from(u64::MAX - 1)) % u128::try_from(proposers.len()).unwrap()
      )
      .unwrap()]
    );
  };

  // Test with uniform and randomly-sampled weights
  for weighted in [false, true] {
    // Test from only one validator to 128 validators
    for len in 1 .. 128 {
      test(
        &(1 ..= len)
          .map(|i| {
            let weight = if weighted {
              use rand_core::{TryRngCore as _, OsRng};
              NonZero::new(u16::try_from(1 + (OsRng.try_next_u64().unwrap() % 16)).unwrap())
                .unwrap()
            } else {
              NonZero::new(1).unwrap()
            };
            (i, weight)
          })
          .collect::<alloc::vec::Vec<_>>(),
      );
    }
  }
}
#[cfg(feature = "alloc")]
#[test]
fn test_btree_map() {
  test_map::<alloc::collections::BTreeMap<u16, NonZero<u16>>>();
}
#[cfg(feature = "std")]
#[test]
fn test_hash_map() {
  test_map::<std::collections::HashMap<u16, NonZero<u16>>>();
}
