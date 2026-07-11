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
#[expect(private_bounds)]
pub trait Validator:
  Send + Sync + Clone + Copy + PartialEq + Eq + Hash + Debug + crate::Borshy
{
}
impl<V: Send + Sync + Clone + Copy + PartialEq + Eq + Hash + Debug + crate::Borshy> Validator
  for V
{
}

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
#[expect(private_bounds)]
pub trait Signature: Send + Sync + Clone + AsRef<[u8]> + crate::Borshy {}
impl<S: Send + Sync + Clone + AsRef<[u8]> + crate::Borshy> Signature for S {}

/// A representation of an aggregate signature.
///
/// This is effectively a trait alias where a potential representation of an aggregate signature is
/// any type which satisfies all of these bounds, and this is implemented for all such types.
///
/// The [`BorshSerialize`] implementation MUST be infallible if the underlying writer is
/// infallible. The [`BorshDeserialize`] implementation MUST be infallible if it is deserializing a
/// value which was successfully serialized, from a well-formed reader.
#[expect(private_bounds)]
pub trait AggregateSignature: Send + Sync + Clone + AsRef<[u8]> + crate::Borshy {}
impl<S: Send + Sync + Clone + AsRef<[u8]> + crate::Borshy> AggregateSignature for S {}

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
  /// they're yielded in DOES NOT have to be stable.
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

map!(
  "alloc",
  alloc::collections::BTreeMap<V, NonZero<u16>>,
  V: PartialOrd + Ord + Validator
);

map!(
  "std",
  std::collections::HashMap<V, NonZero<u16>, H>,
  V: PartialOrd + Ord + Validator, H: Sync + core::hash::BuildHasher
);
