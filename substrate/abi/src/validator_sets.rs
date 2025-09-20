use borsh::{BorshSerialize, BorshDeserialize};

use serai_primitives::{
  crypto::{SignedEmbeddedEllipticCurveKeys, KeyPair, Signature},
  address::SeraiAddress,
  balance::Amount,
  network_id::*,
  validator_sets::*,
};

/// A call to the validator sets.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum Call {
  /// Set the keys for a validator set.
  set_keys {
    /// The validator set which is setting their keys.
    validator_set: ExternalValidatorSet,
    /// The keys being set.
    key_pair: KeyPair,
    /// The participants in the validator set who signed off on these keys.
    // TODO: Bound
    #[borsh(
      serialize_with = "serai_primitives::sp_borsh::borsh_serialize_bitvec",
      deserialize_with = "serai_primitives::sp_borsh::borsh_deserialize_bitvec"
    )]
    signature_participants: bitvec::vec::BitVec<u8, bitvec::order::Lsb0>,
    /// The signature confirming these keys are valid.
    signature: Signature,
  },
  /// Report a validator set's slashes onto Serai.
  report_slashes {
    /// The validator set which is setting their keys.
    validator_set: ExternalValidatorSet,
    /// The slashes they're reporting.
    slashes: SlashReport,
    /// The signature confirming the validity of this slash report.
    signature: Signature,
  },
  /// Set a validator's keys on embedded elliptic curves for a specific network.
  set_embedded_elliptic_curve_keys {
    /// The keys on the embedded elliptic curves.
    keys: SignedEmbeddedEllipticCurveKeys,
  },
  /// Allocate stake to a network.
  allocate {
    /// The network to allocate stake to.
    network: NetworkId,
    /// The amount of stake to allocate.
    amount: Amount,
  },
  /// Deallocate stake from a network.
  ///
  /// This deallocation may be immediate or may be delayed depending on if the origin is an
  /// active, or even recent, validator. If delayed, it will have to be claimed at a later time.
  deallocate {
    /// The network to deallocate stake from.
    network: NetworkId,
    /// The amount of stake to deallocate.
    amount: Amount,
  },
  /// Claim a now-unlocked deallocation.
  claim_deallocation {
    /// The validator set which claiming the deallocation was delayed until.
    deallocation: ValidatorSet,
  },
}

impl Call {
  pub(crate) fn is_signed(&self) -> bool {
    match self {
      Call::set_keys { .. } | Call::report_slashes { .. } => false,
      Call::set_embedded_elliptic_curve_keys { .. } |
      Call::allocate { .. } |
      Call::deallocate { .. } |
      Call::claim_deallocation { .. } => true,
    }
  }
}

/// The timeline for a deallocation.
#[derive(Clone, Copy, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum DeallocationTimeline {
  /// The deallocation is available immediately.
  Immediate,
  /// The dealocation was delayed.
  Delayed {
    /// The session the deallocation unlocks at and can be claimed.
    unlocks_at: Session,
  },
}

/// An event from the validator sets.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum Event {
  /// A new validator set was decided.
  SetDecided {
    /// The set decided.
    set: ValidatorSet,
  },
  /// A validator set has set their keys.
  SetKeys {
    /// The set which set their keys.
    set: ExternalValidatorSet,
    /// The keys sets.
    key_pair: KeyPair,
  },
  /// A validator set has accepted responsibility from the prior validator set.
  AcceptedHandover {
    /// The set which accepted responsibility from the prior set.
    set: ValidatorSet,
  },
  /// A validator set their keys on an embedded elliptic curve for a network.
  SetEmbeddedEllipticCurveKeys {
    /// The validator which set their keys.
    validator: SeraiAddress,
    /// The network which they set embedded elliptic curve keys for.
    network: ExternalNetworkId,
  },
  /// A validator's allocation to a network has increased.
  Allocation {
    /// The validator who increased their allocation.
    validator: SeraiAddress,
    /// The network the stake was allocated to.
    network: NetworkId,
    /// The amount of stake allocated.
    amount: Amount,
  },
  /// A validator's allocation to a network has decreased.
  Deallocation {
    /// The validator who decreased their allocation.
    validator: SeraiAddress,
    /// The network the stake was deallocated from.
    network: NetworkId,
    /// The amount of stake deallocated.
    amount: Amount,
    /// The timeline for this deallocation.
    timeline: DeallocationTimeline,
  },
  /// A validator's delayed deallocation from a network has been claimed.
  DelayedDeallocationClaimed {
    /// The validator who claimed their deallocation.
    validator: SeraiAddress,
    /// The validator set the deallocation was delayed until.
    deallocation: ValidatorSet,
  },
}
