use alloc::vec::Vec;

use borsh::{io, BorshSerialize, BorshDeserialize};

use sp_core::{ConstU32, bounded::BoundedVec};
use serai_primitives::{
  BitVec,
  crypto::{EmbeddedEllipticCurveKeys, SignedEmbeddedEllipticCurveKeys, KeyPair, Signature},
  address::SeraiAddress,
  balance::Amount,
  network_id::*,
  validator_sets::*,
};

pub use serai_primitives::validator_sets::DeallocationTimeline;

/// The address used by the validator sets pallet.
pub fn address() -> SeraiAddress {
  SeraiAddress::system(borsh::to_vec(b"ValidatorSets").unwrap())
}

/// Slash(es) to occur on-chain.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Slashes {
  /// A single slash for a specific validator of the Serai network.
  Serai {
    /// The validator being slashed.
    validator: SeraiAddress,
    /// The reason for the slash, represented as an opaque byte blob.
    ///
    /// This reason is not validated on-chain. Instead, with a trust assumption the validator set
    /// for Serai is honest, an inherent transaction is used (where the Serai validators will only
    /// build on a block which includes it if they agree with it). Not only is this reasonable, and
    /// a trust assumption already in place for validators of external networks, it avoids binding
    /// to the BABE/GRANDPA equivocation proofs within the on-chain protocol.
    ///
    /// The byte blob is present so a validator who observed a fault may effectively communicate it
    /// to the other validators. It also has the benefit of allowing public inspection of the
    /// reason.
    ///
    /// The reason being limited to `u16::MAX` does mean an equivocation proof larger than 64 KiB
    /// cannot be communicated in this method. As an equivocation proof, as defined in
    /// [`sp-consensus-babe`], is primarily a pair of headers, Serai benefits from having defined a
    /// fixed-size header (removing the `Digest` from its canonical wire format). This allows
    /// representing an `EquivocationProof` not with [`SubstrateHeader`] but
    /// `(Header, Digest::new(substrate_header.digest().find(babe)))` which can be of bounded
    /// length even while the digest as a whole remains unbounded (its own sin).
    #[expect(clippy::as_conversions)]
    reason: BoundedVec<u8, ConstU32<{ u16::MAX as u32 }>>,
  },
  /// A [`SlashReport`] from an external network.
  ExternalNetwork {
    /// The validator set which is reporting their slashes.
    set: ExternalValidatorSet,
    /// The slashes they're reporting.
    slashes: SlashReport,
    /// The signature confirming the validity of this slash report.
    ///
    /// This is defined as a `Signature`. This may change in the future, as while `Signature` may
    /// be the type used to sign transactions, this signature must support efficient proving by a
    /// multi-party protocol. While currently, both concepts can be fulfilled by
    /// `RistrettoSignature` (as versioned by `Signature`), in the future, potential upgrades may
    /// diverge.
    signature: Signature,
  },
}

impl BorshSerialize for Slashes {
  fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    match self {
      Slashes::Serai { validator, reason } => {
        (NetworkId::Serai, validator).serialize(writer)?;
        serai_primitives::sp_borsh::borsh_serialize_bounded_vec(reason, writer)
      }
      Slashes::ExternalNetwork { set, slashes, signature } => {
        (set, slashes, signature).serialize(writer)
      }
    }
  }
}

impl BorshDeserialize for Slashes {
  fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    Ok(match NetworkId::deserialize_reader(reader)? {
      NetworkId::Serai => Slashes::Serai {
        validator: <_>::deserialize_reader(reader)?,
        reason: serai_primitives::sp_borsh::borsh_deserialize_bounded_vec(reader)?,
      },
      NetworkId::External(network) => Slashes::ExternalNetwork {
        set: ExternalValidatorSet { network, session: <_>::deserialize_reader(reader)? },
        slashes: <_>::deserialize_reader(reader)?,
        signature: <_>::deserialize_reader(reader)?,
      },
    })
  }
}

/// A call to the validator sets module.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum Call {
  /// Set the keys for a validator set.
  set_keys {
    /// The network whose latest decided validator set is setting their keys.
    network: ExternalNetworkId,
    /// The keys being set.
    key_pair: KeyPair,
    /// The participants in the validator set who signed off on these keys.
    signature_participants: BitVec<{ KeyShares::MAX_PER_SET_U64 }>,
    /// The signature confirming these keys are valid.
    ///
    /// This is defined as a `Signature`. This may change in the future, as while `Signature` may
    /// be the type used to sign transactions, this signature must support verification for a
    /// non-interactive aggregate key of the participating validators. While currently, both
    /// concepts can be fulfilled by `RistrettoSignature` (as versioned by `Signature`), in the
    /// future, potential upgrades may diverge.
    signature: Signature,
  },
  /// Report a validator set's slashes onto Serai.
  report_slashes(Slashes),
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

/// A summary of the slashes reported.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ReportedSlashes {
  /// A single Serai validator was fatally slashed.
  SeraiValidator(SeraiAddress),
  /// A slash report was published for an external network's validator set.
  ExternalValidatorSet(ExternalValidatorSet),
}

impl BorshSerialize for ReportedSlashes {
  fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    match self {
      ReportedSlashes::SeraiValidator(address) => (NetworkId::Serai, address).serialize(writer),
      ReportedSlashes::ExternalValidatorSet(set) => set.serialize(writer),
    }
  }
}

impl BorshDeserialize for ReportedSlashes {
  fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    Ok(match NetworkId::deserialize_reader(reader)? {
      NetworkId::Serai => {
        ReportedSlashes::SeraiValidator(SeraiAddress::deserialize_reader(reader)?)
      }
      NetworkId::External(network) => ReportedSlashes::ExternalValidatorSet(ExternalValidatorSet {
        network,
        session: Session::deserialize_reader(reader)?,
      }),
    })
  }
}

/// An event from the validator sets module.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum Event {
  /// A new validator set was decided.
  SetDecided {
    /// The set decided.
    set: ValidatorSet,
    /// The validators decided to be included in the set.
    validators: Vec<(SeraiAddress, KeyShares)>,
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
  /// A marker event for a slash or slashes having occured.
  Slashes(ReportedSlashes),
  /// A validator set their keys on an embedded elliptic curve for a network.
  SetEmbeddedEllipticCurveKeys {
    /// The validator which set their keys.
    validator: SeraiAddress,
    /// The embedded elliptic curve keys they set.
    keys: EmbeddedEllipticCurveKeys,
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

#[test]
fn serialize_slashes() {
  use alloc::{vec, vec::Vec};
  use rand_core::{RngCore as _, OsRng};
  use serai_primitives::crypto::RistrettoSignature;

  let external_networks = ExternalNetworkId::all().collect::<Vec<_>>();

  for _ in 0 .. 1000 {
    {
      let mut validator = [0; 32];
      OsRng.fill_bytes(&mut validator);
      let validator = SeraiAddress(validator);

      {
        let mut reason =
          vec![0u8; usize::try_from(OsRng.next_u64() % u64::from(u16::MAX)).unwrap()];
        OsRng.fill_bytes(&mut reason);

        let slashes = Slashes::Serai { validator, reason: reason.try_into().unwrap() };

        assert_eq!(
          slashes,
          Slashes::deserialize_reader(&mut borsh::to_vec(&slashes).unwrap().as_slice()).unwrap()
        );
      }
      {
        let reported = ReportedSlashes::SeraiValidator(validator);
        assert_eq!(
          reported,
          ReportedSlashes::deserialize_reader(&mut borsh::to_vec(&reported).unwrap().as_slice())
            .unwrap()
        );
      }
    }

    {
      #[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
      let network = external_networks[(OsRng.next_u64() as usize) % external_networks.len()];
      #[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
      let session = Session(OsRng.next_u64() as u32);
      let set = ExternalValidatorSet { network, session };

      {
        let mut slashes = vec![];
        for _ in 0 .. (OsRng.next_u64() % KeyShares::MAX_PER_SET_U64) {
          if (OsRng.next_u64() & 1) == 1 {
            slashes.push(Slash::Fatal);
          } else {
            #[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
            slashes.push(Slash::Points(OsRng.next_u64() as u32));
          }
        }
        let slashes = SlashReport(slashes.try_into().unwrap());

        let mut signature = [0; 64];
        OsRng.fill_bytes(&mut signature);
        let signature = Signature::from(RistrettoSignature(signature));

        let slashes = Slashes::ExternalNetwork { set, slashes, signature };

        assert_eq!(
          slashes,
          Slashes::deserialize_reader(&mut borsh::to_vec(&slashes).unwrap().as_slice()).unwrap()
        );
      }
      {
        let reported = ReportedSlashes::ExternalValidatorSet(set);
        assert_eq!(
          reported,
          ReportedSlashes::deserialize_reader(&mut borsh::to_vec(&reported).unwrap().as_slice())
            .unwrap()
        );
      }
    }
  }
}

#[cfg(feature = "substrate")]
#[test]
fn babe_grandpa_equivocation_lengths() {
  use scale::MaxEncodedLen as _;
  use sp_runtime::traits::Header as HeaderTrait;
  use crate::{Header, SubstrateHeader};

  // Check two headers, as part of an equivocation proof, fit within a slash's reason once encoded
  {
    let two_serai_headers_with_babe_digest =
      2 * (Header::SIZE + sp_consensus_babe::digests::PreDigest::max_encoded_len());
    // We check we have a wide margin
    assert!(two_serai_headers_with_babe_digest < usize::from(u16::MAX / 2));
  }

  // For GRANDPA, the equivocation does not implement `MaxEncodedLen` but does not contain any
  // heap-allocated types (such as `Digest`), so we simplify to a `size_of` with an even more
  // aggressive bound. We should be _well_ below this regardless
  {
    let grandpa_equivocation = core::mem::size_of::<
      sp_consensus_grandpa::EquivocationProof<
        <SubstrateHeader as HeaderTrait>::Hash,
        <SubstrateHeader as HeaderTrait>::Number,
      >,
    >();
    assert!(grandpa_equivocation < usize::from(u16::MAX / 64));
  }
}
