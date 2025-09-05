use zeroize::Zeroize;
use borsh::{io, BorshSerialize, BorshDeserialize};

use sp_core::{ConstU32, bounded::BoundedVec};

use ciphersuite::{
  group::{ff::FromUniformBytes, GroupEncoding},
  WrappedGroup, GroupCanonicalEncoding,
};
use embedwards25519::Embedwards25519;
use secq256k1::Secq256k1;
use schnorr_signatures::SchnorrSignature;

use crate::network_id::ExternalNetworkId;

/// A Ristretto public key.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
  feature = "non_canonical_scale_derivations",
  derive(
    scale::Encode,
    scale::Decode,
    scale::MaxEncodedLen,
    scale::DecodeWithMemTracking,
    scale_info::TypeInfo
  )
)]
pub struct Public(pub [u8; 32]);
impl From<sp_core::sr25519::Public> for Public {
  fn from(public: sp_core::sr25519::Public) -> Self {
    Self(public.0)
  }
}
impl From<Public> for sp_core::sr25519::Public {
  fn from(public: Public) -> Self {
    Self::from_raw(public.0)
  }
}

/// A sr25519 signature.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
  feature = "non_canonical_scale_derivations",
  derive(
    scale::Encode,
    scale::Decode,
    scale::MaxEncodedLen,
    scale::DecodeWithMemTracking,
    scale_info::TypeInfo
  )
)]
pub struct Signature(pub [u8; 64]);
impl From<schnorrkel::Signature> for Signature {
  fn from(signature: schnorrkel::Signature) -> Self {
    Self(signature.to_bytes())
  }
}
impl From<sp_core::sr25519::Signature> for Signature {
  fn from(signature: sp_core::sr25519::Signature) -> Self {
    Self(signature.0)
  }
}
impl From<Signature> for sp_core::sr25519::Signature {
  fn from(signature: Signature) -> Self {
    Self::from_raw(signature.0)
  }
}

/// A key for an external network.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
  feature = "non_canonical_scale_derivations",
  derive(
    scale::Encode,
    scale::Decode,
    scale::MaxEncodedLen,
    scale::DecodeWithMemTracking,
    scale_info::TypeInfo
  )
)]
pub struct ExternalKey(
  #[borsh(
    serialize_with = "crate::borsh_serialize_bounded_vec",
    deserialize_with = "crate::borsh_deserialize_bounded_vec"
  )]
  pub BoundedVec<u8, ConstU32<{ ExternalKey::MAX_LEN }>>,
);

impl AsRef<[u8]> for ExternalKey {
  fn as_ref(&self) -> &[u8] {
    self.0.as_ref()
  }
}

impl Zeroize for ExternalKey {
  fn zeroize(&mut self) {
    self.0.as_mut().zeroize();
  }
}

impl ExternalKey {
  /// The maximum length for an external key.
  /*
    This support keys up to 96 bytes (such as BLS12-381 G2, which is the largest elliptic-curve
    group element we might reasonably use as a key). This can always be increased if we need to
    adopt a different cryptosystem (one where verification keys are multiple group elements, or
    where group elements do exceed 96 bytes, such as RSA).
  */
  pub const MAX_LEN: u32 = 96;
}

/// Key(s) on embedded elliptic curve(s).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub enum EmbeddedEllipticCurveKeys {
  /// The embedded elliptic curve keys for a Bitcoin validator.
  Bitcoin(
    <<Embedwards25519 as WrappedGroup>::G as GroupEncoding>::Repr,
    <<Secq256k1 as WrappedGroup>::G as GroupEncoding>::Repr,
  ),
  /// The embedded elliptic curve keys for an Ethereum validator.
  Ethereum(
    <<Embedwards25519 as WrappedGroup>::G as GroupEncoding>::Repr,
    <<Secq256k1 as WrappedGroup>::G as GroupEncoding>::Repr,
  ),
  /// The embedded elliptic curve key for a Monero validator.
  Monero(<<Embedwards25519 as WrappedGroup>::G as GroupEncoding>::Repr),
}

impl EmbeddedEllipticCurveKeys {
  /// The network these keys are for.
  pub fn network(&self) -> ExternalNetworkId {
    match self {
      Self::Bitcoin(_, _) => ExternalNetworkId::Bitcoin,
      Self::Ethereum(_, _) => ExternalNetworkId::Ethereum,
      Self::Monero(_) => ExternalNetworkId::Monero,
    }
  }
}

impl BorshSerialize for EmbeddedEllipticCurveKeys {
  fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    match self {
      EmbeddedEllipticCurveKeys::Bitcoin(e, s) | EmbeddedEllipticCurveKeys::Ethereum(e, s) => {
        let mut res = [0; 1 + 32 + 33];
        res[0] = self.network() as u8;
        res[1 .. 33].copy_from_slice(e);
        res[33 ..].copy_from_slice(s);
        writer.write_all(&res)
      }
      EmbeddedEllipticCurveKeys::Monero(e) => {
        let mut res = [0; 1 + 32];
        res[0] = self.network() as u8;
        res[1 ..].copy_from_slice(e);
        writer.write_all(&res)
      }
    }
  }
}

impl BorshDeserialize for EmbeddedEllipticCurveKeys {
  fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let network_id = ExternalNetworkId::deserialize_reader(&mut *reader)?;
    let embedwards25519 = <[u8; 32]>::deserialize_reader(&mut *reader)?;
    Ok(match network_id {
      ExternalNetworkId::Bitcoin => {
        let secq256k1 = <[u8; 33]>::deserialize_reader(&mut *reader)?;
        EmbeddedEllipticCurveKeys::Bitcoin(embedwards25519, secq256k1.into())
      }
      ExternalNetworkId::Ethereum => {
        let secq256k1 = <[u8; 33]>::deserialize_reader(&mut *reader)?;
        EmbeddedEllipticCurveKeys::Ethereum(embedwards25519, secq256k1.into())
      }
      ExternalNetworkId::Monero => EmbeddedEllipticCurveKeys::Monero(embedwards25519),
    })
  }
}

#[cfg(feature = "non_canonical_scale_derivations")]
impl scale::Encode for EmbeddedEllipticCurveKeys {
  fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
    f(&borsh::to_vec(self).unwrap())
  }
}
#[cfg(feature = "non_canonical_scale_derivations")]
impl scale::MaxEncodedLen for EmbeddedEllipticCurveKeys {
  fn max_encoded_len() -> usize {
    1 + 32 + 33
  }
}
#[cfg(feature = "non_canonical_scale_derivations")]
impl scale::EncodeLike<EmbeddedEllipticCurveKeys> for EmbeddedEllipticCurveKeys {}
#[cfg(feature = "non_canonical_scale_derivations")]
impl scale::Decode for EmbeddedEllipticCurveKeys {
  fn decode<I: scale::Input>(input: &mut I) -> Result<Self, scale::Error> {
    crate::read_scale_as_borsh(input)
  }
}
#[cfg(feature = "non_canonical_scale_derivations")]
impl scale::DecodeWithMemTracking for EmbeddedEllipticCurveKeys {}

/// Key(s) on embedded elliptic curve(s) with the required proofs of knowledge.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub enum SignedEmbeddedEllipticCurveKeys {
  /// The signed embedded elliptic curve keys for a Bitcoin validator.
  Bitcoin(
    <<Embedwards25519 as WrappedGroup>::G as GroupEncoding>::Repr,
    <<Secq256k1 as WrappedGroup>::G as GroupEncoding>::Repr,
    [u8; 64],
    [u8; 65],
  ),
  /// The signed embedded elliptic curve keys for an Ethereum validator.
  Ethereum(
    <<Embedwards25519 as WrappedGroup>::G as GroupEncoding>::Repr,
    <<Secq256k1 as WrappedGroup>::G as GroupEncoding>::Repr,
    [u8; 64],
    [u8; 65],
  ),
  /// The signed embedded elliptic curve key for a Monero validator.
  Monero(<<Embedwards25519 as WrappedGroup>::G as GroupEncoding>::Repr, [u8; 64]),
}

impl SignedEmbeddedEllipticCurveKeys {
  /// The network these keys are for.
  pub fn network(&self) -> ExternalNetworkId {
    match self {
      Self::Bitcoin(_, _, _, _) => ExternalNetworkId::Bitcoin,
      Self::Ethereum(_, _, _, _) => ExternalNetworkId::Ethereum,
      Self::Monero(_, _) => ExternalNetworkId::Monero,
    }
  }

  /// Verify these key(s)' signature(s), returning the key(s) if valid.
  pub fn verify(self, validator: Public) -> Option<EmbeddedEllipticCurveKeys> {
    // Sample a unified challenge
    let transcript = match &self {
      Self::Bitcoin(e, s, e_sig, s_sig) => [
        [ExternalNetworkId::Bitcoin as u8].as_slice(),
        &validator.0,
        e,
        s,
        &e_sig[.. 32],
        &s_sig[.. 33],
      ]
      .concat(),
      Self::Ethereum(e, s, e_sig, s_sig) => [
        [ExternalNetworkId::Ethereum as u8].as_slice(),
        &validator.0,
        e,
        s,
        &e_sig[.. 32],
        &s_sig[.. 33],
      ]
      .concat(),
      Self::Monero(e, e_sig) => {
        [[ExternalNetworkId::Monero as u8].as_slice(), &validator.0, e, &e_sig[.. 32]].concat()
      }
    };
    let challenge = sp_core::hashing::blake2_512(&transcript);

    // Verify the Schnorr signatures
    match &self {
      Self::Bitcoin(e, _, e_sig, _) | Self::Ethereum(e, _, e_sig, _) | Self::Monero(e, e_sig) => {
        let sig = SchnorrSignature::<Embedwards25519>::read(&mut e_sig.as_slice()).ok()?;
        if !sig.verify(
          Option::<<Embedwards25519 as WrappedGroup>::G>::from(
            Embedwards25519::from_canonical_bytes(e),
          )?,
          <<Embedwards25519 as WrappedGroup>::F as FromUniformBytes<_>>::from_uniform_bytes(
            &challenge,
          ),
        ) {
          None?;
        }
      }
    };
    match &self {
      Self::Bitcoin(_, s, _, s_sig) | Self::Ethereum(_, s, _, s_sig) => {
        let sig = SchnorrSignature::<Secq256k1>::read(&mut s_sig.as_slice()).ok()?;
        if !sig.verify(
          Option::<<Secq256k1 as WrappedGroup>::G>::from(Secq256k1::from_canonical_bytes(s))?,
          <<Secq256k1 as WrappedGroup>::F as FromUniformBytes<_>>::from_uniform_bytes(&challenge),
        ) {
          None?;
        }
      }
      Self::Monero(_, _) => {}
    }

    // Return the keys
    Some(match self {
      Self::Bitcoin(e, s, _, _) => EmbeddedEllipticCurveKeys::Bitcoin(e, s),
      Self::Ethereum(e, s, _, _) => EmbeddedEllipticCurveKeys::Ethereum(e, s),
      Self::Monero(e, _) => EmbeddedEllipticCurveKeys::Monero(e),
    })
  }
}

impl BorshSerialize for SignedEmbeddedEllipticCurveKeys {
  fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    match self {
      SignedEmbeddedEllipticCurveKeys::Bitcoin(e, s, e_sig, s_sig) |
      SignedEmbeddedEllipticCurveKeys::Ethereum(e, s, e_sig, s_sig) => {
        let mut res = [0; 1 + 32 + 33 + 32 + 32 + 33 + 32];
        res[0] = self.network() as u8;
        res[1 .. 33].copy_from_slice(e);
        res[33 .. 66].copy_from_slice(s);
        res[66 .. 130].copy_from_slice(e_sig);
        res[130 ..].copy_from_slice(s_sig);
        writer.write_all(&res)
      }
      SignedEmbeddedEllipticCurveKeys::Monero(e, e_sig) => {
        let mut res = [0; 1 + 32 + 32 + 32];
        res[0] = self.network() as u8;
        res[1 .. 33].copy_from_slice(e);
        res[33 ..].copy_from_slice(e_sig);
        writer.write_all(&res)
      }
    }
  }
}

impl BorshDeserialize for SignedEmbeddedEllipticCurveKeys {
  fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let embedded_elliptic_curve_keys = EmbeddedEllipticCurveKeys::deserialize_reader(&mut *reader)?;
    let embedwards25519_signature = <[u8; 64]>::deserialize_reader(&mut *reader)?;
    Ok(match embedded_elliptic_curve_keys {
      EmbeddedEllipticCurveKeys::Bitcoin(e, s) => {
        let secq256k1_signature = <[u8; 65]>::deserialize_reader(&mut *reader)?;
        SignedEmbeddedEllipticCurveKeys::Bitcoin(
          e,
          s,
          embedwards25519_signature,
          secq256k1_signature,
        )
      }
      EmbeddedEllipticCurveKeys::Ethereum(e, s) => {
        let secq256k1_signature = <[u8; 65]>::deserialize_reader(&mut *reader)?;
        SignedEmbeddedEllipticCurveKeys::Ethereum(
          e,
          s,
          embedwards25519_signature,
          secq256k1_signature,
        )
      }
      EmbeddedEllipticCurveKeys::Monero(e) => {
        SignedEmbeddedEllipticCurveKeys::Monero(e, embedwards25519_signature)
      }
    })
  }
}

#[cfg(feature = "non_canonical_scale_derivations")]
impl scale::Encode for SignedEmbeddedEllipticCurveKeys {
  fn using_encoded<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
    f(&borsh::to_vec(self).unwrap())
  }
}
#[cfg(feature = "non_canonical_scale_derivations")]
impl scale::EncodeLike<SignedEmbeddedEllipticCurveKeys> for SignedEmbeddedEllipticCurveKeys {}
#[cfg(feature = "non_canonical_scale_derivations")]
impl scale::Decode for SignedEmbeddedEllipticCurveKeys {
  fn decode<I: scale::Input>(input: &mut I) -> Result<Self, scale::Error> {
    crate::read_scale_as_borsh(input)
  }
}
#[cfg(feature = "non_canonical_scale_derivations")]
impl scale::DecodeWithMemTracking for SignedEmbeddedEllipticCurveKeys {}

/// The key pair for a validator set.
///
/// This is their Ristretto key, used for publishing data onto Serai, and their key on the external
/// network.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(
  feature = "non_canonical_scale_derivations",
  derive(
    scale::Encode,
    scale::Decode,
    scale::MaxEncodedLen,
    scale::DecodeWithMemTracking,
    scale_info::TypeInfo
  )
)]
pub struct KeyPair(pub Public, pub ExternalKey);
