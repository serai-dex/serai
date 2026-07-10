use core::ops::Deref as _;

use rand_core::{RngCore, CryptoRng};

use zeroize::{Zeroize, Zeroizing};
use borsh::{io, BorshSerialize, BorshDeserialize};

use ciphersuite::{
  group::{
    ff::{Field as _, PrimeField, FromUniformBytes},
    Group as _, GroupEncoding,
  },
  WrappedGroup, GroupCanonicalEncoding,
};
use dalek_ff_group::Ristretto;
use embedwards25519::Embedwards25519;
use secq256k1::Secq256k1;
use schnorr_signatures::SchnorrSignature;

use crate::{
  address::SeraiAddress,
  network_id::{ExternalNetworkId, NetworkId},
};

/// Identifier for an embedded elliptic curve.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
pub enum EmbeddedEllipticCurve {
  /// The Embedwards25519 curve, defined over (embedded into) Ed25519's/Ristretto's scalar field.
  Embedwards25519,
  /// The secq256k1 curve, forming a cycle with secp256k1.
  Secq256k1,
}
#[cfg(feature = "scale")]
crate::borsh_as_scale!(EmbeddedEllipticCurve);

/// Key(s) on embedded elliptic curve(s).
///
/// These are used by validators for external networks as part of their Distributed Key Generation
/// protocols.
///
/// In the case of `Serai`, this is actually an auxiliary key which the validator uses in place of
/// the key which declared them and controls their stake. It has no relation to the embedded
/// elliptic curves validators for external networks use in their Distributed Key Generation
/// protocols. The presence here is an artifact of the development timeline, where this struct
/// SHOULD be renamed to `AuxiliaryKeys`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub enum EmbeddedEllipticCurveKeys {
  /// The key to use for the validator's identity.
  Serai(<<Ristretto as WrappedGroup>::G as GroupEncoding>::Repr),
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
  pub fn network(&self) -> NetworkId {
    match self {
      Self::Serai(_) => NetworkId::Serai,
      Self::Bitcoin(_, _) => ExternalNetworkId::Bitcoin.into(),
      Self::Ethereum(_, _) => ExternalNetworkId::Ethereum.into(),
      Self::Monero(_) => ExternalNetworkId::Monero.into(),
    }
  }
}

impl BorshSerialize for EmbeddedEllipticCurveKeys {
  fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    match self {
      EmbeddedEllipticCurveKeys::Serai(r) => {
        self.network().serialize(writer)?;
        writer.write_all(r)
      }
      EmbeddedEllipticCurveKeys::Bitcoin(e, s) | EmbeddedEllipticCurveKeys::Ethereum(e, s) => {
        self.network().serialize(writer)?;
        writer.write_all(e)?;
        writer.write_all(s)
      }
      EmbeddedEllipticCurveKeys::Monero(e) => {
        self.network().serialize(writer)?;
        writer.write_all(e)
      }
    }
  }
}

impl BorshDeserialize for EmbeddedEllipticCurveKeys {
  fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let network_id = NetworkId::deserialize_reader(&mut *reader)?;
    Ok(match network_id {
      NetworkId::Serai => {
        let ristretto = <[u8; 32]>::deserialize_reader(&mut *reader)?;
        EmbeddedEllipticCurveKeys::Serai(ristretto)
      }
      NetworkId::External(network_id) => {
        let embedwards25519 = <[u8; 32]>::deserialize_reader(&mut *reader)?;
        match network_id {
          ExternalNetworkId::Bitcoin => {
            let secq256k1 = <[u8; 33]>::deserialize_reader(&mut *reader)?;
            EmbeddedEllipticCurveKeys::Bitcoin(embedwards25519, secq256k1.into())
          }
          ExternalNetworkId::Ethereum => {
            let secq256k1 = <[u8; 33]>::deserialize_reader(&mut *reader)?;
            EmbeddedEllipticCurveKeys::Ethereum(embedwards25519, secq256k1.into())
          }
          ExternalNetworkId::Monero => EmbeddedEllipticCurveKeys::Monero(embedwards25519),
        }
      }
    })
  }
}

#[cfg(feature = "scale")]
crate::borsh_as_scale!(EmbeddedEllipticCurveKeys);

#[cfg(feature = "scale")]
impl scale::MaxEncodedLen for EmbeddedEllipticCurveKeys {
  fn max_encoded_len() -> usize {
    NetworkId::max_encoded_len() + 32 + 33
  }
}

/// Key(s) on embedded elliptic curve(s) with the required proofs of knowledge.
///
/// The proofs of knowledge assert that the validator setting these keys, knows these keys, and
/// that the keys themselves are valid and well-formed.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub enum SignedEmbeddedEllipticCurveKeys {
  /// The signed key to use for the validator's identity.
  Serai(<<Ristretto as WrappedGroup>::G as GroupEncoding>::Repr, [u8; 64]),
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
  pub fn network(&self) -> NetworkId {
    match self {
      Self::Serai(_, _) => NetworkId::Serai,
      Self::Bitcoin(_, _, _, _) => ExternalNetworkId::Bitcoin.into(),
      Self::Ethereum(_, _, _, _) => ExternalNetworkId::Ethereum.into(),
      Self::Monero(_, _) => ExternalNetworkId::Monero.into(),
    }
  }

  fn transcript(&self, validator: SeraiAddress) -> [u8; 64] {
    let ristretto_nonce_commitment_len =
      <<Ristretto as WrappedGroup>::G as GroupEncoding>::Repr::default().as_slice().len();
    let embedwards25519_nonce_commitment_len =
      <<Embedwards25519 as WrappedGroup>::G as GroupEncoding>::Repr::default().as_slice().len();
    let secq256k1_nonce_commitment_len =
      <<Secq256k1 as WrappedGroup>::G as GroupEncoding>::Repr::default().as_slice().len();

    /*
      `H(A || m || R)` where `m` is the serialization of the corresponding
      `EmbeddedEllipticCurveKeys` and `R` is the nonce commitments from each signature present.

      This introspects how the `SchnorrSignature` serialization is of the form `(R, s)`, which we
      assert in a following test. The alternative would be to deserialize the `SchnorrSignature`
      here, giving us typed access to the `R` field (the nonce commitment) and allowing us to
      serialize it specifically, but this would involve expensive elliptic curve operations (a
      square root within the deserialization and inversion for the serialization, both over the
      finite field the elliptic curve is defined over (presumably ~256-bit)).
    */
    let mut transcript = validator.0.as_slice().to_vec();
    transcript.extend(borsh::to_vec(&self.network()).unwrap());
    transcript.extend(
      (match &self {
        Self::Serai(ristretto, signature) => {
          [ristretto.as_slice(), &signature[.. ristretto_nonce_commitment_len], &[], &[]]
            .into_iter()
        }
        Self::Bitcoin(e, s, e_sig, s_sig) | Self::Ethereum(e, s, e_sig, s_sig) => [
          e.as_slice(),
          s.as_ref(),
          &e_sig[.. embedwards25519_nonce_commitment_len],
          &s_sig[.. secq256k1_nonce_commitment_len],
        ]
        .into_iter(),
        Self::Monero(e, e_sig) => {
          [e.as_slice(), &[], &e_sig[.. embedwards25519_nonce_commitment_len], &[]].into_iter()
        }
      })
      .flat_map(<[_]>::iter),
    );
    sp_crypto_hashing::blake2_512(&transcript)
  }

  /// Verify these key(s)' signature(s), returning the key(s) if valid.
  ///
  /// This does not require any signature from the validator. The validator is expected to provide
  /// their signature over these keys when they publish the message (or transaction) declaring
  /// these keys.
  pub fn verify(self, validator: SeraiAddress) -> Option<EmbeddedEllipticCurveKeys> {
    let challenge = self.transcript(validator);

    // Verify the Schnorr signatures for Ristretto
    match &self {
      Self::Serai(ristretto, sig) => {
        let sig = SchnorrSignature::<Ristretto>::read(&mut sig.as_slice()).ok()?;
        if !sig.verify(
          Option::<<Ristretto as WrappedGroup>::G>::from(Ristretto::from_canonical_bytes(
            ristretto,
          ))?,
          <<Ristretto as WrappedGroup>::F as FromUniformBytes<_>>::from_uniform_bytes(&challenge),
        ) {
          None?;
        }
      }
      Self::Bitcoin(_, _, _, _) | Self::Ethereum(_, _, _, _) | Self::Monero(_, _) => {}
    }

    // Verify the Schnorr signatures for Embedwards25519
    match &self {
      Self::Serai(_, _) => {}
      Self::Bitcoin(e, _, e_sig, _) | Self::Ethereum(e, _, e_sig, _) | Self::Monero(e, e_sig) => {
        let e = Option::<<Embedwards25519 as WrappedGroup>::G>::from(
          Embedwards25519::from_canonical_bytes(e),
        )?;
        // The eVRF DKG rejects public keys which are the identity as they don't have well-defined
        // affine coordinates
        if bool::from(e.is_identity()) {
          None?;
        }

        let sig = SchnorrSignature::<Embedwards25519>::read(&mut e_sig.as_slice()).ok()?;
        if !sig.verify(
          e,
          <<Embedwards25519 as WrappedGroup>::F as FromUniformBytes<_>>::from_uniform_bytes(
            &challenge,
          ),
        ) {
          None?;
        }
      }
    }

    // Verify the Schnorr signatures for Secq256k1
    match &self {
      Self::Bitcoin(_, s, _, s_sig) | Self::Ethereum(_, s, _, s_sig) => {
        let s = Option::<<Secq256k1 as WrappedGroup>::G>::from(Secq256k1::from_canonical_bytes(s))?;
        if bool::from(s.is_identity()) {
          None?;
        }

        let sig = SchnorrSignature::<Secq256k1>::read(&mut s_sig.as_slice()).ok()?;
        if !sig.verify(
          s,
          <<Secq256k1 as WrappedGroup>::F as FromUniformBytes<_>>::from_uniform_bytes(&challenge),
        ) {
          None?;
        }
      }
      Self::Serai(_, _) | Self::Monero(_, _) => {}
    }

    // Return the keys
    Some(match self {
      Self::Serai(ristretto, _) => EmbeddedEllipticCurveKeys::Serai(ristretto),
      Self::Bitcoin(e, s, _, _) => EmbeddedEllipticCurveKeys::Bitcoin(e, s),
      Self::Ethereum(e, s, _, _) => EmbeddedEllipticCurveKeys::Ethereum(e, s),
      Self::Monero(e, _) => EmbeddedEllipticCurveKeys::Monero(e),
    })
  }

  fn commit<G: WrappedGroup>(
    rng: &mut (impl RngCore + CryptoRng),
    key: &Zeroizing<G::F>,
    sig: &mut [u8],
  ) -> (<G::G as GroupEncoding>::Repr, Zeroizing<G::F>) {
    let public_key = (G::generator() * key.deref()).to_bytes();
    let nonce = Zeroizing::new(G::F::random(rng));
    let nonce_commitment = G::generator() * nonce.deref();

    let nonce_commitment_len = <G::G as GroupEncoding>::Repr::default().as_ref().len();
    let response_len = <G::F as PrimeField>::Repr::default().as_ref().len();
    debug_assert_eq!(sig.len(), nonce_commitment_len + response_len);
    sig[.. nonce_commitment_len].copy_from_slice(nonce_commitment.to_bytes().as_ref());

    (public_key, nonce)
  }

  fn sign<G: GroupCanonicalEncoding<F: FromUniformBytes<64>>>(
    key: &Zeroizing<G::F>,
    nonce: Zeroizing<G::F>,
    challenge: &[u8; 64],
    signature: &mut [u8],
  ) {
    let sig = SchnorrSignature::<G>::sign(
      key,
      nonce,
      <G::F as FromUniformBytes<_>>::from_uniform_bytes(challenge),
    );

    let nonce_commitment_len = <G::G as GroupEncoding>::Repr::default().as_ref().len();
    let response_len = <G::F as PrimeField>::Repr::default().as_ref().len();
    debug_assert_eq!(signature.len(), nonce_commitment_len + response_len);
    debug_assert_eq!(&signature[.. nonce_commitment_len], sig.R.to_bytes().as_ref());
    signature[nonce_commitment_len ..].copy_from_slice(sig.s.to_repr().as_ref());
  }

  /*
    The following functions take the above generic functions to sign signatures and provides
    literal definitions for each variant. They're hidden as they're not intended to be part of our
    API commitment at this time due to questions about what key provisioning and management will
    look like in the long run. They are intended for use in production, just not being committed to
    under SemVer.
  */

  #[doc(hidden)]
  pub fn serai(
    rng: &mut (impl RngCore + CryptoRng),
    validator: SeraiAddress,
    ristretto: &Zeroizing<<Ristretto as WrappedGroup>::F>,
  ) -> Self {
    let mut rist_sig = [0; 64];
    let (rist_public_key, rist_nonce) = Self::commit::<Ristretto>(rng, ristretto, &mut rist_sig);

    let challenge =
      SignedEmbeddedEllipticCurveKeys::Serai(rist_public_key, rist_sig).transcript(validator);

    Self::sign::<Ristretto>(ristretto, rist_nonce, &challenge, &mut rist_sig);

    SignedEmbeddedEllipticCurveKeys::Serai(rist_public_key, rist_sig)
  }

  #[doc(hidden)]
  pub fn bitcoin(
    rng: &mut (impl RngCore + CryptoRng),
    validator: SeraiAddress,
    embedwards25519: &Zeroizing<<Embedwards25519 as WrappedGroup>::F>,
    secq256k1: &Zeroizing<<Secq256k1 as WrappedGroup>::F>,
  ) -> Self {
    let mut em_sig = [0; 64];
    let (em_public_key, em_nonce) =
      Self::commit::<Embedwards25519>(rng, embedwards25519, &mut em_sig);
    let mut secq_sig = [0; 65];
    let (secq_public_key, secq_nonce) = Self::commit::<Secq256k1>(rng, secq256k1, &mut secq_sig);

    let challenge =
      SignedEmbeddedEllipticCurveKeys::Bitcoin(em_public_key, secq_public_key, em_sig, secq_sig)
        .transcript(validator);

    Self::sign::<Embedwards25519>(embedwards25519, em_nonce, &challenge, &mut em_sig);
    Self::sign::<Secq256k1>(secq256k1, secq_nonce, &challenge, &mut secq_sig);

    SignedEmbeddedEllipticCurveKeys::Bitcoin(em_public_key, secq_public_key, em_sig, secq_sig)
  }

  #[doc(hidden)]
  pub fn ethereum(
    rng: &mut (impl RngCore + CryptoRng),
    validator: SeraiAddress,
    embedwards25519: &Zeroizing<<Embedwards25519 as WrappedGroup>::F>,
    secq256k1: &Zeroizing<<Secq256k1 as WrappedGroup>::F>,
  ) -> Self {
    let mut em_sig = [0; 64];
    let (em_public_key, em_nonce) =
      Self::commit::<Embedwards25519>(rng, embedwards25519, &mut em_sig);
    let mut secq_sig = [0; 65];
    let (secq_public_key, secq_nonce) = Self::commit::<Secq256k1>(rng, secq256k1, &mut secq_sig);

    let challenge =
      SignedEmbeddedEllipticCurveKeys::Ethereum(em_public_key, secq_public_key, em_sig, secq_sig)
        .transcript(validator);

    Self::sign::<Embedwards25519>(embedwards25519, em_nonce, &challenge, &mut em_sig);
    Self::sign::<Secq256k1>(secq256k1, secq_nonce, &challenge, &mut secq_sig);

    SignedEmbeddedEllipticCurveKeys::Ethereum(em_public_key, secq_public_key, em_sig, secq_sig)
  }

  #[doc(hidden)]
  pub fn monero(
    rng: &mut (impl RngCore + CryptoRng),
    validator: SeraiAddress,
    embedwards25519: &Zeroizing<<Embedwards25519 as WrappedGroup>::F>,
  ) -> Self {
    let mut em_sig = [0; 64];
    let (em_public_key, em_nonce) =
      Self::commit::<Embedwards25519>(rng, embedwards25519, &mut em_sig);

    let challenge =
      SignedEmbeddedEllipticCurveKeys::Monero(em_public_key, em_sig).transcript(validator);

    Self::sign::<Embedwards25519>(embedwards25519, em_nonce, &challenge, &mut em_sig);

    SignedEmbeddedEllipticCurveKeys::Monero(em_public_key, em_sig)
  }
}

impl BorshSerialize for SignedEmbeddedEllipticCurveKeys {
  fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    match self {
      SignedEmbeddedEllipticCurveKeys::Serai(ristretto, signature) => {
        self.network().serialize(writer)?;
        writer.write_all(ristretto)?;
        writer.write_all(signature)
      }
      SignedEmbeddedEllipticCurveKeys::Bitcoin(e, s, e_sig, s_sig) |
      SignedEmbeddedEllipticCurveKeys::Ethereum(e, s, e_sig, s_sig) => {
        self.network().serialize(writer)?;
        writer.write_all(e)?;
        writer.write_all(s)?;
        writer.write_all(e_sig)?;
        writer.write_all(s_sig)
      }
      SignedEmbeddedEllipticCurveKeys::Monero(e, e_sig) => {
        self.network().serialize(writer)?;
        writer.write_all(e)?;
        writer.write_all(e_sig)
      }
    }
  }
}

impl BorshDeserialize for SignedEmbeddedEllipticCurveKeys {
  fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let embedded_elliptic_curve_keys = EmbeddedEllipticCurveKeys::deserialize_reader(&mut *reader)?;
    Ok(match embedded_elliptic_curve_keys {
      EmbeddedEllipticCurveKeys::Serai(ristretto) => {
        let ristretto_signature = <[u8; 64]>::deserialize_reader(&mut *reader)?;
        SignedEmbeddedEllipticCurveKeys::Serai(ristretto, ristretto_signature)
      }
      EmbeddedEllipticCurveKeys::Bitcoin(e, s) => {
        let embedwards25519_signature = <[u8; 64]>::deserialize_reader(&mut *reader)?;
        let secq256k1_signature = <[u8; 65]>::deserialize_reader(&mut *reader)?;
        SignedEmbeddedEllipticCurveKeys::Bitcoin(
          e,
          s,
          embedwards25519_signature,
          secq256k1_signature,
        )
      }
      EmbeddedEllipticCurveKeys::Ethereum(e, s) => {
        let embedwards25519_signature = <[u8; 64]>::deserialize_reader(&mut *reader)?;
        let secq256k1_signature = <[u8; 65]>::deserialize_reader(&mut *reader)?;
        SignedEmbeddedEllipticCurveKeys::Ethereum(
          e,
          s,
          embedwards25519_signature,
          secq256k1_signature,
        )
      }
      EmbeddedEllipticCurveKeys::Monero(e) => {
        let embedwards25519_signature = <[u8; 64]>::deserialize_reader(&mut *reader)?;
        SignedEmbeddedEllipticCurveKeys::Monero(e, embedwards25519_signature)
      }
    })
  }
}

#[cfg(feature = "scale")]
crate::borsh_as_scale!(SignedEmbeddedEllipticCurveKeys);

#[test]
fn serialize() {
  use rand_core::{RngCore as _, OsRng};
  use ciphersuite::group::Group as _;

  let mut ristretto = [0; 32];
  OsRng.fill_bytes(&mut ristretto);
  let mut ristretto_sig = [0; 64];
  ristretto_sig.copy_from_slice(
    &(SchnorrSignature::<Ristretto> {
      R: <Ristretto as WrappedGroup>::G::random(&mut OsRng),
      s: <Ristretto as WrappedGroup>::F::random(&mut OsRng),
    })
    .serialize(),
  );
  let mut embedwards25519 = [0; 32];
  OsRng.fill_bytes(&mut embedwards25519);
  let mut embedwards25519_sig = [0; 64];
  embedwards25519_sig.copy_from_slice(
    &(SchnorrSignature::<Embedwards25519> {
      R: <Embedwards25519 as WrappedGroup>::G::random(&mut OsRng),
      s: <Embedwards25519 as WrappedGroup>::F::random(&mut OsRng),
    })
    .serialize(),
  );
  let mut secq256k1 = <<Secq256k1 as WrappedGroup>::G as GroupEncoding>::Repr::default();
  OsRng.fill_bytes(secq256k1.as_mut());
  let mut secq256k1_sig = [0; 65];
  secq256k1_sig.copy_from_slice(
    &(SchnorrSignature::<Secq256k1> {
      R: <Secq256k1 as WrappedGroup>::G::random(&mut OsRng),
      s: <Secq256k1 as WrappedGroup>::F::random(&mut OsRng),
    })
    .serialize(),
  );

  for (network, embedded_elliptic_curve_keys, signed_embedded_elliptic_curve_keys) in [
    (
      NetworkId::Serai,
      EmbeddedEllipticCurveKeys::Serai(ristretto),
      SignedEmbeddedEllipticCurveKeys::Serai(ristretto, ristretto_sig),
    ),
    (
      ExternalNetworkId::Bitcoin.into(),
      EmbeddedEllipticCurveKeys::Bitcoin(embedwards25519, secq256k1),
      SignedEmbeddedEllipticCurveKeys::Bitcoin(
        embedwards25519,
        secq256k1,
        embedwards25519_sig,
        secq256k1_sig,
      ),
    ),
    (
      ExternalNetworkId::Ethereum.into(),
      EmbeddedEllipticCurveKeys::Ethereum(embedwards25519, secq256k1),
      SignedEmbeddedEllipticCurveKeys::Ethereum(
        embedwards25519,
        secq256k1,
        embedwards25519_sig,
        secq256k1_sig,
      ),
    ),
    (
      ExternalNetworkId::Monero.into(),
      EmbeddedEllipticCurveKeys::Monero(embedwards25519),
      SignedEmbeddedEllipticCurveKeys::Monero(embedwards25519, embedwards25519_sig),
    ),
  ] {
    assert_eq!(embedded_elliptic_curve_keys.network(), network);
    assert_eq!(signed_embedded_elliptic_curve_keys.network(), network);

    assert_eq!(
      EmbeddedEllipticCurveKeys::deserialize_reader(
        &mut borsh::to_vec(&embedded_elliptic_curve_keys).unwrap().as_slice()
      )
      .unwrap(),
      embedded_elliptic_curve_keys,
    );

    assert_eq!(
      SignedEmbeddedEllipticCurveKeys::deserialize_reader(
        &mut borsh::to_vec(&signed_embedded_elliptic_curve_keys).unwrap().as_slice()
      )
      .unwrap(),
      signed_embedded_elliptic_curve_keys,
    );

    #[cfg(feature = "scale")]
    {
      use scale::{Encode as _, DecodeAll as _, MaxEncodedLen as _};

      assert_eq!(
        borsh::to_vec(&embedded_elliptic_curve_keys).unwrap(),
        embedded_elliptic_curve_keys.encode()
      );
      assert_eq!(
        EmbeddedEllipticCurveKeys::decode_all(
          &mut embedded_elliptic_curve_keys.encode().as_slice()
        )
        .unwrap(),
        embedded_elliptic_curve_keys
      );
      assert!(
        embedded_elliptic_curve_keys.encode().len() <= EmbeddedEllipticCurveKeys::max_encoded_len()
      );

      assert_eq!(
        borsh::to_vec(&signed_embedded_elliptic_curve_keys).unwrap(),
        signed_embedded_elliptic_curve_keys.encode()
      );
      assert_eq!(
        SignedEmbeddedEllipticCurveKeys::decode_all(
          &mut signed_embedded_elliptic_curve_keys.encode().as_slice()
        )
        .unwrap(),
        signed_embedded_elliptic_curve_keys
      );

      // The encoding of `EmbeddedEllipticCurveKeys` should equal the
      // first segment of a corresponding `SignedEmbeddedEllipticCurveKeys`
      let embedded_elliptic_curve_keys = borsh::to_vec(&embedded_elliptic_curve_keys).unwrap();
      assert_eq!(
        &borsh::to_vec(&signed_embedded_elliptic_curve_keys).unwrap()
          [.. embedded_elliptic_curve_keys.len()],
        &embedded_elliptic_curve_keys
      );
    }

    // Check the format of `transcript`
    {
      let mut validator = [0; 32];
      OsRng.fill_bytes(&mut validator);
      let validator = SeraiAddress(validator);

      // `A || m`
      let mut transcript = borsh::to_vec(&(validator, embedded_elliptic_curve_keys)).unwrap();
      // `R`
      let mut wrote_nonce = false;
      match network {
        NetworkId::Serai => {
          let nonce = &ristretto_sig[.. 32];
          assert_eq!(
            SchnorrSignature::<Ristretto>::read(&mut ristretto_sig.as_slice())
              .unwrap()
              .R
              .to_bytes()
              .as_slice(),
            nonce
          );
          transcript.extend(nonce);
          wrote_nonce = true;
        }
        NetworkId::External(network) => {
          for embedded_elliptic_curve in network.embedded_elliptic_curves() {
            match embedded_elliptic_curve {
              EmbeddedEllipticCurve::Embedwards25519 => {
                let nonce = &embedwards25519_sig[.. 32];
                assert_eq!(
                  SchnorrSignature::<Embedwards25519>::read(&mut embedwards25519_sig.as_slice())
                    .unwrap()
                    .R
                    .to_bytes()
                    .as_slice(),
                  nonce
                );
                transcript.extend(nonce);
              }
              EmbeddedEllipticCurve::Secq256k1 => {
                let nonce = &secq256k1_sig[.. 33];
                assert_eq!(
                  SchnorrSignature::<Secq256k1>::read(&mut secq256k1_sig.as_slice())
                    .unwrap()
                    .R
                    .to_bytes()
                    .as_slice(),
                  nonce
                );
                transcript.extend(nonce);
              }
            }
            wrote_nonce = true;
          }
        }
      }
      assert!(wrote_nonce);
      assert_eq!(
        sp_crypto_hashing::blake2_512(&transcript),
        signed_embedded_elliptic_curve_keys.transcript(validator)
      );
    }
  }
}

#[test]
fn sign_and_verify() {
  use rand_core::OsRng;

  let mut validator = [0; 32];
  OsRng.fill_bytes(&mut validator);

  let mut other_validator = validator;
  other_validator[0] ^= 1;

  let validator = SeraiAddress(validator);
  let other_validator = SeraiAddress(other_validator);

  let ristretto = Zeroizing::new(<Ristretto as WrappedGroup>::F::random(&mut OsRng));
  let ristretto_pub = (Ristretto::generator() * *ristretto).to_bytes();
  let embedwards25519 = Zeroizing::new(<Embedwards25519 as WrappedGroup>::F::random(&mut OsRng));
  let embedwards25519_pub = (Embedwards25519::generator() * *embedwards25519).to_bytes();
  let secq256k1 = Zeroizing::new(<Secq256k1 as WrappedGroup>::F::random(&mut OsRng));
  let secq256k1_pub = (Secq256k1::generator() * *secq256k1).to_bytes();

  let verify = |signed: SignedEmbeddedEllipticCurveKeys, expected| {
    assert_eq!(signed.clone().verify(validator).unwrap(), expected);

    // Test a distinct validator causes verification to fail
    assert!(signed.clone().verify(other_validator).is_none());

    // Test changing a single byte in the serialization causes verification to fail
    let serialization = borsh::to_vec(&signed).unwrap();
    'byte_index: for i in 0 .. serialization.len() {
      let mut serialization = serialization.clone();
      let original_byte = serialization[i];

      // Try to randomize a byte this many times before giving up
      let mut byte_candidates = 128 * 256;
      let signed = loop {
        // Choose a new byte which wasn't the original byte
        serialization[i] = loop {
          #[allow(clippy::as_conversions, clippy::cast_possible_truncation)]
          let candidate = OsRng.next_u64() as u8;
          if candidate != original_byte {
            break candidate;
          }
        };
        // If this deserializes, break out of the loop and try verification
        if let Ok(signed) =
          SignedEmbeddedEllipticCurveKeys::deserialize_reader(&mut serialization.as_slice())
        {
          break signed;
        }

        byte_candidates -= 1;
        // The network with the shortest `SignedEmbeddedEllipticCurveKeys` will fail to deserialize
        // as any other network if it is the sole network with such a short instance. We allow
        // re-randomizing the network (the very first byte) to fail for this specific edge case.
        if byte_candidates == 0 {
          assert_eq!(i, 0);
          continue 'byte_index;
        }
      };

      // Make sure this malleation fails to verify
      assert!(signed.verify(validator).is_none());
    }
  };

  verify(
    SignedEmbeddedEllipticCurveKeys::serai(&mut OsRng, validator, &ristretto),
    EmbeddedEllipticCurveKeys::Serai(ristretto_pub),
  );

  verify(
    SignedEmbeddedEllipticCurveKeys::bitcoin(&mut OsRng, validator, &embedwards25519, &secq256k1),
    EmbeddedEllipticCurveKeys::Bitcoin(embedwards25519_pub, secq256k1_pub),
  );

  verify(
    SignedEmbeddedEllipticCurveKeys::ethereum(&mut OsRng, validator, &embedwards25519, &secq256k1),
    EmbeddedEllipticCurveKeys::Ethereum(embedwards25519_pub, secq256k1_pub),
  );

  verify(
    SignedEmbeddedEllipticCurveKeys::monero(&mut OsRng, validator, &embedwards25519),
    EmbeddedEllipticCurveKeys::Monero(embedwards25519_pub),
  );
}
