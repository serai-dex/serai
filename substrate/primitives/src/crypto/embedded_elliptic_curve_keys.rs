use core::ops::Deref as _;

use rand_core::{RngCore, CryptoRng};

use zeroize::{Zeroize, Zeroizing};
use borsh::{io, BorshSerialize, BorshDeserialize};

use ciphersuite::{
  group::{
    ff::{Field as _, PrimeField as _, FromUniformBytes},
    GroupEncoding,
  },
  WrappedGroup, GroupCanonicalEncoding as _,
};
use embedwards25519::Embedwards25519;
use secq256k1::Secq256k1;
use schnorr_signatures::SchnorrSignature;

use crate::{network_id::ExternalNetworkId, crypto::Public};

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
        res[0] = u8::from(self.network());
        res[1 .. 33].copy_from_slice(e);
        res[33 ..].copy_from_slice(s);
        writer.write_all(&res)
      }
      EmbeddedEllipticCurveKeys::Monero(e) => {
        let mut res = [0; 1 + 32];
        res[0] = u8::from(self.network());
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

#[cfg(feature = "scale")]
crate::borsh_as_scale!(EmbeddedEllipticCurveKeys);

#[cfg(feature = "scale")]
impl scale::MaxEncodedLen for EmbeddedEllipticCurveKeys {
  fn max_encoded_len() -> usize {
    1 + 32 + 33
  }
}

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

  fn transcript(&self, validator: Public) -> [u8; 64] {
    let transcript = match &self {
      Self::Bitcoin(e, s, e_sig, s_sig) => [
        [u8::from(ExternalNetworkId::Bitcoin)].as_slice(),
        &validator.0,
        e,
        s,
        &e_sig[.. 32],
        &s_sig[.. 33],
      ]
      .concat(),
      Self::Ethereum(e, s, e_sig, s_sig) => [
        [u8::from(ExternalNetworkId::Ethereum)].as_slice(),
        &validator.0,
        e,
        s,
        &e_sig[.. 32],
        &s_sig[.. 33],
      ]
      .concat(),
      Self::Monero(e, e_sig) => {
        [[u8::from(ExternalNetworkId::Monero)].as_slice(), &validator.0, e, &e_sig[.. 32]].concat()
      }
    };
    sp_core::hashing::blake2_512(&transcript)
  }

  /// Verify these key(s)' signature(s), returning the key(s) if valid.
  pub fn verify(self, validator: Public) -> Option<EmbeddedEllipticCurveKeys> {
    let challenge = self.transcript(validator);

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
    }
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

  #[doc(hidden)]
  pub fn bitcoin(
    rng: &mut (impl RngCore + CryptoRng),
    validator: Public,
    embedwards25519: &Zeroizing<<Embedwards25519 as WrappedGroup>::F>,
    secq256k1: &Zeroizing<<Secq256k1 as WrappedGroup>::F>,
  ) -> Self {
    let em_public_key =
      (<Embedwards25519 as WrappedGroup>::generator() * embedwards25519.deref()).to_bytes();
    let em_nonce = Zeroizing::new(<Embedwards25519 as WrappedGroup>::F::random(&mut *rng));
    let em_nonce_commitment = <Embedwards25519 as WrappedGroup>::generator() * em_nonce.deref();
    let mut em_sig = [0; 64];
    em_sig[.. 32].copy_from_slice(em_nonce_commitment.to_bytes().as_ref());

    let secq_public_key = (<Secq256k1 as WrappedGroup>::generator() * secq256k1.deref()).to_bytes();
    let secq_nonce = Zeroizing::new(<Secq256k1 as WrappedGroup>::F::random(&mut *rng));
    let secq_nonce_commitment = <Secq256k1 as WrappedGroup>::generator() * secq_nonce.deref();
    let mut secq_sig = [0; 65];
    secq_sig[.. 33].copy_from_slice(secq_nonce_commitment.to_bytes().as_ref());

    let challenge =
      SignedEmbeddedEllipticCurveKeys::Bitcoin(em_public_key, secq_public_key, em_sig, secq_sig)
        .transcript(validator);

    em_sig[32 ..].copy_from_slice(
      SchnorrSignature::<Embedwards25519>::sign(
        embedwards25519,
        em_nonce,
        <<Embedwards25519 as WrappedGroup>::F as FromUniformBytes<_>>::from_uniform_bytes(
          &challenge,
        ),
      )
      .s
      .to_repr()
      .as_ref(),
    );

    secq_sig[33 ..].copy_from_slice(
      SchnorrSignature::<Secq256k1>::sign(
        secq256k1,
        secq_nonce,
        <<Secq256k1 as WrappedGroup>::F as FromUniformBytes<_>>::from_uniform_bytes(&challenge),
      )
      .s
      .to_repr()
      .as_ref(),
    );

    SignedEmbeddedEllipticCurveKeys::Bitcoin(em_public_key, secq_public_key, em_sig, secq_sig)
  }

  #[doc(hidden)]
  pub fn ethereum(
    rng: &mut (impl RngCore + CryptoRng),
    validator: Public,
    embedwards25519: &Zeroizing<<Embedwards25519 as WrappedGroup>::F>,
    secq256k1: &Zeroizing<<Secq256k1 as WrappedGroup>::F>,
  ) -> Self {
    let em_public_key =
      (<Embedwards25519 as WrappedGroup>::generator() * embedwards25519.deref()).to_bytes();
    let em_nonce = Zeroizing::new(<Embedwards25519 as WrappedGroup>::F::random(&mut *rng));
    let em_nonce_commitment = <Embedwards25519 as WrappedGroup>::generator() * em_nonce.deref();
    let mut em_sig = [0; 64];
    em_sig[.. 32].copy_from_slice(em_nonce_commitment.to_bytes().as_ref());

    let secq_public_key = (<Secq256k1 as WrappedGroup>::generator() * secq256k1.deref()).to_bytes();
    let secq_nonce = Zeroizing::new(<Secq256k1 as WrappedGroup>::F::random(&mut *rng));
    let secq_nonce_commitment = <Secq256k1 as WrappedGroup>::generator() * secq_nonce.deref();
    let mut secq_sig = [0; 65];
    secq_sig[.. 33].copy_from_slice(secq_nonce_commitment.to_bytes().as_ref());

    let challenge =
      SignedEmbeddedEllipticCurveKeys::Ethereum(em_public_key, secq_public_key, em_sig, secq_sig)
        .transcript(validator);

    em_sig[32 ..].copy_from_slice(
      SchnorrSignature::<Embedwards25519>::sign(
        embedwards25519,
        em_nonce,
        <<Embedwards25519 as WrappedGroup>::F as FromUniformBytes<_>>::from_uniform_bytes(
          &challenge,
        ),
      )
      .s
      .to_repr()
      .as_ref(),
    );

    secq_sig[33 ..].copy_from_slice(
      SchnorrSignature::<Secq256k1>::sign(
        secq256k1,
        secq_nonce,
        <<Secq256k1 as WrappedGroup>::F as FromUniformBytes<_>>::from_uniform_bytes(&challenge),
      )
      .s
      .to_repr()
      .as_ref(),
    );

    SignedEmbeddedEllipticCurveKeys::Ethereum(em_public_key, secq_public_key, em_sig, secq_sig)
  }

  #[doc(hidden)]
  pub fn monero(
    rng: &mut (impl RngCore + CryptoRng),
    validator: Public,
    embedwards25519: &Zeroizing<<Embedwards25519 as WrappedGroup>::F>,
  ) -> Self {
    let em_public_key =
      (<Embedwards25519 as WrappedGroup>::generator() * embedwards25519.deref()).to_bytes();
    let em_nonce = Zeroizing::new(<Embedwards25519 as WrappedGroup>::F::random(&mut *rng));
    let em_nonce_commitment = <Embedwards25519 as WrappedGroup>::generator() * em_nonce.deref();
    let mut em_sig = [0; 64];
    em_sig[.. 32].copy_from_slice(em_nonce_commitment.to_bytes().as_ref());
    let challenge =
      SignedEmbeddedEllipticCurveKeys::Monero(em_public_key, em_sig).transcript(validator);
    em_sig[32 ..].copy_from_slice(
      SchnorrSignature::<Embedwards25519>::sign(
        embedwards25519,
        em_nonce,
        <<Embedwards25519 as WrappedGroup>::F as FromUniformBytes<_>>::from_uniform_bytes(
          &challenge,
        ),
      )
      .s
      .to_repr()
      .as_ref(),
    );
    SignedEmbeddedEllipticCurveKeys::Monero(em_public_key, em_sig)
  }
}

impl BorshSerialize for SignedEmbeddedEllipticCurveKeys {
  fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    match self {
      SignedEmbeddedEllipticCurveKeys::Bitcoin(e, s, e_sig, s_sig) |
      SignedEmbeddedEllipticCurveKeys::Ethereum(e, s, e_sig, s_sig) => {
        let mut res = [0; 1 + 32 + 33 + 32 + 32 + 33 + 32];
        res[0] = u8::from(self.network());
        res[1 .. 33].copy_from_slice(e);
        res[33 .. 66].copy_from_slice(s);
        res[66 .. 130].copy_from_slice(e_sig);
        res[130 ..].copy_from_slice(s_sig);
        writer.write_all(&res)
      }
      SignedEmbeddedEllipticCurveKeys::Monero(e, e_sig) => {
        let mut res = [0; 1 + 32 + 32 + 32];
        res[0] = u8::from(self.network());
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

#[cfg(feature = "scale")]
crate::borsh_as_scale!(SignedEmbeddedEllipticCurveKeys);
