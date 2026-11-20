use zeroize::Zeroize;

use borsh::{BorshSerialize, BorshDeserialize};

mod external_key;
pub use external_key::*;
mod embedded_elliptic_curve_keys;
pub use embedded_elliptic_curve_keys::*;

pub use sp_core::crypto::{KeyTypeId, key_types};
use sp_core::crypto::DeriveJunction;

/// A Ristretto public key.
///
/// This does not validate the 32-byte blob is actually a valid public key. It solely associates
/// the idea this 32-byte blob will be used as a public key.
///
/// This is approximate to [`sp_core::sr25519::Public`] but implements the APIs from `borsh`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "scale", derive(scale::MaxEncodedLen))]
pub struct Public(pub [u8; 32]);
#[cfg(feature = "scale")]
crate::borsh_as_scale!(Public);

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

#[cfg(feature = "scale")]
impl scale::EncodeLike<sp_core::sr25519::Public> for Public {}
#[cfg(feature = "scale")]
impl scale::EncodeLike<Public> for sp_core::sr25519::Public {}

/// A Ristretto (sr25519) signature.
///
/// This does not validate the 64-byte blob is actually a valid signature (even syntactically). It
/// solely associates the idea this 64-byte blob will be used as a signature.
///
/// This is approximate to [`sp_core::sr25519::Signature`] but implements the APIs from `borsh`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
pub struct RistrettoSignature(pub [u8; 64]);
#[cfg(feature = "scale")]
crate::borsh_as_scale!(RistrettoSignature);

impl From<schnorrkel::Signature> for RistrettoSignature {
  fn from(signature: schnorrkel::Signature) -> Self {
    Self(signature.to_bytes())
  }
}

impl From<sp_core::sr25519::Signature> for RistrettoSignature {
  fn from(signature: sp_core::sr25519::Signature) -> Self {
    Self(signature.0)
  }
}
impl From<RistrettoSignature> for sp_core::sr25519::Signature {
  fn from(signature: RistrettoSignature) -> Self {
    Self::from_raw(signature.0)
  }
}

#[cfg(feature = "scale")]
impl scale::EncodeLike<sp_core::sr25519::Signature> for RistrettoSignature {}
#[cfg(feature = "scale")]
impl scale::EncodeLike<RistrettoSignature> for sp_core::sr25519::Signature {}

/// A general-purpose signature within the Serai protocol.
///
/// This is variadic in order to support distinct signature algorithms in the future without
/// having to break the wire format.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
pub enum Signature {
  /// A Ristretto (sr25519) signature.
  Ristretto(RistrettoSignature),
}
#[cfg(feature = "scale")]
crate::borsh_as_scale!(Signature);

impl From<schnorrkel::Signature> for Signature {
  fn from(signature: schnorrkel::Signature) -> Self {
    Self::Ristretto(signature.into())
  }
}

impl From<sp_core::sr25519::Signature> for Signature {
  fn from(signature: sp_core::sr25519::Signature) -> Self {
    Self::Ristretto(signature.into())
  }
}

impl From<RistrettoSignature> for Signature {
  fn from(signature: RistrettoSignature) -> Self {
    Self::Ristretto(signature)
  }
}

/// The key pair for a validator set.
///
/// This is their Ristretto key, used for publishing data onto Serai, and their key on the external
/// network.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, BorshSerialize, BorshDeserialize)]
#[cfg_attr(feature = "scale", derive(scale::MaxEncodedLen))]
pub struct KeyPair(pub Public, pub ExternalKey);
#[cfg(feature = "scale")]
crate::borsh_as_scale!(KeyPair);

mod sealed {
  use super::*;

  /// [`sp_crypto::core::Derive`], for public keys _and_ pairs.
  pub trait Derive: Sized {
    fn derive(&self, path: impl Iterator<Item = DeriveJunction>) -> Option<Self>;
  }
  impl Derive for sp_core::sr25519::Public {
    fn derive(&self, path: impl Iterator<Item = DeriveJunction>) -> Option<Self> {
      sp_core::crypto::Derive::derive(self, path)
    }
  }
  impl Derive for sp_core::sr25519::Pair {
    fn derive(&self, path: impl Iterator<Item = DeriveJunction>) -> Option<Self> {
      sp_core::crypto::Pair::derive(self, path, None).map(|(pair, _seed)| pair).ok()
    }
  }
}

/// Derive a subkey for a validator.
pub fn subkey<K: sealed::Derive>(key: &K, key_type: KeyTypeId) -> K {
  let key_type: [u8; 4] = key_type.0;
  let mut derivation = [0; 32];
  derivation[28 ..].copy_from_slice(&key_type);

  /*
    This is safe as `Derive::derive` is documented to return `None` when a hard junction (requiring
    a private key) is used with a public key (without a private key). We explicitly use a soft
    junction, as possible with solely the public key.

    https://docs.rs/sp-core/39.0.0/sp_core/crypto/trait.Derive.html#method.derive
  */
  key.derive(core::iter::once(DeriveJunction::Soft(derivation))).unwrap()
}

#[test]
fn public() {
  use rand_core::{RngCore as _, OsRng};

  let mut public = [0; 32];
  OsRng.fill_bytes(&mut public);
  let public = Public(public);

  assert_eq!(
    Public::deserialize_reader(&mut borsh::to_vec(&public).unwrap().as_slice()).unwrap(),
    public
  );

  #[cfg(feature = "scale")]
  {
    use scale::{Encode as _, DecodeAll as _, MaxEncodedLen as _};
    assert_eq!(borsh::to_vec(&public).unwrap(), public.encode());
    assert_eq!(Public::decode_all(&mut public.encode().as_slice()).unwrap(), public);
    assert_eq!(public.encode().len(), Public::max_encoded_len());
    assert_eq!(sp_core::sr25519::Public::from(public).encode(), public.encode());
  }
}

#[test]
fn signature() {
  use rand_core::{RngCore as _, OsRng};

  let mut signature = [0; 64];
  OsRng.fill_bytes(&mut signature);
  let signature = RistrettoSignature(signature);

  assert_eq!(
    RistrettoSignature::deserialize_reader(&mut borsh::to_vec(&signature).unwrap().as_slice())
      .unwrap(),
    signature
  );

  #[cfg(feature = "scale")]
  {
    use scale::{Encode as _, DecodeAll as _};
    assert_eq!(borsh::to_vec(&signature).unwrap(), signature.encode());
    assert_eq!(
      RistrettoSignature::decode_all(&mut signature.encode().as_slice()).unwrap(),
      signature
    );
    assert_eq!(sp_core::sr25519::Signature::from(signature).encode(), signature.encode());
  }

  {
    let signature = Signature::Ristretto(signature);
    assert_eq!(
      Signature::deserialize_reader(&mut borsh::to_vec(&signature).unwrap().as_slice()).unwrap(),
      signature
    );

    #[cfg(feature = "scale")]
    {
      use scale::{Encode as _, DecodeAll as _};
      assert_eq!(borsh::to_vec(&signature).unwrap(), signature.encode());
      assert_eq!(Signature::decode_all(&mut signature.encode().as_slice()).unwrap(), signature);
    }
  }
}

#[cfg(feature = "std")]
#[test]
fn subkeys() {
  use rand_core::OsRng;

  use sp_core::Pair as _;

  let pair = sp_core::sr25519::Pair::from(schnorrkel::Keypair::generate_with(&mut OsRng));
  let public = pair.public();

  for key_type in [key_types::BABE, key_types::GRANDPA, key_types::AUTHORITY_DISCOVERY] {
    // The subkey for a key pair should be the public key of the subpair.
    assert_eq!(subkey(&pair, key_type).public(), subkey(&public, key_type));
  }
}

#[test]
fn key_pair() {
  use alloc::vec;
  use rand_core::{RngCore as _, OsRng};

  #[cfg(feature = "scale")]
  use scale::{Encode as _, MaxEncodedLen as _};

  // Check `max_encoded_len` is correctly defined
  #[cfg(feature = "scale")]
  assert_eq!(
    KeyPair::max_encoded_len(),
    KeyPair(
      Public([0; 32]),
      ExternalKey({
        let mut vec = sp_core::bounded::BoundedVec::new();
        while vec.try_push(0).is_ok() {}
        vec
      })
    )
    .encode()
    .len()
  );

  // Fuzz test various `KeyPair`s
  for _ in 0 .. 100 {
    let key_pair = {
      let mut public = Public([0; 32]);
      OsRng.fill_bytes(&mut public.0);
      let mut vec =
        vec![0; usize::try_from(OsRng.next_u64() % u64::from(ExternalKey::MAX_SIZE)).unwrap()];
      OsRng.fill_bytes(&mut vec);
      let external_key = ExternalKey(vec.try_into().unwrap());
      KeyPair(public, external_key)
    };

    assert_eq!(
      KeyPair::deserialize_reader(&mut borsh::to_vec(&key_pair).unwrap().as_slice()).unwrap(),
      key_pair
    );

    #[cfg(feature = "scale")]
    use scale::{Encode as _, DecodeAll as _};
    #[cfg(feature = "scale")]
    assert_eq!(
      KeyPair::decode_all(&mut borsh::to_vec(&key_pair).unwrap().as_slice()).unwrap(),
      key_pair
    );
    #[cfg(feature = "scale")]
    assert_eq!(KeyPair::deserialize_reader(&mut key_pair.encode().as_slice()).unwrap(), key_pair);
  }
}
