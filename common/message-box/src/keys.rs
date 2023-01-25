use core::{ops::Deref, hash::Hash, fmt::Debug};

use zeroize::{Zeroize, Zeroizing, ZeroizeOnDrop};

use rand_core::OsRng;

use group::{
  ff::{Field, PrimeField},
  Group, GroupEncoding,
};
use dalek_ff_group::{Scalar, RistrettoPoint};

use serde::{
  Serializer, Serialize, Deserialize,
  de::{Error, Deserializer},
};

/// Private Key for a Message Box.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey(pub(crate) Zeroizing<Scalar>);
impl PrivateKey {
  #[doc(hidden)]
  pub unsafe fn inner(&self) -> &Zeroizing<Scalar> {
    &self.0
  }

  pub fn to_public(&self) -> PublicKey {
    PublicKey(RistrettoPoint::generator() * self.0.deref())
  }

  /// Parse a Private Key from a string. Panics if an invalid is key.
  pub fn from_string(mut str: String) -> PrivateKey {
    let mut bytes = base64::decode::<&str>(str.as_ref()).unwrap().try_into().unwrap();
    str.zeroize();
    let res = PrivateKey(Zeroizing::new(Scalar::from_repr(bytes).unwrap()));
    bytes.zeroize();
    res
  }

  /// Serialize a Private Key to a string.
  #[deprecated]
  #[allow(clippy::inherent_to_string)]
  pub fn to_string(&self) -> String {
    let bytes = Zeroizing::new(self.0.to_repr());
    base64::encode(bytes.deref())
  }
}

/// Public Key for a Message Box.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Zeroize)]
pub struct PublicKey(pub(crate) RistrettoPoint);

impl PublicKey {
  /// Parse a Public Key from a string. Panics if an invalid key is used.
  pub fn from_trusted_str(str: &str) -> Self {
    Self::from_str(str).unwrap()
  }

  /// Parse a Public Key from a string.
  #[allow(clippy::should_implement_trait)]
  pub fn from_str(str: &str) -> Option<Self> {
    Option::from(RistrettoPoint::from_bytes(&base64::decode(str).ok()?.try_into().ok()?)).map(Self)
  }
}

impl ToString for PublicKey {
  fn to_string(&self) -> String {
    base64::encode(self.0.to_bytes())
  }
}

impl Serialize for PublicKey {
  fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
    self.0.to_bytes().serialize(serializer)
  }
}

impl<'de> Deserialize<'de> for PublicKey {
  fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
    Option::from(RistrettoPoint::from_bytes(&<[u8; 32]>::deserialize(deserializer)?))
      .ok_or(D::Error::custom("invalid public key"))
      .map(Self)
  }
}

/// Generate a key pair
pub fn key_gen() -> (PrivateKey, PublicKey) {
  let mut scalar;
  while {
    scalar = Zeroizing::new(Scalar::random(&mut OsRng));
    scalar.is_zero().into()
  } {}
  let public = RistrettoPoint::generator() * scalar.deref();
  (PrivateKey(scalar), PublicKey(public))
}
