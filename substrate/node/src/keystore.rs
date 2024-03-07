use zeroize::Zeroize;

use sp_core::{crypto::*, ed25519, sr25519};
use sp_keystore::*;

pub struct Keystore(sr25519::Pair);

impl Keystore {
  pub fn from_env() -> Option<Self> {
    let mut key_hex = serai_env::var("KEY")?;
    let mut key = hex::decode(&key_hex).expect("KEY from environment wasn't hex");
    key_hex.zeroize();

    assert_eq!(key.len(), 32, "KEY from environment wasn't 32 bytes");
    key.extend(sp_core::blake2_256(&key));

    let res = Self(sr25519::Pair::from(schnorrkel::SecretKey::from_bytes(&key).unwrap()));
    key.zeroize();
    Some(res)
  }
}

impl sp_keystore::Keystore for Keystore {
  fn sr25519_public_keys(&self, _: KeyTypeId) -> Vec<sr25519::Public> {
    vec![self.0.public()]
  }

  fn sr25519_generate_new(&self, _: KeyTypeId, _: Option<&str>) -> Result<sr25519::Public, Error> {
    panic!("asked to generate an sr25519 key");
  }

  fn sr25519_sign(
    &self,
    _: KeyTypeId,
    public: &sr25519::Public,
    msg: &[u8],
  ) -> Result<Option<sr25519::Signature>, Error> {
    if public == &self.0.public() {
      Ok(Some(self.0.sign(msg)))
    } else {
      Ok(None)
    }
  }

  fn sr25519_vrf_sign(
    &self,
    _: KeyTypeId,
    public: &sr25519::Public,
    data: &sr25519::vrf::VrfSignData,
  ) -> Result<Option<sr25519::vrf::VrfSignature>, Error> {
    if public == &self.0.public() {
      Ok(Some(self.0.vrf_sign(data)))
    } else {
      Ok(None)
    }
  }

  fn sr25519_vrf_output(
    &self,
    _: KeyTypeId,
    public: &sr25519::Public,
    input: &sr25519::vrf::VrfInput,
  ) -> Result<Option<sr25519::vrf::VrfOutput>, Error> {
    if public == &self.0.public() {
      Ok(Some(self.0.vrf_output(input)))
    } else {
      Ok(None)
    }
  }

  fn ed25519_public_keys(&self, _: KeyTypeId) -> Vec<ed25519::Public> {
    panic!("asked for ed25519 keys");
  }

  fn ed25519_generate_new(&self, _: KeyTypeId, _: Option<&str>) -> Result<ed25519::Public, Error> {
    panic!("asked to generate an ed25519 key");
  }

  fn ed25519_sign(
    &self,
    _: KeyTypeId,
    _: &ed25519::Public,
    _: &[u8],
  ) -> Result<Option<ed25519::Signature>, Error> {
    panic!("asked to produce an ed25519 signature");
  }

  fn insert(&self, _: KeyTypeId, _: &str, _: &[u8]) -> Result<(), ()> {
    panic!("asked to insert a key");
  }

  fn keys(&self, _: KeyTypeId) -> Result<Vec<Vec<u8>>, Error> {
    Ok(vec![self.0.public().0.to_vec()])
  }

  fn has_keys(&self, public_keys: &[(Vec<u8>, KeyTypeId)]) -> bool {
    let our_key = self.0.public().0;
    for (public_key, _) in public_keys {
      if our_key != public_key.as_slice() {
        return false;
      }
    }
    true
  }
}
