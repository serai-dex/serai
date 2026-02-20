use core::str::FromStr as _;

use zeroize::Zeroize as _;

use sp_core::{crypto::*, sr25519};
use sp_keystore::*;

use serai_abi::primitives::address::SeraiAddress;

pub struct Keystore(sr25519::Pair);

impl From<sr25519::Pair> for Keystore {
  fn from(keypair: sr25519::Pair) -> Self {
    Self(keypair)
  }
}

impl Keystore {
  pub fn from_env() -> Option<(SeraiAddress, Self)> {
    let address = serai_env::var("ADDRESS")?;
    let address =
      SeraiAddress::from_str(&address).expect("validator address wasn't properly specified");

    let mut key_hex = serai_env::var("KEY")?;
    if key_hex.trim().is_empty() {
      None?;
    }
    let mut key = hex::decode(&key_hex).expect("KEY from environment wasn't hex");
    key_hex.zeroize();

    assert_eq!(key.len(), 32, "KEY from environment wasn't 32 bytes");
    key.extend(sp_core::blake2_256(&key));

    let res = Self::from(sr25519::Pair::from(schnorrkel::SecretKey::from_bytes(&key).unwrap()));
    key.zeroize();
    Some((address, res))
  }

  fn pair(&self, id: KeyTypeId) -> sr25519::Pair {
    let mut junction = [0; 32];
    junction[28 ..].copy_from_slice(&id.0);
    self.0.derive(core::iter::once(DeriveJunction::Soft(junction)), None).unwrap().0
  }
}

impl sp_keystore::Keystore for Keystore {
  fn sr25519_public_keys(&self, id: KeyTypeId) -> Vec<sr25519::Public> {
    vec![self.pair(id).public()]
  }

  fn sr25519_generate_new(&self, _: KeyTypeId, _: Option<&str>) -> Result<sr25519::Public, Error> {
    panic!("asked to generate an sr25519 key");
  }

  fn sr25519_sign(
    &self,
    id: KeyTypeId,
    public: &sr25519::Public,
    msg: &[u8],
  ) -> Result<Option<sr25519::Signature>, Error> {
    let pair = self.pair(id);

    if public == &pair.public() {
      Ok(Some(pair.sign(msg)))
    } else {
      Ok(None)
    }
  }

  fn sr25519_vrf_sign(
    &self,
    id: KeyTypeId,
    public: &sr25519::Public,
    data: &sr25519::vrf::VrfSignData,
  ) -> Result<Option<sr25519::vrf::VrfSignature>, Error> {
    let pair = self.pair(id);

    if public == &pair.public() {
      Ok(Some(pair.vrf_sign(data)))
    } else {
      Ok(None)
    }
  }

  fn sr25519_vrf_pre_output(
    &self,
    id: KeyTypeId,
    public: &sr25519::Public,
    input: &sr25519::vrf::VrfInput,
  ) -> Result<Option<sr25519::vrf::VrfPreOutput>, Error> {
    let pair = self.pair(id);

    if public == &pair.public() {
      Ok(Some(pair.vrf_pre_output(input)))
    } else {
      Ok(None)
    }
  }

  fn insert(&self, _: KeyTypeId, _: &str, _: &[u8]) -> Result<(), ()> {
    panic!("asked to insert a key");
  }

  fn keys(&self, id: KeyTypeId) -> Result<Vec<Vec<u8>>, Error> {
    Ok(vec![self.pair(id).public().0.to_vec()])
  }

  fn has_keys(&self, public_keys: &[(Vec<u8>, KeyTypeId)]) -> bool {
    for (public_key, id) in public_keys {
      if self.pair(*id).public().0.as_slice() != public_key {
        return false;
      }
    }
    true
  }
}
