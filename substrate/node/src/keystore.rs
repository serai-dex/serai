use core::{ops::Deref as _, str::FromStr as _};

use zeroize::Zeroizing;

use sp_core::{crypto::*, sr25519};
use sp_keystore::*;

use serai_abi::primitives::address::SeraiAddress;

use serai_env::Environment;

/// The Serai Keystore.
///
/// This is a keystore explicitly intended for use as seen when operating a Serai node. It differs
/// from more traditional keystores, such as the ones provided by Substrate, accordingly. It
/// FUNDAMENTALLY holds a single underlying key pair, intended to be the Serai auxiliary key set by
/// a validator in order to operate their node with.
///
/// When a conventional Substrate node begins, it passes a handle to the keystore into the runtime
/// which handles generation of the declared session keys. These are domain-specific keys, which
/// may make use of distinct cryptographic premises, and can be independently rotated.
///
/// Serai's cryptography is homogenized to Ristretto, allowing it to solely consider such a case.
/// Additionally, instead of defining independent keys for each context, each context derives a key
/// from the single auxiliary key. This is safe as even though such keys have know relation, the
/// signatures over Ristretto produced are key-binding, preventing transposition.
///
/// Because only a single elliptic curve has to be considered, and keys are dependent, the keystore
/// is enabled to map to a single underlying key pair and never have to consider multiple keys. To
/// this end, the keystore is simplified to a wrapper around a single Ristretto key pair. This
/// makes it unable to facilitate certain methods with the keystore `trait` however, leaving a
/// variety `unimplemented` and prone to runtime panics, making it only fit for usage as exactly
/// used within the Serai node.
///
/// For context on the history of this, please see https://github.com/serai-dex/serai/issues/735.
pub(crate) struct Keystore(sr25519::Pair);

impl From<sr25519::Pair> for Keystore {
  fn from(keypair: sr25519::Pair) -> Self {
    Self(keypair)
  }
}

impl Keystore {
  /// Construct a keystore from the environment, as exposed via `serai-env`.
  ///
  /// This will return the address specified within the environment, intended to be the address of
  /// the validator this keystore is used by (or otherwise associated with). The key itself is
  /// intended to be the validator's auxiliary key.
  ///
  /// This function expects the following environment variables to be set:
  ///
  /// - `ADDRESS`: The validator's address
  ///
  /// - `SERAI_AUXILIARY_KEY`: The validator's auxiliary key for the Serai network, encoded as
  ///   hexadecimal bytes
  ///
  /// Note using a process's environment variables for key material is generally insecure as
  /// unprivileged processes can generally read the environment variables of other processes.
  /// `serai-env` is expected to provide variables from an environment without using the process's
  /// literal environment, resolving this concern.
  ///
  /// This function MAY panic if the environment variables were not set as expected, even if the
  /// environment variables meet the description specified within this function. It is intended
  /// solely for use within the Serai node upon its initialization with no further safety offerred.
  pub(crate) fn from_env(env: &Environment) -> Option<(SeraiAddress, Self)> {
    let address = env.var("ADDRESS")?;
    let address =
      SeraiAddress::from_str(address).expect("validator address wasn't properly specified");

    let key_hex = env.var("SERAI_AUXILIARY_KEY")?;
    if key_hex.trim().is_empty() {
      None?;
    }
    let mut key_bytes = Zeroizing::new([0; 32 + 32]);
    base16ct::mixed::decode(key_hex.as_bytes(), &mut key_bytes[.. 32])
      .expect("`SERAI_AUXILIARY_KEY` from environment wasn't 32 hex-encoded bytes");

    /*
      Fill in the seed used for the nonce with the hash of the private key.

      This differs from the traditional flow for Ed25519, and similar, due to deterministically
      deriving nonces from a seed the hash of the private key itself. Generally, a seed of entropy
      is simultaneously expanded into both the private key and the deterministic seed for nonces.
      Regardless, hashing the private key alone is generally satisfactory for deterministic nonces,
      and the distribution of the seed for nonces is still uniformly random so long as we trust the
      hash function used to function as a random oracle.

      There is the commentary that this isn't as post-quantum in that an Ed25519 signature may have
      the private key recovered from it, but not the underlying entropy if the key was generated as
      traditionally done, allowing whoever has the entropy to create a post-quantum proof they know
      the entropy and it does expand to the private key to prove they were the original key holder
      and not a key holder by virtue of recovering the private key. We forsake such ideals for the
      practicality of this and independent requirement for comprehensive post-quantum policy.
    */
    let nonce_seed = Zeroizing::new(sp_crypto_hashing::blake2_256(&key_bytes[.. 32]));
    key_bytes[32 ..].copy_from_slice(nonce_seed.as_slice());

    let res = Self::from(sr25519::Pair::from(
      schnorrkel::SecretKey::from_bytes(key_bytes.deref()).unwrap(),
    ));
    Some((address, res))
  }

  /// The key pair for the specified context ([`KeyTypeId`]).
  ///
  /// This follows the derivation schema employed by [`serai_validator_sets_pallet::subkey`]. It
  /// applies the scheme to a key pair however, not to a public key.
  // TODO: Have `serai_validator_sets_pallet::subkey` take `T: Derive` so we can reuse it here?
  pub(super) fn pair(&self, id: KeyTypeId) -> sr25519::Pair {
    let mut junction = [0; 32];
    junction[28 ..].copy_from_slice(&id.0);
    self.0.derive(core::iter::once(DeriveJunction::Soft(junction)), None).unwrap().0
  }
}

impl sp_keystore::Keystore for Keystore {
  fn sr25519_public_keys(&self, id: KeyTypeId) -> Vec<sr25519::Public> {
    vec![self.pair(id).public()]
  }

  /// This will panic as the keystore is intended for sole usage with a single key as constructed.
  fn sr25519_generate_new(&self, _: KeyTypeId, _: Option<&str>) -> Result<sr25519::Public, Error> {
    unimplemented!("asked to generate an sr25519 key");
  }

  fn sr25519_sign(
    &self,
    id: KeyTypeId,
    public: &sr25519::Public,
    msg: &[u8],
  ) -> Result<Option<sr25519::Signature>, Error> {
    let pair = self.pair(id);
    Ok((public == &pair.public()).then(|| pair.sign(msg)))
  }

  fn sr25519_vrf_sign(
    &self,
    id: KeyTypeId,
    public: &sr25519::Public,
    data: &sr25519::vrf::VrfSignData,
  ) -> Result<Option<sr25519::vrf::VrfSignature>, Error> {
    let pair = self.pair(id);
    Ok((public == &pair.public()).then(|| pair.vrf_sign(data)))
  }

  fn sr25519_vrf_pre_output(
    &self,
    id: KeyTypeId,
    public: &sr25519::Public,
    input: &sr25519::vrf::VrfInput,
  ) -> Result<Option<sr25519::vrf::VrfPreOutput>, Error> {
    let pair = self.pair(id);
    Ok((public == &pair.public()).then(|| pair.vrf_pre_output(input)))
  }

  /// This will panic as the keystore is intended for sole usage with a single key as constructed.
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
