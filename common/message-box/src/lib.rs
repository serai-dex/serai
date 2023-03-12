#![cfg_attr(docsrs, feature(doc_auto_cfg))]

use core::{
  ops::Deref,
  hash::Hash,
  fmt::{Debug, Formatter},
};
use std::collections::HashMap;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use rand_core::{RngCore, OsRng};

use group::{Group, GroupEncoding};
use dalek_ff_group::{Scalar, RistrettoPoint};
use ciphersuite::Ristretto;

use transcript::{Transcript, RecommendedTranscript};

use schnorr::SchnorrSignature;

pub use serde::{
  Serializer, Serialize, Deserialize,
  de::{Error, Deserializer, DeserializeOwned},
};

mod keys;
pub use keys::*;

#[cfg(test)]
mod tests;

fn transcript() -> RecommendedTranscript {
  RecommendedTranscript::new(b"MessageBox")
}

/// Stub trait for obtaining the bytes of a value.
pub trait AsDesignatedVerifier {
  type Output: AsRef<[u8]>;
  fn as_designated_verifier(&self) -> Option<Self::Output>;
}

#[allow(non_snake_case)]
pub(crate) fn signature_challenge<V: AsDesignatedVerifier>(
  recipient: &V,
  R: RistrettoPoint,
  A: RistrettoPoint,
  msg: &[u8],
) -> Scalar {
  let mut transcript = transcript();

  if let Some(recipient) = recipient.as_designated_verifier() {
    transcript.domain_separate(b"recipient");
    transcript.append_message(b"name", recipient);
  }

  transcript.domain_separate(b"signature");
  transcript.append_message(b"nonce", R.to_bytes());
  transcript.append_message(b"public_key", A.to_bytes());

  transcript.append_message(b"message", msg);

  Scalar::from_bytes_mod_order_wide(&transcript.challenge(b"challenge").into())
}

/// A Signed Message.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Message<M: Serialize> {
  msg: M,
  #[serde(serialize_with = "serialize_sig")]
  #[serde(deserialize_with = "deserialize_sig")]
  sig: SchnorrSignature<Ristretto>,
}

fn serialize_sig<S: Serializer>(
  sig: &SchnorrSignature<Ristretto>,
  serializer: S,
) -> Result<S::Ok, S::Error> {
  let sig = sig.serialize();
  #[allow(non_snake_case)]
  let mut R = [0; 32];
  let mut s = [0; 32];
  R.copy_from_slice(&sig[.. 32]);
  s.copy_from_slice(&sig[32 ..]);
  (R, s).serialize(serializer)
}

fn deserialize_sig<'de, D: Deserializer<'de>>(
  deserializer: D,
) -> Result<SchnorrSignature<Ristretto>, D::Error> {
  let sig = <([u8; 32], [u8; 32])>::deserialize(deserializer)?;
  SchnorrSignature::<Ristretto>::read::<&[u8]>(
    &mut [sig.0.as_ref(), sig.1.as_ref()].concat().as_ref(),
  )
  .map_err(|_| D::Error::custom("invalid signature"))
}

impl<M: Serialize + DeserializeOwned> Message<M> {
  pub fn to_bytes(&self) -> Vec<u8> {
    bincode::serialize(self).unwrap()
  }
}

impl<M: Serialize + DeserializeOwned> ToString for Message<M> {
  fn to_string(&self) -> String {
    serde_json::to_string(self).unwrap()
  }
}

/// A box enabling authenticating messages to/from various other peers.
pub struct MessageBox<K: Copy + Eq + Hash + Debug + AsDesignatedVerifier> {
  our_name: K,
  our_key: PrivateKey,
  // Optimization for later transcripting
  our_public_key: RistrettoPoint,
  // When generating nonces, we transcript additional entropy to hedge against weak randomness
  // This is primarily the private key, yet also an early set of bytes from the OsRng which may
  // have a higher quality entropy than latter calls
  // Instead of constantly passing around the private key bytes/early RNG, littering memory with
  // copies, store a copy which is already hashed
  additional_entropy: [u8; 64],

  pub_keys: HashMap<K, RistrettoPoint>,
}

impl<K: Copy + Eq + Hash + Debug + AsDesignatedVerifier> Debug for MessageBox<K> {
  fn fmt(&self, fmt: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
    fmt
      .debug_struct("MessageBox")
      .field("our_name", &self.our_name)
      .field("our_public_key", &self.our_public_key)
      .field("pub_keys", &self.pub_keys)
      .finish_non_exhaustive()
  }
}

impl<K: Copy + Eq + Hash + Debug + AsDesignatedVerifier> Zeroize for MessageBox<K> {
  fn zeroize(&mut self) {
    // Doesn't zeroize our_name as we can't if it's &'static str
    self.our_key.zeroize();
    self.our_public_key.zeroize();
    self.additional_entropy.zeroize();
    for (_, key) in self.pub_keys.iter_mut() {
      key.zeroize();
    }
  }
}
impl<K: Copy + Eq + Hash + Debug + AsDesignatedVerifier> Drop for MessageBox<K> {
  fn drop(&mut self) {
    self.zeroize();
  }
}
impl<K: Copy + Eq + Hash + Debug + AsDesignatedVerifier> ZeroizeOnDrop for MessageBox<K> {}

impl<K: Copy + Eq + Hash + Debug + AsDesignatedVerifier> MessageBox<K> {
  fn add_generic(&mut self, name: K, key: RistrettoPoint) {
    self.pub_keys.insert(name, key);
  }

  pub fn remove(&mut self, name: &K) {
    self.pub_keys.remove(name);
  }

  /// Create a new message box with our identity and the identities of our peers.
  fn new_generic(our_name: K, our_key: PrivateKey, mut keys: HashMap<K, PublicKey>) -> Self {
    let mut res = MessageBox {
      additional_entropy: {
        let mut transcript = transcript();
        transcript.domain_separate(b"additional_entropy");

        {
          let mut key_bytes = our_key.0.to_bytes();
          transcript.append_message(b"private_key", key_bytes.as_ref());
          key_bytes.zeroize();
        }

        // This is exceptionally redundant and arguably pointless
        // The initial idea was to use the private_key as additional entropy
        // Then it was to hash it in order to reduce the copies in memory
        // Then it was to use a transcript for a structured hash, as we have a transcript available
        // And then it was why *not* add additional fields
        {
          // Uses 64-bytes so the input matches the output length, since the full output is needed
          // to perform wide reduction (though a similarly sized output could also be rehashed
          // to perform rejection sampling)
          let mut bytes = [0; 64];
          OsRng.fill_bytes(&mut bytes);
          transcript.append_message(b"rng", bytes.as_ref());
          bytes.zeroize();
        }

        transcript.challenge(b"entropy").into()
      },

      our_name,
      our_public_key: RistrettoPoint::generator() * our_key.0.deref(),
      our_key,

      pub_keys: HashMap::new(),
    };

    for (name, key) in keys.drain().map(|(name, key)| (name, key.0)) {
      res.add_generic(name, key);
    }
    res
  }

  // Sign a message to be sent to another party.
  fn sign_generic<M: Serialize + DeserializeOwned>(&self, to: &K, msg: M) -> Message<M> {
    let msg_ser = bincode::serialize(&msg).unwrap();
    let nonce = {
      let mut transcript = transcript();
      transcript.domain_separate(b"nonce");

      // Transcript everything committed to in the challenge
      // This would create a secure, deterministic nonce scheme, so long as the private key is also
      // hashed in order to ensure that it isn't based off of public data alone
      // THe private key is indirectly included via the below additional entropy, ensuring a lack
      // of potential for nonce reuse
      if let Some(to) = to.as_designated_verifier() {
        transcript.append_message(b"to", to);
      }
      transcript.append_message(b"public_key", self.our_public_key.to_bytes());
      transcript.append_message(b"message", &msg_ser);

      // Transcript entropy
      // While this could be fully deterministic, anyone who recovers the entropy can recover the
      // nonce and therefore the private key. While recovering additional_entropy should be as
      // difficult as recovering our_key, this entropy binds the nonce's recoverability lifespan
      // to the lifetime of this specific entropy and this specific nonce
      let mut entropy = [0; 32];
      OsRng.fill_bytes(&mut entropy);
      transcript.append_message(b"entropy", entropy.as_ref());
      entropy.zeroize();

      // Not only does this include the private key, making this a valid deterministic nonce
      // scheme, it includes entropy from the start of the program's lifetime (hedging against a
      // RNG which has decreased in entropy), binding the nonce's recoverability to the lifespan of
      // this program
      transcript.append_message(b"additional_entropy", self.additional_entropy.as_ref());

      let mut nonce = transcript.challenge(b"nonce").into();
      let res = Zeroizing::new(Scalar::from_bytes_mod_order_wide(&nonce));
      nonce.zeroize();
      res
    };

    #[allow(non_snake_case)]
    let R = RistrettoPoint::generator() * nonce.deref();
    let sig = SchnorrSignature::<Ristretto>::sign(
      &self.our_key.0, // SchnorrSignature will zeroize this copy.
      nonce,
      signature_challenge(to, R, self.our_public_key, &msg_ser),
    );

    Message { msg, sig }
  }

  /// Verify a message.
  pub fn verify<M: Serialize + DeserializeOwned>(&self, from: &K, msg: Message<M>) -> Option<M> {
    let Message { msg, sig } = msg;

    if !sig.verify(
      self.pub_keys[from],
      signature_challenge(
        &self.our_name,
        sig.R,
        self.pub_keys[from],
        &bincode::serialize(&msg).unwrap(),
      ),
    ) {
      return None;
    }

    Some(msg)
  }
}

impl AsDesignatedVerifier for &'static str {
  type Output = &'static [u8];
  fn as_designated_verifier(&self) -> Option<Self::Output> {
    Some(str::as_bytes(self))
  }
}

pub type InternalMessageBox = MessageBox<&'static str>;
impl InternalMessageBox {
  pub fn new(
    our_name: &'static str,
    our_key: PrivateKey,
    keys: HashMap<&'static str, PublicKey>,
  ) -> Self {
    MessageBox::new_generic(our_name, our_key, keys)
  }

  // TODO: Remove
  pub fn add(&mut self, name: &'static str, key: PublicKey) {
    self.add_generic(name, key.0);
  }

  pub fn sign<M: Serialize + DeserializeOwned>(&self, to: &'static str, msg: M) -> Message<M> {
    self.sign_generic(&to, msg)
  }

  pub fn deserialize<M: Serialize + DeserializeOwned>(
    &self,
    from: &'static str,
    msg: &str,
  ) -> Option<M> {
    self.verify(&from, serde_json::from_str(msg).ok()?)
  }
}

// Don't utilize weakly designated-verified challenges for the P2P layer, which broadcasts
impl AsDesignatedVerifier for PublicKey {
  type Output = [u8; 0];
  fn as_designated_verifier(&self) -> Option<Self::Output> {
    None
  }
}

pub type ExternalMessageBox = MessageBox<PublicKey>;
impl ExternalMessageBox {
  pub fn new(our_key: PrivateKey) -> Self {
    ExternalMessageBox::new_generic(our_key.to_public(), our_key, HashMap::new())
  }

  pub fn add(&mut self, key: PublicKey) {
    self.add_generic(key, key.0);
  }

  pub fn sign<M: Serialize + DeserializeOwned>(&self, msg: M) -> Message<M> {
    self.sign_generic(&PublicKey(RistrettoPoint::identity()), msg)
  }

  pub fn deserialize<M: Serialize + DeserializeOwned>(
    &self,
    from: &PublicKey,
    msg: &[u8],
  ) -> Option<M> {
    self.verify(from, bincode::deserialize(msg).ok()?)
  }
}
