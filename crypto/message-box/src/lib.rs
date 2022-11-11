#![cfg_attr(docsrs, feature(doc_auto_cfg))]

use core::{
  ops::Deref,
  cmp::Ordering,
  fmt::{Debug, Formatter},
};
use std::collections::HashMap;

use thiserror::Error;

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
use rand_core::{RngCore, OsRng};

use group::{
  ff::{Field, PrimeField},
  Group, GroupEncoding,
};
use dalek_ff_group::{Scalar, RistrettoPoint};
use ciphersuite::Ristretto;

use transcript::{Transcript, RecommendedTranscript};
use chacha20::{
  cipher::{KeyIvInit, StreamCipher},
  Key, XNonce, XChaCha20,
};

use schnorr::SchnorrSignature;

pub use serde::{Serialize, Deserialize};

mod ser;
use ser::*;

#[cfg(test)]
mod tests;

/// Private Key for a Message Box.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct PrivateKey(pub(crate) Zeroizing<Scalar>);
impl PrivateKey {
  #[doc(hidden)]
  pub unsafe fn inner(&self) -> &Zeroizing<Scalar> {
    &self.0
  }

  /// Parse a Private Key from a string.
  pub fn from_string(mut str: String) -> PrivateKey {
    let mut bytes = hex::decode::<&str>(str.as_ref()).unwrap().try_into().unwrap();
    str.zeroize();
    let res = PrivateKey(Zeroizing::new(Scalar::from_repr(bytes).unwrap()));
    bytes.zeroize();
    res
  }
}

/// Public Key for a Message Box.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize)]
pub struct PublicKey(RistrettoPoint);
impl PublicKey {
  /// Parse a Public Key from a string. Panics if an invalid key is used.
  pub fn from_str(str: &str) -> Self {
    Self::from_bytes(&hex::decode(str).unwrap().try_into().unwrap()).unwrap()
  }

  /// Serialize a Public Key to bytes.
  pub fn to_bytes(&self) -> [u8; 32] {
    self.0.to_bytes()
  }

  /// Parse a Public Key from bytes.
  pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
    Option::from(RistrettoPoint::from_bytes(bytes)).map(PublicKey)
  }
}

/// Error from creating/decrypting a message.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Error)]
pub enum MessageError {
  #[error("message was incomplete")]
  Incomplete,
  #[error("invalid encoding")]
  InvalidEncoding,
}

/// A Secure Message, defined as being not only encrypted yet authenticated.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SecureMessage {
  #[serde(serialize_with = "serialize_iv")]
  #[serde(deserialize_with = "deserialize_iv")]
  iv: XNonce,
  ciphertext: Vec<u8>,
  #[serde(serialize_with = "serialize_sig")]
  #[serde(deserialize_with = "deserialize_sig")]
  sig: SchnorrSignature<Ristretto>,
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

fn transcript() -> RecommendedTranscript {
  RecommendedTranscript::new(b"MessageBox")
}

#[allow(non_snake_case)]
fn signature_challenge(
  recipient: &'static str,
  R: RistrettoPoint,
  A: RistrettoPoint,
  iv: &XNonce,
  enc_msg: &[u8],
) -> Scalar {
  let mut transcript = transcript();

  transcript.domain_separate(b"recipient");
  transcript.append_message(b"name", recipient.as_bytes());

  transcript.domain_separate(b"signature");
  transcript.append_message(b"nonce", R.to_bytes());
  transcript.append_message(b"public_key", A.to_bytes());

  transcript.domain_separate(b"message");
  transcript.append_message(b"iv", iv);
  transcript.append_message(b"encrypted_message", enc_msg);

  Scalar::from_bytes_mod_order_wide(&transcript.challenge(b"challenge").into())
}

/// MessageBox. A box enabling encrypting and decrypting messages to/from various other peers.
pub struct MessageBox {
  our_name: &'static str,
  our_key: PrivateKey,
  // Optimization for later transcripting
  our_public_key: RistrettoPoint,
  // When generating nonces, we transcript additional entropy to hedge against weak randomness
  // This is primarily the private key, yet also an early set of bytes from the OsRng which may
  // have a higher quality entropy than latter calls
  // Instead of constantly passing around the private key bytes/early RNG, littering memory with
  // copies, store a copy which is already hashed
  additional_entropy: [u8; 64],

  pub_keys: HashMap<&'static str, RistrettoPoint>,
  enc_keys: HashMap<&'static str, Key>,
}

impl Debug for MessageBox {
  fn fmt(&self, fmt: &mut Formatter<'_>) -> Result<(), core::fmt::Error> {
    fmt
      .debug_struct("MessageBox")
      .field("our_name", &self.our_name)
      .field("our_public_key", &self.our_public_key)
      .field("pub_keys", &self.pub_keys)
      .finish()
  }
}

impl Zeroize for MessageBox {
  fn zeroize(&mut self) {
    self.our_key.zeroize();
    self.our_public_key.zeroize();
    self.additional_entropy.zeroize();
    for (_, key) in self.pub_keys.iter_mut() {
      key.zeroize();
    }
    for (_, key) in self.enc_keys.iter_mut() {
      key.zeroize();
    }
  }
}
impl Drop for MessageBox {
  fn drop(&mut self) {
    self.zeroize();
  }
}
impl ZeroizeOnDrop for MessageBox {}

impl MessageBox {
  /// Create a new message box with our identity and the identities of our peers.
  pub fn new(
    our_name: &'static str,
    our_key: PrivateKey,
    mut keys: HashMap<&'static str, PublicKey>,
  ) -> MessageBox {
    let keys = keys
      .drain()
      .map(|(name, key)| (name, key.0))
      .collect::<HashMap<&'static str, RistrettoPoint>>();

    MessageBox {
      enc_keys: keys
        .iter()
        .map(|(other_name, other_key)| {
          let mut transcript = transcript();
          transcript.domain_separate(b"encryption_keys");

          // We could make these encryption keys directional, yet the sender is clearly established
          // by the Ristretto signature
          let (name_a, name_b) = match our_name.cmp(other_name) {
            Ordering::Less => (our_name, *other_name),
            Ordering::Equal => panic!("encrypting to ourself"),
            Ordering::Greater => (*other_name, our_name),
          };
          transcript.append_message(b"name_a", name_a.as_bytes());
          transcript.append_message(b"name_b", name_b.as_bytes());

          transcript.append_message(b"shared_key", (*other_key * our_key.0.deref()).to_bytes());
          let shared_key = transcript.challenge(b"encryption_key");

          let mut key = Key::default();
          debug_assert_eq!(key.len(), 32);
          key.copy_from_slice(&shared_key[.. 32]);

          (*other_name, key)
        })
        .collect(),
      pub_keys: keys,

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
    }
  }

  /// Encrypt bytes to be sent to another party.
  pub fn encrypt_bytes(&self, to: &'static str, mut msg: Vec<u8>) -> SecureMessage {
    let mut iv = XNonce::default();
    OsRng.fill_bytes(iv.as_mut());
    XChaCha20::new(&self.enc_keys[to], &iv).apply_keystream(msg.as_mut());

    let nonce = {
      let mut transcript = transcript();
      transcript.domain_separate(b"nonce");

      // Transcript everything committed to in the challenge
      // This would create a secure, deterministic nonce scheme, so long as the private key is also
      // hashed in order to ensure that it isn't based off of public data alone
      // THe private key is indirectly included via the below additional entropy, ensuring a lack
      // of potential for nonce reuse
      transcript.append_message(b"to", to.as_bytes());
      transcript.append_message(b"public_key", self.our_public_key.to_bytes());
      transcript.append_message(b"iv", iv);
      transcript.append_message(b"message", &msg);

      // Transcript entropy
      // While this could be fully deterministic, anyone who recovers the entropy can recover the
      // nonce and therefore the private key. While recovering additional_entropy should be as
      // difficult as recovering our_key, this entropy binds the nonce's recoverability lifespan
      // to the lifetime of this specific entropy and this specific nonce
      let mut entropy = [0; 64];
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
      signature_challenge(to, R, self.our_public_key, &iv, &msg),
    );

    let mut res = iv.to_vec();
    sig.write(&mut res).unwrap();
    res.extend(&msg);

    SecureMessage { iv, ciphertext: msg, sig }
  }

  /// Decrypt a message, returning the contained byte vector.
  pub fn decrypt_to_bytes(&self, from: &'static str, msg: SecureMessage) -> Vec<u8> {
    if !msg.sig.verify(
      self.pub_keys[from],
      signature_challenge(self.our_name, msg.sig.R, self.pub_keys[from], &msg.iv, &msg.ciphertext),
    ) {
      panic!("unauthorized/unintended message entered into an authenticated system");
    }

    let SecureMessage { iv, mut ciphertext, .. } = msg;
    XChaCha20::new(&self.enc_keys[from], &iv).apply_keystream(ciphertext.as_mut());
    ciphertext
  }
}
