#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

use core::{
  cmp::Ordering,
  fmt::{Debug, Formatter},
};
use std::{
  io::{Read, Cursor},
  collections::HashMap,
};

use thiserror::Error;

use zeroize::{Zeroize, ZeroizeOnDrop};
use rand_core::{RngCore, OsRng};

use group::{ff::Field, Group, GroupEncoding};
use dalek_ff_group::{Scalar, RistrettoPoint};
use ciphersuite::Ristretto;

use transcript::{Transcript, RecommendedTranscript};
use chacha20::{
  cipher::{KeyIvInit, StreamCipher},
  Key, XNonce, XChaCha20,
};

use schnorr::SchnorrSignature;

/// Error from creating/decrypting a message.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Error)]
pub enum MessageError {
  #[error("message was incomplete")]
  Incomplete,
}

/// A Secure Message, defined as being not only encrypted yet authenticated.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SecureMessage(Vec<u8>);
impl SecureMessage {
  /// Create a new SecureMessage from bytes.
  pub fn new(bytes: Vec<u8>) -> Result<SecureMessage, MessageError> {
    Ok(SecureMessage(bytes))
  }

  /// Serialize a message to a byte vector.
  pub fn serialize(&self) -> Vec<u8> {
    self.0.clone()
  }
}

/// Generate a key pair
pub fn key_gen() -> (Scalar, RistrettoPoint) {
  let mut scalar;
  while {
    scalar = Scalar::random(&mut OsRng);
    scalar.is_zero().into()
  } {}
  (scalar, RistrettoPoint::generator() * scalar)
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
  transcript.append_message(b"nonce", &R.to_bytes());
  transcript.append_message(b"public_key", &A.to_bytes());

  transcript.domain_separate(b"message");
  transcript.append_message(b"iv", iv.as_ref());
  transcript.append_message(b"encrypted_message", enc_msg);

  Scalar::from_bytes_mod_order_wide(&transcript.challenge(b"challenge").into())
}

/// MessageBox. A box enabling encrypting and decrypting messages to/from various other peers.
pub struct MessageBox {
  our_name: &'static str,
  our_key: Scalar,
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
    our_key: Scalar,
    keys: HashMap<&'static str, RistrettoPoint>,
  ) -> MessageBox {
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

          transcript.append_message(b"shared_key", &(*other_key * our_key).to_bytes());
          let shared_key = transcript.challenge(b"encryption_key");

          let mut key = Key::default();
          debug_assert_eq!(key.len(), 32);
          key.copy_from_slice(&shared_key[.. 32]);

          (*other_name, key)
        })
        .collect(),
      pub_keys: keys,

      our_name,
      our_key,
      our_public_key: RistrettoPoint::generator() * our_key,

      additional_entropy: {
        let mut transcript = transcript();
        transcript.domain_separate(b"key_hash");
        transcript.append_message(b"private_key", &our_key.to_bytes());

        // This is exceptionally redundant and arguably pointless
        // The initial idea was to use the private_key as additional entropy
        // Then it was to hash it in order to reduce the copies in memory
        // Then it was to use a transcript for a structured hash, as we have a transcript available
        // And then it was why *not* add additional fields
        {
          let mut bytes = [0; 64];
          OsRng.fill_bytes(&mut bytes);
          transcript.append_message(b"rng", &bytes);
        }

        transcript.challenge(b"key_hash").into()
      },
    }
  }

  /// Encrypt a message to be sent to another party.
  pub fn encrypt(&self, to: &'static str, mut msg: Vec<u8>) -> SecureMessage {
    let mut iv = XNonce::default();
    OsRng.fill_bytes(iv.as_mut());
    XChaCha20::new(&self.enc_keys[to], &iv).apply_keystream(msg.as_mut());

    let nonce = {
      let mut transcript = transcript();
      transcript.domain_separate(b"nonce");
      transcript.append_message(b"additional_entropy", &self.additional_entropy);
      transcript.append_message(b"to", to.as_bytes());
      transcript.append_message(b"public_key", &self.our_public_key.to_bytes());
      transcript.append_message(b"iv", &iv);
      transcript.append_message(b"message", &msg);
      Scalar::from_bytes_mod_order_wide(&transcript.challenge(b"nonce").into())
    };

    let sig = SchnorrSignature::<Ristretto>::sign(
      self.our_key,
      nonce,
      signature_challenge(to, RistrettoPoint::generator() * nonce, self.our_public_key, &iv, &msg),
    );

    let mut res = iv.to_vec();
    sig.write(&mut res).unwrap();
    res.extend(&msg);

    SecureMessage(res)
  }

  /// Decrypt a message, returning the contained byte vector.
  pub fn decrypt(&self, from: &'static str, msg: SecureMessage) -> Result<Vec<u8>, MessageError> {
    let mut cursor = Cursor::new(msg.0);

    let mut iv = XNonce::default();
    cursor.read_exact(&mut iv).map_err(|_| MessageError::Incomplete)?;

    let sig =
      SchnorrSignature::<Ristretto>::read(&mut cursor).map_err(|_| MessageError::Incomplete)?;

    let mut msg = vec![];
    cursor.read_to_end(&mut msg).unwrap();

    if !sig.verify(
      self.pub_keys[from],
      signature_challenge(self.our_name, sig.R, self.pub_keys[from], &iv, &msg),
    ) {
      panic!("unauthorized/unintended message entered into an authenticated system");
    }

    Ok(msg)
  }
}
