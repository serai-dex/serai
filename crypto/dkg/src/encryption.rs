use core::{hash::Hash, fmt::Debug};
use std::{
  ops::Deref,
  io::{self, Read, Write},
  collections::HashMap,
};

use zeroize::{Zeroize, Zeroizing};
use rand_core::{RngCore, CryptoRng};

use chacha20::{
  cipher::{crypto_common::KeyIvInit, StreamCipher},
  Key as Cc20Key, Nonce as Cc20Iv, ChaCha20,
};

use transcript::{Transcript, RecommendedTranscript};

use group::GroupEncoding;
use ciphersuite::Ciphersuite;

use dleq::DLEqProof;

use crate::ThresholdParams;

pub trait ReadWrite: Sized {
  fn read<R: Read>(reader: &mut R, params: ThresholdParams) -> io::Result<Self>;
  fn write<W: Write>(&self, writer: &mut W) -> io::Result<()>;

  fn serialize(&self) -> Vec<u8> {
    let mut buf = vec![];
    self.write(&mut buf).unwrap();
    buf
  }
}

pub trait Message: Clone + PartialEq + Eq + Debug + Zeroize + ReadWrite {}
impl<M: Clone + PartialEq + Eq + Debug + Zeroize + ReadWrite> Message for M {}

/// Wraps a message with a key to use for encryption in the future.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct EncryptionKeyMessage<C: Ciphersuite, M: Message> {
  msg: M,
  enc_key: C::G,
}

// Doesn't impl ReadWrite so that doesn't need to be imported
impl<C: Ciphersuite, M: Message> EncryptionKeyMessage<C, M> {
  pub fn read<R: Read>(reader: &mut R, params: ThresholdParams) -> io::Result<Self> {
    Ok(Self { msg: M::read(reader, params)?, enc_key: C::read_G(reader)? })
  }

  pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    self.msg.write(writer)?;
    writer.write_all(self.enc_key.to_bytes().as_ref())
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut buf = vec![];
    self.write(&mut buf).unwrap();
    buf
  }
}

pub trait Encryptable: Clone + AsMut<[u8]> + Zeroize + ReadWrite {}
impl<E: Clone + AsMut<[u8]> + Zeroize + ReadWrite> Encryptable for E {}

/// An encrypted message, with a per-message encryption key enabling revealing specific messages
/// without side effects.
#[derive(Clone, Zeroize)]
pub struct EncryptedMessage<C: Ciphersuite, E: Encryptable> {
  key: C::G,
  msg: Zeroizing<E>,
}

impl<C: Ciphersuite, E: Encryptable> EncryptedMessage<C, E> {
  pub fn read<R: Read>(reader: &mut R, params: ThresholdParams) -> io::Result<Self> {
    Ok(Self { key: C::read_G(reader)?, msg: Zeroizing::new(E::read(reader, params)?) })
  }

  pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(self.key.to_bytes().as_ref())?;
    self.msg.write(writer)
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut buf = vec![];
    self.write(&mut buf).unwrap();
    buf
  }
}

/// A proof that the provided point is the legitimately derived shared key for some message.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct EncryptionKeyProof<C: Ciphersuite> {
  key: Zeroizing<C::G>,
  dleq: DLEqProof<C::G>,
}

impl<C: Ciphersuite> EncryptionKeyProof<C> {
  pub fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
    Ok(Self { key: Zeroizing::new(C::read_G(reader)?), dleq: DLEqProof::read(reader)? })
  }

  pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(self.key.to_bytes().as_ref())?;
    self.dleq.write(writer)
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut buf = vec![];
    self.write(&mut buf).unwrap();
    buf
  }
}

fn ecdh<C: Ciphersuite>(private: &Zeroizing<C::F>, public: C::G) -> Zeroizing<C::G> {
  Zeroizing::new(public * private.deref())
}

fn encryption_key_transcript() -> RecommendedTranscript {
  RecommendedTranscript::new(b"DKG Encryption Key Proof v0.2")
}

// A simple box for managing encryption.
#[derive(Clone)]
pub(crate) struct Encryption<Id: Eq + Hash, C: Ciphersuite> {
  dst: &'static [u8],
  enc_key: Zeroizing<C::F>,
  enc_pub_key: C::G,
  enc_keys: HashMap<Id, C::G>,
}

impl<Id: Eq + Hash, C: Ciphersuite> Zeroize for Encryption<Id, C> {
  fn zeroize(&mut self) {
    self.enc_key.zeroize();
    self.enc_pub_key.zeroize();
    for (_, mut value) in self.enc_keys.drain() {
      value.zeroize();
    }
  }
}

impl<Id: Eq + Hash, C: Ciphersuite> Encryption<Id, C> {
  pub(crate) fn new<R: RngCore + CryptoRng>(dst: &'static [u8], rng: &mut R) -> Self {
    let enc_key = Zeroizing::new(C::random_nonzero_F(rng));
    Self { dst, enc_pub_key: C::generator() * enc_key.deref(), enc_key, enc_keys: HashMap::new() }
  }

  pub(crate) fn registration<M: Message>(&self, msg: M) -> EncryptionKeyMessage<C, M> {
    EncryptionKeyMessage { msg, enc_key: self.enc_pub_key }
  }

  pub(crate) fn register<M: Message>(
    &mut self,
    participant: Id,
    msg: EncryptionKeyMessage<C, M>,
  ) -> M {
    if self.enc_keys.contains_key(&participant) {
      panic!("Re-registering encryption key for a participant");
    }
    self.enc_keys.insert(participant, msg.enc_key);
    msg.msg
  }

  fn cipher(&self, ecdh: &Zeroizing<C::G>) -> ChaCha20 {
    // Ideally, we'd box this transcript with ZAlloc, yet that's only possible on nightly
    // TODO: https://github.com/serai-dex/serai/issues/151
    let mut transcript = RecommendedTranscript::new(b"DKG Encryption v0.2");
    transcript.domain_separate(self.dst);

    let mut ecdh = ecdh.to_bytes();
    transcript.append_message(b"shared_key", ecdh.as_ref());
    ecdh.as_mut().zeroize();

    let zeroize = |buf: &mut [u8]| buf.zeroize();

    let mut key = Cc20Key::default();
    let mut challenge = transcript.challenge(b"key");
    key.copy_from_slice(&challenge[.. 32]);
    zeroize(challenge.as_mut());

    // The RecommendedTranscript isn't vulnerable to length extension attacks, yet if it was,
    // it'd make sense to clone it (and fork it) just to hedge against that
    let mut iv = Cc20Iv::default();
    let mut challenge = transcript.challenge(b"iv");
    iv.copy_from_slice(&challenge[.. 12]);
    zeroize(challenge.as_mut());

    // Same commentary as the transcript regarding ZAlloc
    // TODO: https://github.com/serai-dex/serai/issues/151
    let res = ChaCha20::new(&key, &iv);
    zeroize(key.as_mut());
    zeroize(iv.as_mut());
    res
  }

  pub(crate) fn encrypt<R: RngCore + CryptoRng, E: Encryptable>(
    &self,
    rng: &mut R,
    participant: Id,
    mut msg: Zeroizing<E>,
  ) -> EncryptedMessage<C, E> {
    /*
    The following code could be used to replace the requirement on an RNG here.
    It's just currently not an issue to require taking in an RNG here.
    let last = self.last_enc_key.to_bytes();
    self.last_enc_key = C::hash_to_F(b"encryption_base", last.as_ref());
    let key = C::hash_to_F(b"encryption_key", last.as_ref());
    last.as_mut().zeroize();
    */

    let key = Zeroizing::new(C::random_nonzero_F(rng));
    self
      .cipher(&ecdh::<C>(&key, self.enc_keys[&participant]))
      .apply_keystream(msg.as_mut().as_mut());
    EncryptedMessage { key: C::generator() * key.deref(), msg }
  }

  pub(crate) fn decrypt<R: RngCore + CryptoRng, E: Encryptable>(
    &self,
    rng: &mut R,
    mut msg: EncryptedMessage<C, E>,
  ) -> (Zeroizing<E>, EncryptionKeyProof<C>) {
    let key = ecdh::<C>(&self.enc_key, msg.key);
    self.cipher(&key).apply_keystream(msg.msg.as_mut().as_mut());
    (
      msg.msg,
      EncryptionKeyProof {
        key,
        dleq: DLEqProof::prove(
          rng,
          &mut encryption_key_transcript(),
          &[C::generator(), msg.key],
          &self.enc_key,
        ),
      },
    )
  }

  // Given a message, and the intended decryptor, and a proof for its key, decrypt the message.
  // Returns None if the key was wrong.
  pub(crate) fn decrypt_with_proof<E: Encryptable>(
    &self,
    decryptor: Id,
    mut msg: EncryptedMessage<C, E>,
    proof: EncryptionKeyProof<C>,
  ) -> Option<Zeroizing<E>> {
    // Verify this is the decryption key for this message
    if proof
      .dleq
      .verify(
        &mut encryption_key_transcript(),
        &[C::generator(), msg.key],
        &[self.enc_keys[&decryptor], *proof.key],
      )
      .is_err()
    {
      return None;
    }
    self.cipher(&proof.key).apply_keystream(msg.msg.as_mut().as_mut());
    Some(msg.msg)
  }
}
