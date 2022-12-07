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

use group::GroupEncoding;

use ciphersuite::Ciphersuite;

use transcript::{Transcript, RecommendedTranscript};

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
#[derive(Clone, Zeroize)]
pub struct EncryptedMessage<E: Encryptable>(Zeroizing<E>);

impl<E: Encryptable> EncryptedMessage<E> {
  pub fn read<R: Read>(reader: &mut R, params: ThresholdParams) -> io::Result<Self> {
    Ok(Self(Zeroizing::new(E::read(reader, params)?)))
  }

  pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    self.0.write(writer)
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut buf = vec![];
    self.write(&mut buf).unwrap();
    buf
  }
}

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

  fn cipher(&self, participant: Id, encrypt: bool) -> ChaCha20 {
    // Ideally, we'd box this transcript with ZAlloc, yet that's only possible on nightly
    // TODO
    let mut transcript = RecommendedTranscript::new(b"DKG Encryption v0");
    transcript.domain_separate(self.dst);

    let other = self.enc_keys[&participant];
    if encrypt {
      transcript.append_message(b"sender", self.enc_pub_key.to_bytes());
      transcript.append_message(b"receiver", other.to_bytes());
    } else {
      transcript.append_message(b"sender", other.to_bytes());
      transcript.append_message(b"receiver", self.enc_pub_key.to_bytes());
    }

    let mut shared = Zeroizing::new(other * self.enc_key.deref()).deref().to_bytes();
    transcript.append_message(b"shared_key", shared.as_ref());
    shared.as_mut().zeroize();

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
    // TODO
    let res = ChaCha20::new(&key, &iv);
    zeroize(key.as_mut());
    zeroize(iv.as_mut());
    res
  }

  pub(crate) fn encrypt<E: Encryptable>(
    &self,
    participant: Id,
    mut msg: Zeroizing<E>,
  ) -> EncryptedMessage<E> {
    self.cipher(participant, true).apply_keystream(msg.as_mut().as_mut());
    EncryptedMessage(msg)
  }

  pub(crate) fn decrypt<E: Encryptable>(
    &self,
    participant: Id,
    mut msg: EncryptedMessage<E>,
  ) -> Zeroizing<E> {
    self.cipher(participant, false).apply_keystream(msg.0.as_mut().as_mut());
    msg.0
  }
}
