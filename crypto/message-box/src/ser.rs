use std::io::Read;

use chacha20::XNonce;

use ciphersuite::Ristretto;
use schnorr::SchnorrSignature;

use serde::{Serializer, Serialize, de::Error, Deserializer, Deserialize};

use crate::{MessageError, SecureMessage, MessageBox};

// Functions enabling serde serialization of SecureMessage
pub(crate) fn serialize_iv<S: Serializer>(iv: &XNonce, serializer: S) -> Result<S::Ok, S::Error> {
  <[u8; 24]>::from(*iv).serialize(serializer)
}

pub(crate) fn deserialize_iv<'de, D: Deserializer<'de>>(
  deserializer: D,
) -> Result<XNonce, D::Error> {
  Ok(<[u8; 24]>::deserialize(deserializer)?.into())
}

pub(crate) fn serialize_sig<S: Serializer>(
  sig: &SchnorrSignature<Ristretto>,
  serializer: S,
) -> Result<S::Ok, S::Error> {
  sig.serialize().serialize(serializer)
}

pub(crate) fn deserialize_sig<'de, D: Deserializer<'de>>(
  deserializer: D,
) -> Result<SchnorrSignature<Ristretto>, D::Error> {
  SchnorrSignature::<Ristretto>::read::<&[u8]>(&mut Vec::<u8>::deserialize(deserializer)?.as_ref())
    .map_err(|_| D::Error::custom("invalid signature"))
}

impl SecureMessage {
  /// Read a SecureMessage from a reader.
  pub fn read<R: Read>(reader: &mut R) -> Result<SecureMessage, MessageError> {
    let mut iv = XNonce::default();
    reader.read_exact(&mut iv).map_err(|_| MessageError::Incomplete)?;

    let sig = SchnorrSignature::<Ristretto>::read(reader).map_err(|_| MessageError::Incomplete)?;

    let mut ciphertext = vec![];
    reader.read_to_end(&mut ciphertext).unwrap();

    Ok(SecureMessage { iv, ciphertext, sig })
  }

  /// Create a new SecureMessage from bytes.
  pub fn new(bytes: Vec<u8>) -> Result<SecureMessage, MessageError> {
    Self::read::<&[u8]>(&mut bytes.as_ref())
  }

  /// Serialize a message to a byte vector.
  pub fn serialize(&self) -> Vec<u8> {
    let mut res = vec![];
    res.extend(self.iv);
    // Write the sig before the ciphertext since it's of a fixed length
    // This enables reading the ciphertext without length prefixing within this library
    // While the communication method likely will, if length prefixing was done with this library,
    // it'd likely happen twice. Hence why this library avoids doing it
    self.sig.write(&mut res).unwrap();
    res.extend(&self.ciphertext);
    res
  }
}

/// Type-safe wrapper around a Vec<u8> which does not guarantee a valid message is contained.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SecureMessageBytes(Vec<u8>);
impl SecureMessageBytes {
  /// Create a new SecureMessage from bytes.
  pub fn new(bytes: Vec<u8>) -> SecureMessageBytes {
    Self(bytes)
  }

  /// Serialize a message to a byte vector.
  pub fn serialize(&self) -> Vec<u8> {
    self.0.clone()
  }
}

#[cfg(feature = "kafka")]
impl rdkafka::message::ToBytes for SecureMessageBytes {
  fn to_bytes(&self) -> &[u8] {
    &self.0
  }
}

impl MessageBox {
  /// Encrypt a message and serialize it.
  pub fn encrypt_to_bytes(&self, to: &'static str, msg: Vec<u8>) -> SecureMessageBytes {
    SecureMessageBytes(self.encrypt(to, msg).serialize())
  }

  /// Deserialize a message and decrypt it.
  pub fn decrypt_from_bytes(
    &self,
    from: &'static str,
    msg: SecureMessageBytes,
  ) -> Result<Vec<u8>, MessageError> {
    SecureMessage::new(msg.0).map(|msg| self.decrypt(from, msg))
  }

  /// Encrypt a message, serialize it, and base64 encode it.
  #[deprecated(note = "use encrypt_to_bytes")]
  pub fn encrypt_to_string(&self, to: &'static str, msg: Vec<u8>) -> String {
    base64::encode(self.encrypt_to_bytes(to, msg).0)
  }

  /// Base64 decode the given string, deserialize it as a message, and decrypt it.
  #[deprecated(note = "use decrypt_from_bytes")]
  pub fn decrypt_from_str(&self, from: &'static str, msg: &str) -> Result<Vec<u8>, MessageError> {
    self.decrypt_from_bytes(
      from,
      SecureMessageBytes(base64::decode(msg).map_err(|_| MessageError::InvalidEncoding)?),
    )
  }
}
