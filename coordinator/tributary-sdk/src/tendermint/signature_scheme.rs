use core::{ops::Deref as _, convert::AsRef};
use alloc::{boxed::Box, vec::Vec, vec};

use zeroize::Zeroizing;
use rand::rngs::OsRng;

use blake2::digest::{Digest as _, CustomizedInit as _};
use ciphersuite::{
  group::{ff::PrimeField, GroupEncoding},
  FromUniformBytes as _, WrappedGroup, GroupIo, WithPreferredHash,
};
use dalek_ff_group::Ristretto;
use schnorr::{
  SchnorrSignature,
  aggregate::{SchnorrAggregator, SchnorrAggregate},
};

use borsh::{
  io::{self, Read, Write},
  BorshSerialize, BorshDeserialize,
};
use tendermint::InvalidAggregateSignature;

/// The DST used for aggregating Schnorr signatures.
const AGGREGATOR_DST: &[u8] = b"Tributary Tendermint Commit Aggregator";

/// A transcript which has already been scoped to a message.
///
/// The `SignatureScheme` API expected by `tendermint-machine` supports aggregation where multiple
/// signers sign the same message and then non-interactively produce a single signature. Because
/// the messages are the same, we first transcript the message, _then_ the signer's key and nonce.
/// If we hashed the signer's key and nonce _first_, as traditional, we'd have to re-hash the
/// message for each signer. This is safe, without a risk of collisions, as the length of the
/// signer's key and nonce is constant.
#[derive(Clone)]
struct MessageScopedTranscript(<Ristretto as WithPreferredHash>::H);
impl MessageScopedTranscript {
  fn challenge(self, key: [u8; 32], nonce: &[u8]) -> <Ristretto as WrappedGroup>::F {
    <Ristretto as WrappedGroup>::F::from_uniform_bytes(
      &self.0.chain_update(key).chain_update(nonce).finalize().into(),
    )
  }
}

#[test]
fn message_scoped_transcript() {
  let transcript = MessageScopedTranscript(<Ristretto as WithPreferredHash>::H::new());

  let rand_bytes = || {
    use rand::RngCore as _;

    let mut bytes = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    bytes
  };

  let key_a = rand_bytes();
  let key_b = rand_bytes();

  let nonce_a = rand_bytes();
  let nonce_b = rand_bytes();

  // This should be consistent if quieried multiple times, not mutated
  assert_eq!(
    transcript.clone().challenge(key_a, &nonce_a),
    transcript.clone().challenge(key_a, &nonce_a)
  );
  // Yet either the key or the nonce being different should produce a different challenge
  assert_ne!(
    transcript.clone().challenge(key_a, &nonce_a),
    transcript.clone().challenge(key_b, &nonce_a)
  );
  assert_ne!(
    transcript.clone().challenge(key_a, &nonce_a),
    transcript.clone().challenge(key_a, &nonce_b)
  );
  assert_ne!(
    transcript.clone().challenge(key_a, &nonce_a),
    transcript.clone().challenge(key_b, &nonce_b)
  );
}

/// The signature scheme for a Tendermint process.
///
/// This is bound to the genesis hash of the Tributary, providing domain-separation across
/// Tributaries.
// TODO: We currently represent validators as `[u8; 32]`, the byte representation of their public
// keys. Should we represent them as `u16`, as possible by also including a sorted list of
// validators here?
#[derive(Clone)]
pub(crate) struct SignatureScheme {
  genesis_scoped_transcript: <Ristretto as WithPreferredHash>::H,
}

/// A signer for a signature scheme for a Tendermint process.
///
/// This is scoped to a specific signature scheme (and therefore a specific Tributary).
#[derive(Clone)]
pub(crate) struct Signer {
  signature_scheme: SignatureScheme,
  private_key: Zeroizing<<Ristretto as WrappedGroup>::F>,
  public_key: [u8; 32],
}

impl SignatureScheme {
  /// Instance a new signature scheme for Tendermint, scoped to a specific Tributary.
  pub fn new(genesis: [u8; 32]) -> Self {
    Self {
      // Initialize the transcripts for Tendermint with a customization of "tendermint", ensuring a
      // separate domain then the Tributary itself will use for its transcripts.
      genesis_scoped_transcript: <Ristretto as WithPreferredHash>::H::new_customized(b"tendermint")
        .chain_update(genesis),
    }
  }

  /// Instance a signer for this signature scheme.
  pub fn signer(&self, private_key: Zeroizing<<Ristretto as WrappedGroup>::F>) -> Signer {
    let public_key = (Ristretto::generator() * private_key.deref()).to_bytes();
    Signer { signature_scheme: self.clone(), private_key, public_key }
  }

  /// Scope a transcript from this signature scheme to a specific message.
  ///
  /// The message-scoped transcript may then be scoped to a specific signer, nonce, to obtain the
  /// signature's challenge.
  fn message_scope(
    &self,
    message: impl IntoIterator<Item: AsRef<[u8]>>,
  ) -> MessageScopedTranscript {
    let mut transcript = self.genesis_scoped_transcript.clone();
    for message_part in message {
      transcript.update(message_part);
    }
    MessageScopedTranscript(transcript)
  }
}

#[test]
fn genesis_scoped_transcript() {
  let rand_scheme = || {
    use rand::RngCore as _;

    let mut bytes = [0; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    SignatureScheme::new(bytes)
  };

  let scheme = rand_scheme();

  // This should be binding to a genesis
  assert_ne!(
    scheme.genesis_scoped_transcript.clone().finalize(),
    rand_scheme().genesis_scoped_transcript.finalize()
  );

  // This should handle messages by their concatenation
  assert_eq!(
    scheme.message_scope([*b"a", *b"b"]).0.finalize(),
    scheme.message_scope([b"ab"]).0.finalize()
  );
  // This should be binding to the message
  assert_eq!(scheme.message_scope([b"a"]).0.finalize(), scheme.message_scope([b"b"]).0.finalize());
}

/// The type for an aggregate signature.
///
/// This contains the _serialization_ of a `schnorr::SchnorrAggregate`. It may or may not be valid.
#[derive(Clone)]
pub struct AggregateSignature(Box<[u8]>);
impl AsRef<[u8]> for AggregateSignature {
  fn as_ref(&self) -> &[u8] {
    self.0.as_ref()
  }
}

impl AggregateSignature {
  /// The amount of validators within this aggregate signature.
  fn validators(&self) -> usize {
    /*
      The serialization is a list of signers, and their nonces, nonces followed by a single scalar.
      We solely need to determine the length of the list of signers and their nonces to know how
      many signers were included.

      This can be minorly optimized as `self.0.len() / (32 + 32)`, relying on the integer division
      to truncate the `32` bytes for the scalar. The lack of clarity that would incur isn't
      preferable though.
    */
    #[expect(clippy::manual_assert)]
    const {
      if core::mem::size_of::<<<Ristretto as WrappedGroup>::G as GroupEncoding>::Repr>() != 32 {
        panic!("(memory) representation of a Ristretto point's encoding wasn't 32 bytes")
      }
      if core::mem::size_of::<<<Ristretto as WrappedGroup>::F as PrimeField>::Repr>() != 32 {
        panic!("(memory) representation of a Ristretto scalar's encoding wasn't 32 bytes")
      }
    }
    let validators = (self.0.len() - 32) / (32 + 32);
    debug_assert_eq!((validators * (32 + 32)) + 32, self.0.len());
    validators
  }
}

impl BorshSerialize for AggregateSignature {
  fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), io::Error> {
    /*
      We use `u16` to represent the amount of validators included due to Tendermint having the
      following definition:

      ```rs
      trait ValidatorSet {
        ...
        fn total_weight(&self) -> NonZero<u16>;
        ...
      }

      which means any legitimate aggregate signature will have at most `u16::MAX` weight and
      therefore `u16::MAX` validators.
    */
    writer.write_all(
      &u16::try_from(self.validators())
        .map_err(|_| {
          io::Error::other("aggregate signature has more validators than possible weight")
        })?
        .to_le_bytes(),
    )?;
    writer.write_all(&self.0)
  }
}
impl BorshDeserialize for AggregateSignature {
  fn deserialize_reader<R: Read>(reader: &mut R) -> Result<Self, io::Error> {
    let validators = {
      let mut bytes = [0; 2];
      reader.read_exact(&mut bytes)?;
      u16::from_le_bytes(bytes)
    };

    let len =
      usize::from(validators).checked_mul(32 + 32).and_then(|len| len.checked_add(32)).ok_or_else(
        || io::Error::other("length of aggregate signature overflowed platform's `usize`"),
      )?;

    /*
      TODO: This will presumably be optimized exactly as desired, but the `Vec` indirection could
      technically have a performance penalty to it. We can use `Box<[MaybeUninit<u8>]>` as an
      optimization, but then we'd have to write `unsafe` code. Additionally, `io::Read::read_exact`
      isn't strictly required to write into the bytes before reading them, making reading into such
      an object potentially unsafe. Is there a slightly better way to handle this?
    */
    let mut result = vec![0; len].into_boxed_slice();
    reader.read_exact(&mut result)?;
    Ok(Self(result))
  }
}

impl tendermint::SignatureScheme for SignatureScheme {
  // The byte representation of the validator's public key
  type Validator = [u8; 32];
  // The byte representation of a Schnorr signature
  type Signature = [u8; 64];
  type AggregateSignature = AggregateSignature;

  fn verify(
    &self,
    validator: &Self::Validator,
    message: impl IntoIterator<Item = impl AsRef<[u8]>>,
    signature: &Self::Signature,
  ) -> bool {
    let challenge = self.message_scope(message).challenge(*validator, &signature[.. 32]);
    /*
      We are not required to confirm this 'validator' is actually a validator with weight, hence
      why we solely decode and verify the corresponding signature.

      If we do represent validators by their index, then this property would become almost inherent
      however.
    */
    let Ok(validator) = Ristretto::read_G(validator.as_slice()) else {
      return false;
    };
    let Ok(signature) = SchnorrSignature::<Ristretto>::read(signature.as_slice()) else {
      return false;
    };
    signature.verify(validator, challenge)
  }

  fn aggregate<'sig>(
    &self,
    message: impl IntoIterator<Item = impl AsRef<[u8]>>,
    signatures: impl IntoIterator<Item = (&'sig Self::Validator, &'sig Self::Signature)>,
  ) -> Self::AggregateSignature
  where
    Self::Validator: 'sig,
    Self::Signature: 'sig,
  {
    let transcript = self.message_scope(message);
    let signatures = signatures.into_iter();

    let sorted = {
      let mut sorted = Vec::with_capacity({
        let (lower, _upper) = signatures.size_hint();
        lower
      });
      for signature in signatures {
        sorted.push(signature);
      }
      sorted.sort_by_key(|(validator, _signature)| **validator);
      sorted
    };

    let mut result = Vec::with_capacity((sorted.len() * (32 + 32)) + 32);
    let mut aggregator = SchnorrAggregator::<Ristretto>::new(AGGREGATOR_DST);
    for (validator, signature) in sorted {
      result.write_all(validator).expect("`<Vec<_> as io::Write>` is infallible");

      let challenge = transcript.clone().challenge(*validator, &signature[.. 32]);
      let signature = SchnorrSignature::<Ristretto>::read(signature.as_slice())
        .expect("asked to aggregate an invalid signature");
      aggregator.aggregate(challenge, signature);
    }
    let aggregate = aggregator.complete().expect("asked to aggregate no signatures");
    aggregate.write(&mut result).expect("`<Vec<_> as io::Write>` is infallible");

    AggregateSignature(result.into_boxed_slice())
  }

  fn verify_aggregate(
    &self,
    message: impl IntoIterator<Item = impl AsRef<[u8]>>,
    aggregate_signature: &Self::AggregateSignature,
  ) -> Result<impl IntoIterator<Item = Self::Validator>, InvalidAggregateSignature> {
    let transcript = self.message_scope(message);

    let (validators, aggregate_signature) = {
      let validators_len = aggregate_signature.validators();
      let aggregate_signature = aggregate_signature.as_ref();

      let (validators, mut aggregate_signature) = aggregate_signature.split_at(validators_len * 32);

      let (validators, []) = validators.as_chunks::<32>() else {
        panic!("multiple of `32` wasn't evenly divisible into chunks of length `32`")
      };
      // Ensure the validators were sorted, ensuring no validators were present multiple times
      {
        let mut last = None;
        for validator in validators.iter().map(Some) {
          if last >= validator {
            Err(InvalidAggregateSignature)?;
          }
          last = validator;
        }
      }

      let aggregate_signature = {
        let Ok(aggregate_signature_value) =
          SchnorrAggregate::<Ristretto>::read(&mut aggregate_signature, validators_len)
        else {
          Err(InvalidAggregateSignature)?
        };
        debug_assert_eq!(aggregate_signature, &[]);
        aggregate_signature_value
      };

      (validators, aggregate_signature)
    };

    let mut challenges = vec![];
    for (validator, nonce) in validators.iter().zip(aggregate_signature.Rs()) {
      let challenge = transcript.clone().challenge(*validator, nonce.to_bytes().as_ref());
      let Ok(validator) = <Ristretto as GroupIo>::read_G(validator.as_slice()) else {
        Err(InvalidAggregateSignature)?
      };
      challenges.push((validator, challenge));
    }

    if !aggregate_signature.verify(AGGREGATOR_DST, &challenges) {
      Err(InvalidAggregateSignature)?;
    }

    Ok(validators.iter().copied())
  }
}

impl tendermint::Signer for Signer {
  type Validator = [u8; 32];
  type Signature = [u8; 64];

  fn validator(&self) -> Self::Validator {
    self.public_key
  }

  type SignFuture = core::future::Ready<Self::Signature>;
  fn sign(&self, message: impl IntoIterator<Item = impl AsRef<[u8]>>) -> Self::SignFuture {
    let transcript = self.signature_scheme.message_scope(message);

    let nonce = Zeroizing::new(<Ristretto as WrappedGroup>::F::random(&mut OsRng));
    let challenge = transcript
      .challenge(self.public_key, (Ristretto::generator() * nonce.deref()).to_bytes().as_ref());
    let signature = SchnorrSignature::<Ristretto>::sign(&self.private_key, nonce, challenge);

    // TODO: Write directly into a `[u8; 64]` to avoid the intermediary `Vec<u8>`
    core::future::ready(signature.serialize().try_into().unwrap())
  }
}
