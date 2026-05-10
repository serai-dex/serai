#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
// We don't have a no-`std` use-case for this, but we also don't need `std`
#![no_std]

use core::ops::Deref as _;

extern crate alloc;
use alloc::vec::Vec;

use zeroize::Zeroizing;
use rand_core::{RngCore, CryptoRng};

use transcript::{Transcript as _, DigestTranscript};
#[rustfmt::skip]
use ciphersuite::{group::GroupEncoding as _, FromUniformBytes as _, WrappedGroup, WithPreferredHash};
use dalek_ff_group::Ristretto;
use schnorr_signatures::SchnorrSignature;

use borsh::{BorshSerialize, BorshDeserialize};

use serai_primitives::network_id::ExternalNetworkId;

/// The ID for a service on a validator's intranet.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, BorshSerialize, BorshDeserialize)]
pub enum Service {
  /// A processor for an external network.
  Processor(ExternalNetworkId),
  /// The coordinator.
  Coordinator,
}

/// A message queued by one service, for another service.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct QueuedMessage {
  /// The metadata for this message.
  pub metadata: Metadata,
  /// The message itself.
  pub message: Vec<u8>,
  /// The signature for the metdata, message.
  pub signature: [u8; 64],
  /// The incremental ID for this message.
  ///
  /// This is assigned by the `message-queue`.
  pub id: u64,
}

/// Metadata for a messages.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct Metadata {
  /// This service this was sent by.
  pub from: Service,
  /// This service this was sent to.
  pub to: Service,
  /// The 'intent' for this message.
  ///
  /// If two messages are sent with the same intent, only one will be queued. This is intended to
  /// allow a service to send a message multiple times but ensure it's only actually sent once.
  pub intent: Vec<u8>,
}

/// A request for the `message-queue` server.
#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum Request {
  /// Queue a message.
  Queue {
    /// The metadata for this message.
    metadata: Metadata,
    /// The message itself.
    message: Vec<u8>,
    /// The message's signature.
    signature: [u8; 64],
  },
  /// Fetch the next message.
  ///
  /// This is not authenticated as no messages queued are considered private. The `message-queue`
  /// is only itself concerned with authenticity, not confidentiality.
  Fetch {
    /// The service which sent the message.
    from: Service,
    /// The service which the message was sent to.
    to: Service,
  },
  /// Acknowledge a message as received.
  Acknowledge {
    /// The service which sent the message.
    from: Service,
    /// The service the message was sent to.
    to: Service,
    /// The message's ID.
    id: u64,
    /// The signature authenticating this acknowledgment.
    signature: [u8; 64],
  },
}

impl Request {
  /// The challenge for the signature for this request.
  ///
  /// This ignores the include `signature` field (if one exists) and defers to the passed-in
  /// `nonce` argument.
  fn signature_challenge(
    &self,
    from_key: <Ristretto as WrappedGroup>::G,
    nonce: &[u8; 32],
  ) -> Option<<Ristretto as WrappedGroup>::F> {
    let mut transcript = DigestTranscript::<<Ristretto as WithPreferredHash>::H>::new(match self {
      Self::Queue { .. } => b"Serai Message Queue v0.1 Message",
      Self::Fetch { .. } => None?,
      Self::Acknowledge { .. } => b"Serai Message Queue v0.1 Message Acknowledgment",
    });
    transcript.domain_separate(b"metadata");
    transcript.append_message(b"key", from_key.to_bytes());
    match self {
      Self::Queue { metadata: Metadata { from, to, intent }, message, signature: _ } => {
        transcript.append_message(b"from", borsh::to_vec(&from).unwrap());
        transcript.append_message(b"to", borsh::to_vec(&to).unwrap());
        transcript.append_message(b"intent", intent);
        transcript.domain_separate(b"message");
        transcript.append_message(b"message", message);
      }
      Self::Fetch { .. } => None?,
      Self::Acknowledge { from, to, id, signature: _ } => {
        transcript.append_message(b"from", borsh::to_vec(&from).unwrap());
        transcript.append_message(b"to", borsh::to_vec(&to).unwrap());
        transcript.domain_separate(b"message");
        transcript.append_message(b"id", id.to_le_bytes());
      }
    }
    transcript.domain_separate(b"signature");
    transcript.append_message(b"nonce", nonce);
    Some(<Ristretto as WrappedGroup>::F::from_uniform_bytes(
      &transcript.challenge(b"challenge").into(),
    ))
  }

  /// Sign this request.
  pub fn sign(
    &mut self,
    rng: &mut (impl RngCore + CryptoRng),
    from_key: &Zeroizing<<Ristretto as WrappedGroup>::F>,
  ) {
    let nonce = Zeroizing::new(<Ristretto as WrappedGroup>::F::random(rng));
    if let Some(challenge) = self.signature_challenge(
      <Ristretto as WrappedGroup>::generator() * from_key.deref(),
      &(<Ristretto as WrappedGroup>::generator() * nonce.deref()).to_bytes(),
    ) {
      let signature = SchnorrSignature::<Ristretto>::sign(from_key, nonce, challenge);
      let signature = <[u8; 64]>::try_from(signature.serialize()).unwrap();
      match self {
        Self::Queue { signature: signature_ref, .. } |
        Self::Acknowledge { signature: signature_ref, .. } => {
          *signature_ref = signature;
        }
        Self::Fetch { .. } => panic!("signature challenge for request without signature"),
      }
    }
  }

  /// Verify this request.
  #[must_use]
  pub fn verify(&self, from_key: <Ristretto as WrappedGroup>::G) -> bool {
    let signature = match self {
      Self::Queue { signature, .. } | Self::Acknowledge { signature, .. } => signature,
      Self::Fetch { .. } => return true,
    };

    let challenge = self
      .signature_challenge(from_key, signature[.. 32].as_array().unwrap())
      .expect("`Request` with signature lacked challenge");

    let Ok(signature) = SchnorrSignature::<Ristretto>::read(&mut signature.as_slice()) else {
      return false;
    };
    signature.verify(from_key, challenge)
  }
}
