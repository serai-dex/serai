use transcript::{Transcript, RecommendedTranscript};
use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};

use borsh::{BorshSerialize, BorshDeserialize};

use serai_primitives::NetworkId;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, BorshSerialize, BorshDeserialize)]
pub enum Service {
  Processor(NetworkId),
  Coordinator,
}

#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct QueuedMessage {
  pub from: Service,
  pub id: u64,
  pub msg: Vec<u8>,
  pub sig: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct Metadata {
  pub from: Service,
  pub to: Service,
  pub intent: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub enum MessageQueueRequest {
  Queue { meta: Metadata, msg: Vec<u8>, sig: Vec<u8> },
  Next { from: Service, to: Service },
  Ack { from: Service, to: Service, id: u64, sig: Vec<u8> },
}

pub fn message_challenge(
  from: Service,
  from_key: <Ristretto as Ciphersuite>::G,
  to: Service,
  intent: &[u8],
  msg: &[u8],
  nonce: <Ristretto as Ciphersuite>::G,
) -> <Ristretto as Ciphersuite>::F {
  let mut transcript = RecommendedTranscript::new(b"Serai Message Queue v0.1 Message");
  transcript.domain_separate(b"metadata");
  transcript.append_message(b"from", borsh::to_vec(&from).unwrap());
  transcript.append_message(b"from_key", from_key.to_bytes());
  transcript.append_message(b"to", borsh::to_vec(&to).unwrap());
  transcript.append_message(b"intent", intent);
  transcript.domain_separate(b"message");
  transcript.append_message(b"msg", msg);
  transcript.domain_separate(b"signature");
  transcript.append_message(b"nonce", nonce.to_bytes());
  <Ristretto as Ciphersuite>::hash_to_F(b"message_challenge", &transcript.challenge(b"challenge"))
}

pub fn ack_challenge(
  to: Service,
  to_key: <Ristretto as Ciphersuite>::G,
  from: Service,
  id: u64,
  nonce: <Ristretto as Ciphersuite>::G,
) -> <Ristretto as Ciphersuite>::F {
  let mut transcript = RecommendedTranscript::new(b"Serai Message Queue v0.1 Acknowledgement");
  transcript.domain_separate(b"metadata");
  transcript.append_message(b"to", borsh::to_vec(&to).unwrap());
  transcript.append_message(b"to_key", to_key.to_bytes());
  transcript.append_message(b"from", borsh::to_vec(&from).unwrap());
  transcript.domain_separate(b"message");
  transcript.append_message(b"id", id.to_le_bytes());
  transcript.domain_separate(b"signature");
  transcript.append_message(b"nonce", nonce.to_bytes());
  <Ristretto as Ciphersuite>::hash_to_F(b"ack_challenge", &transcript.challenge(b"challenge"))
}
