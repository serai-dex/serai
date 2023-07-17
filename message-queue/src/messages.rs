use transcript::{Transcript, RecommendedTranscript};
use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};

use serde::{Serialize, Deserialize};

use serai_primitives::NetworkId;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub enum Service {
  Processor(NetworkId),
  Coordinator,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct QueuedMessage {
  pub from: Service,
  pub id: u64,
  pub msg: Vec<u8>,
  pub sig: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Metadata {
  pub from: Service,
  pub to: Service,
  pub intent: Vec<u8>,
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
  transcript.append_message(b"from", bincode::serialize(&from).unwrap());
  transcript.append_message(b"from_key", from_key.to_bytes());
  transcript.append_message(b"to", bincode::serialize(&to).unwrap());
  transcript.append_message(b"intent", intent);
  transcript.domain_separate(b"message");
  transcript.append_message(b"msg", msg);
  transcript.domain_separate(b"signature");
  transcript.append_message(b"nonce", nonce.to_bytes());
  <Ristretto as Ciphersuite>::hash_to_F(b"message_challenge", &transcript.challenge(b"challenge"))
}

pub fn ack_challenge(
  from: Service,
  from_key: <Ristretto as Ciphersuite>::G,
  id: u64,
  nonce: <Ristretto as Ciphersuite>::G,
) -> <Ristretto as Ciphersuite>::F {
  let mut transcript = RecommendedTranscript::new(b"Serai Message Queue v0.1 Ackowledgement");
  transcript.domain_separate(b"metadata");
  transcript.append_message(b"from", bincode::serialize(&from).unwrap());
  transcript.append_message(b"from_key", from_key.to_bytes());
  transcript.domain_separate(b"message");
  transcript.append_message(b"id", id.to_le_bytes());
  transcript.domain_separate(b"signature");
  transcript.append_message(b"nonce", nonce.to_bytes());
  <Ristretto as Ciphersuite>::hash_to_F(b"ack_challenge", &transcript.challenge(b"challenge"))
}
