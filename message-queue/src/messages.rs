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
  pub msg: Vec<u8>,
  pub sig: Vec<u8>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Metadata {
  pub from: Service,
  pub to: Service,
  pub from_id: u64,
}

pub fn message_challenge(
  from: <Ristretto as Ciphersuite>::G,
  msg: &[u8],
  nonce: <Ristretto as Ciphersuite>::G,
) -> <Ristretto as Ciphersuite>::F {
  let mut transcript = RecommendedTranscript::new(b"Serai Message Queue v0.1");
  transcript.domain_separate(b"message");
  transcript.append_message(b"from", from.to_bytes());
  transcript.append_message(b"msg", msg);
  transcript.domain_separate(b"signature");
  transcript.append_message(b"nonce", nonce.to_bytes());
  <Ristretto as Ciphersuite>::hash_to_F(b"challenge", &transcript.challenge(b"challenge"))
}
