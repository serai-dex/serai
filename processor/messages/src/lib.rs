use std::collections::HashMap;

use zeroize::Zeroize;

use rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use transcript::{Transcript, RecommendedTranscript};

use serde::{Serialize, Deserialize};

use dkg::ThresholdParams;

use serai_primitives::WithAmount;
use in_instructions_primitives::InInstruction;
use tokens_primitives::OutInstruction;
use validator_sets_primitives::ValidatorSetInstance;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize, Serialize, Deserialize)]
pub struct SubstrateContext {
  pub time: u64,
  pub coin_latest_block_number: u64,
}

pub mod key_gen {
  use super::*;

  #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Zeroize, Serialize, Deserialize)]
  pub struct KeyGenId {
    pub set: ValidatorSetInstance,
    pub attempt: u32,
  }

  #[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
  pub enum CoordinatorMessage {
    // Instructs the Processor to begin the key generation process.
    GenerateKey { id: KeyGenId, params: ThresholdParams },
    // Received commitments for the specified key generation protocol.
    Commitments { id: KeyGenId, commitments: HashMap<u16, Vec<u8>> },
    // Received shares for the specified key generation protocol.
    Shares { id: KeyGenId, shares: HashMap<u16, Vec<u8>> },
    // Confirm a key.
    ConfirmKey { context: SubstrateContext, id: KeyGenId },
  }

  #[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
  pub enum ProcessorMessage {
    // Created commitments for the specified key generation protocol.
    Commitments { id: KeyGenId, commitments: Vec<u8> },
    // Created shares for the specified key generation protocol.
    Shares { id: KeyGenId, shares: HashMap<u16, Vec<u8>> },
    // Resulting key from the specified key generation protocol.
    GeneratedKey { id: KeyGenId, key: Vec<u8> },
  }
}

pub mod sign {
  use super::*;

  #[derive(Clone, PartialEq, Eq, Hash, Debug, Zeroize, Serialize, Deserialize)]
  pub struct SignId {
    pub key: Vec<u8>,
    pub id: [u8; 32],
    pub attempt: u32,
  }

  impl SignId {
    /// Determine a signing set for a given signing session.
    // TODO: Replace with ROAST or the first available group of signers.
    // https://github.com/serai-dex/serai/issues/163
    pub fn signing_set(&self, params: &ThresholdParams) -> Vec<u16> {
      let mut transcript = RecommendedTranscript::new(b"SignId signing_set");
      transcript.domain_separate(b"SignId");
      transcript.append_message(b"key", &self.key);
      transcript.append_message(b"id", self.id);
      transcript.append_message(b"attempt", self.attempt.to_le_bytes());

      let mut candidates = (1 ..= params.n()).collect::<Vec<_>>();
      let mut rng = ChaCha8Rng::from_seed(transcript.rng_seed(b"signing_set"));
      while candidates.len() > params.t().into() {
        candidates.swap_remove(
          usize::try_from(rng.next_u64() % u64::try_from(candidates.len()).unwrap()).unwrap(),
        );
      }
      candidates
    }
  }

  #[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
  pub enum CoordinatorMessage {
    // Received preprocesses for the specified signing protocol.
    Preprocesses { id: SignId, preprocesses: HashMap<u16, Vec<u8>> },
    // Received shares for the specified signing protocol.
    Shares { id: SignId, shares: HashMap<u16, Vec<u8>> },
  }

  #[derive(Clone, PartialEq, Eq, Debug, Zeroize, Serialize, Deserialize)]
  pub enum ProcessorMessage {
    // Created preprocess for the specified signing protocol.
    Preprocess { id: SignId, preprocess: Vec<u8> },
    // Signed share for the specified signing protocol.
    Share { id: SignId, share: Vec<u8> },
  }

  impl CoordinatorMessage {
    pub fn key(&self) -> &[u8] {
      match self {
        CoordinatorMessage::Preprocesses { id, .. } => &id.key,
        CoordinatorMessage::Shares { id, .. } => &id.key,
      }
    }
  }
}

pub mod substrate {
  use super::*;

  #[derive(Clone, PartialEq, Eq, Debug, Zeroize, Serialize, Deserialize)]
  pub enum CoordinatorMessage {
    BlockAcknowledged { context: SubstrateContext, key: Vec<u8>, block: Vec<u8> },
    Burns { context: SubstrateContext, burns: Vec<WithAmount<OutInstruction>> },
  }

  #[derive(Clone, PartialEq, Eq, Debug, Zeroize, Serialize, Deserialize)]
  pub enum ProcessorMessage {
    Update { key: Vec<u8>, block: Vec<u8>, instructions: Vec<WithAmount<InInstruction>> },
  }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum CoordinatorMessage {
  KeyGen(key_gen::CoordinatorMessage),
  Sign(sign::CoordinatorMessage),
  Substrate(substrate::CoordinatorMessage),
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum ProcessorMessage {
  KeyGen(key_gen::ProcessorMessage),
  Sign(sign::ProcessorMessage),
  Substrate(substrate::ProcessorMessage),
}
