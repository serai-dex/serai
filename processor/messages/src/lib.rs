use std::collections::HashMap;

use zeroize::Zeroize;

use serde::{Serialize, Deserialize};

use dkg::{Participant, ThresholdParams};

use serai_primitives::BlockHash;
use in_instructions_primitives::SignedBatch;
use tokens_primitives::OutInstructionWithBalance;
use validator_sets_primitives::ValidatorSet;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize, Serialize, Deserialize)]
pub struct SubstrateContext {
  pub coin_latest_finalized_block: BlockHash,
}

pub mod key_gen {
  use super::*;

  #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Zeroize, Serialize, Deserialize)]
  pub struct KeyGenId {
    pub set: ValidatorSet,
    pub attempt: u32,
  }

  #[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
  pub enum CoordinatorMessage {
    // Instructs the Processor to begin the key generation process.
    GenerateKey { id: KeyGenId, params: ThresholdParams },
    // Received commitments for the specified key generation protocol.
    Commitments { id: KeyGenId, commitments: HashMap<Participant, Vec<u8>> },
    // Received shares for the specified key generation protocol.
    Shares { id: KeyGenId, shares: HashMap<Participant, Vec<u8>> },
    // Confirm a key pair.
    ConfirmKeyPair { context: SubstrateContext, id: KeyGenId },
  }

  impl CoordinatorMessage {
    pub fn required_block(&self) -> Option<BlockHash> {
      if let CoordinatorMessage::ConfirmKeyPair { context, .. } = self {
        Some(context.coin_latest_finalized_block)
      } else {
        None
      }
    }
  }

  #[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
  pub enum ProcessorMessage {
    // Created commitments for the specified key generation protocol.
    Commitments { id: KeyGenId, commitments: Vec<u8> },
    // Created shares for the specified key generation protocol.
    Shares { id: KeyGenId, shares: HashMap<Participant, Vec<u8>> },
    // Resulting keys from the specified key generation protocol.
    GeneratedKeyPair { id: KeyGenId, substrate_key: [u8; 32], coin_key: Vec<u8> },
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

  #[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
  pub enum CoordinatorMessage {
    // Received preprocesses for the specified signing protocol.
    Preprocesses { id: SignId, preprocesses: HashMap<Participant, Vec<u8>> },
    // Received shares for the specified signing protocol.
    Shares { id: SignId, shares: HashMap<Participant, Vec<u8>> },
    // Re-attempt a signing protocol.
    Reattempt { id: SignId },
    // Completed a signing protocol already.
    Completed { key: Vec<u8>, id: [u8; 32], tx: Vec<u8> },
  }

  #[derive(Clone, PartialEq, Eq, Debug, Zeroize, Serialize, Deserialize)]
  pub enum ProcessorMessage {
    // Created preprocess for the specified signing protocol.
    Preprocess { id: SignId, preprocess: Vec<u8> },
    // Signed share for the specified signing protocol.
    Share { id: SignId, share: Vec<u8> },
    // Completed a signing protocol already.
    Completed { key: Vec<u8>, id: [u8; 32], tx: Vec<u8> },
  }

  impl CoordinatorMessage {
    pub fn required_block(&self) -> Option<BlockHash> {
      None
    }

    pub fn key(&self) -> &[u8] {
      match self {
        CoordinatorMessage::Preprocesses { id, .. } => &id.key,
        CoordinatorMessage::Shares { id, .. } => &id.key,
        CoordinatorMessage::Reattempt { id } => &id.key,
        CoordinatorMessage::Completed { key, .. } => key,
      }
    }
  }
}

pub mod coordinator {
  use super::{sign::SignId, *};

  #[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
  pub enum CoordinatorMessage {
    // Uses Vec<u8> instead of [u8; 64] since serde Deserialize isn't implemented for [u8; 64]
    BatchPreprocesses { id: SignId, preprocesses: HashMap<Participant, Vec<u8>> },
    BatchShares { id: SignId, shares: HashMap<Participant, [u8; 32]> },
    // Re-attempt a batch signing protocol.
    BatchReattempt { id: SignId },
    // Needed so a client which didn't participate in signing can still realize signing completed
    BatchSigned { key: Vec<u8>, block: BlockHash },
  }

  impl CoordinatorMessage {
    pub fn required_block(&self) -> Option<BlockHash> {
      Some(match self {
        CoordinatorMessage::BatchPreprocesses { id, .. } => BlockHash(id.id),
        CoordinatorMessage::BatchShares { id, .. } => BlockHash(id.id),
        CoordinatorMessage::BatchReattempt { id } => BlockHash(id.id),
        CoordinatorMessage::BatchSigned { block, .. } => *block,
      })
    }

    pub fn key(&self) -> &[u8] {
      match self {
        CoordinatorMessage::BatchPreprocesses { id, .. } => &id.key,
        CoordinatorMessage::BatchShares { id, .. } => &id.key,
        CoordinatorMessage::BatchReattempt { id } => &id.key,
        CoordinatorMessage::BatchSigned { key, .. } => key,
      }
    }
  }

  #[derive(Clone, PartialEq, Eq, Debug, Zeroize, Serialize, Deserialize)]
  pub enum ProcessorMessage {
    BatchPreprocess { id: SignId, preprocess: Vec<u8> },
    BatchShare { id: SignId, share: [u8; 32] },
  }
}

pub mod substrate {
  use super::*;

  #[derive(Clone, PartialEq, Eq, Debug, Zeroize, Serialize, Deserialize)]
  pub enum CoordinatorMessage {
    SubstrateBlock {
      context: SubstrateContext,
      key: Vec<u8>,
      burns: Vec<OutInstructionWithBalance>,
    },
  }

  impl CoordinatorMessage {
    pub fn required_block(&self) -> Option<BlockHash> {
      let context = match self {
        CoordinatorMessage::SubstrateBlock { context, .. } => context,
      };
      Some(context.coin_latest_finalized_block)
    }
  }

  #[derive(Clone, PartialEq, Eq, Debug, Zeroize, Serialize, Deserialize)]
  pub enum ProcessorMessage {
    Update { key: Vec<u8>, batch: SignedBatch },
  }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum CoordinatorMessage {
  KeyGen(key_gen::CoordinatorMessage),
  Sign(sign::CoordinatorMessage),
  Coordinator(coordinator::CoordinatorMessage),
  Substrate(substrate::CoordinatorMessage),
}

impl CoordinatorMessage {
  pub fn required_block(&self) -> Option<BlockHash> {
    match self {
      CoordinatorMessage::KeyGen(msg) => msg.required_block(),
      CoordinatorMessage::Sign(msg) => msg.required_block(),
      CoordinatorMessage::Coordinator(msg) => msg.required_block(),
      CoordinatorMessage::Substrate(msg) => msg.required_block(),
    }
  }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum ProcessorMessage {
  KeyGen(key_gen::ProcessorMessage),
  Sign(sign::ProcessorMessage),
  Coordinator(coordinator::ProcessorMessage),
  Substrate(substrate::ProcessorMessage),
}
