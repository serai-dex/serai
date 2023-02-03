use std::collections::HashMap;

use zeroize::Zeroize;

use serde::{Serialize, Deserialize};

use dkg::ThresholdParams;

use serai_primitives::WithAmount;
use in_instructions_primitives::InInstruction;
use tokens_primitives::OutInstruction;
use validator_sets_primitives::ValidatorSetInstance;

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
    KeyGen { id: KeyGenId, params: ThresholdParams },
    // Received commitments for the specified key generation protocol.
    KeyGenCommitments { id: KeyGenId, commitments: HashMap<u16, Vec<u8>> },
    // Received shares for the specified key generation protocol.
    KeyGenShares { id: KeyGenId, shares: HashMap<u16, Vec<u8>> },
    // Confirm a key.
    ConfirmKey { id: KeyGenId }
  }

  #[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
  pub enum ProcessorMessage {
    // Created commitments for the specified key generation protocol.
    KeyGenCommitments { id: KeyGenId, commitments: Vec<u8> },
    // Created shares for the specified key generation protocol.
    KeyGenShares { id: KeyGenId, shares: HashMap<u16, Vec<u8>> },
    // Resulting key from the specified key generation protocol.
    KeyGenCompletion { id: KeyGenId, key: Vec<u8> },
  }
}

pub mod sign {
  use super::*;

  #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Zeroize, Serialize, Deserialize)]
  pub struct SignId {
    pub id: [u8; 32],
    pub attempt: u32,
  }

  #[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
  pub enum CoordinatorMessage {
    // Received preprocesses for the specified signing protocol.
    SignPreprocesses { id: SignId, preprocesses: HashMap<u16, Vec<u8>> },
    // Received shares for the specified signing protocol.
    SignShares { id: SignId, shares: HashMap<u16, Vec<u8>> },
  }

  #[derive(Clone, PartialEq, Eq, Debug, Zeroize, Serialize, Deserialize)]
  pub enum ProcessorMessage {
    // Created preprocess for the specified signing protocol.
    SignPreprocess { id: SignId, preprocess: Vec<u8> },
    // Signed share for the specified signing protocol.
    SignShare { id: SignId, share: Vec<u8> },
  }
}

pub mod substrate {
  use super::*;

  #[derive(Clone, PartialEq, Eq, Debug, Zeroize, Serialize, Deserialize)]
  pub enum CoordinatorMessage {
    BlockAcknowledged([u8; 32]),
    Burns(Vec<WithAmount<OutInstruction>>),
  }

  #[derive(Clone, PartialEq, Eq, Debug, Zeroize, Serialize, Deserialize)]
  pub enum ProcessorMessage {
    Update { block: [u8; 32], instructions: Vec<WithAmount<InInstruction>> },
  }
}
