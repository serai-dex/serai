use std::collections::HashMap;

use zeroize::Zeroize;

use serde::{Serialize, Deserialize};

use serai_primitives::WithAmount;
use in_instructions_primitives::InInstruction;
use tokens_primitives::OutInstruction;

pub mod processor {
  use super::*;

  #[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
  pub enum KeyGenMessage {
    // Created commitments for the specified key generation protocol.
    KeyGenCommitments { context: [u8; 32], commitments: Vec<u8> },
    // Created shares for the specified key generation protocol.
    KeyGenShares { context: [u8; 32], shares: HashMap<u16, Vec<u8>> },
    // Resulting key from the specified key generation protocol.
    KeyGenCompletion { context: [u8; 32], key: Vec<u8> },
  }

  #[derive(Clone, PartialEq, Eq, Debug, Zeroize, Serialize, Deserialize)]
  pub enum SignMessage {
    // Created commitments for the specified signing protocol.
    SignCommitments { context: [u8; 32], commitments: Vec<u8> },
    // Signed share for the specified signing protocol.
    SignShares { context: [u8; 32], shares: Vec<u8> },
  }

  #[derive(Clone, PartialEq, Eq, Debug, Zeroize, Serialize, Deserialize)]
  pub enum SubstrateMessage {
    Update { block: [u8; 32], instructions: Vec<WithAmount<InInstruction>> },
  }
}

pub mod coordinator {
  use super::*;

  #[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
  pub enum KeyGenMessage {
    // Instructs the Processor to begin the key generation process.
    // The context should include not only the context for the key generation, yet also the attempt
    // this is.
    KeyGen { context: [u8; 32] },
    // Received commitments for the specified key generation protocol.
    KeyGenCommitments { context: [u8; 32], commitments: HashMap<u16, Vec<u8>> },
    // Received shares for the specified key generation protocol.
    KeyGenShares { context: [u8; 32], shares: HashMap<u16, Vec<u8>> },
  }

  #[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
  pub enum SignMessage {
    // Received commitments for the specified signing protocol.
    SignCommitments { context: [u8; 32], commitments: HashMap<u16, Vec<u8>> },
    // Received shares for the specified signing protocol.
    SignShares { context: [u8; 32], shares: HashMap<u16, Vec<u8>> },
  }

  #[derive(Clone, PartialEq, Eq, Debug, Zeroize, Serialize, Deserialize)]
  pub enum SubstrateMessage {
    BlockAcknowledged([u8; 32]),
    Burns(Vec<WithAmount<OutInstruction>>),
  }
}
