use std::collections::HashMap;

use zeroize::Zeroize;

use serde::{Serialize, Deserialize};

use dkg::{Participant, ThresholdParams};

use serai_primitives::{BlockHash, NetworkId};
use in_instructions_primitives::SignedBatch;
use tokens_primitives::OutInstructionWithBalance;
use validator_sets_primitives::{ValidatorSet, KeyPair};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Zeroize, Serialize, Deserialize)]
pub struct SubstrateContext {
  pub serai_time: u64,
  pub network_latest_finalized_block: BlockHash,
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
    // TODO: Should this be moved under Substrate?
    GenerateKey { id: KeyGenId, params: ThresholdParams },
    // Received commitments for the specified key generation protocol.
    Commitments { id: KeyGenId, commitments: HashMap<Participant, Vec<u8>> },
    // Received shares for the specified key generation protocol.
    Shares { id: KeyGenId, shares: HashMap<Participant, Vec<u8>> },
  }

  impl CoordinatorMessage {
    pub fn required_block(&self) -> Option<BlockHash> {
      None
    }
  }

  #[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
  pub enum ProcessorMessage {
    // Created commitments for the specified key generation protocol.
    Commitments { id: KeyGenId, commitments: Vec<u8> },
    // Created shares for the specified key generation protocol.
    Shares { id: KeyGenId, shares: HashMap<Participant, Vec<u8>> },
    // Resulting keys from the specified key generation protocol.
    GeneratedKeyPair { id: KeyGenId, substrate_key: [u8; 32], network_key: Vec<u8> },
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

  #[derive(Clone, PartialEq, Eq, Debug, Zeroize, Serialize, Deserialize)]
  pub enum ProcessorMessage {
    // Created preprocess for the specified signing protocol.
    Preprocess { id: SignId, preprocess: Vec<u8> },
    // Signed share for the specified signing protocol.
    Share { id: SignId, share: Vec<u8> },
    // Completed a signing protocol already.
    Completed { key: Vec<u8>, id: [u8; 32], tx: Vec<u8> },
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
  }

  impl CoordinatorMessage {
    // The Coordinator will only send Batch messages once the Batch ID has been recognized
    // The ID will only be recognized when the block is acknowledged by a super-majority of the
    // network *and the local node*
    // This synchrony obtained lets us ignore the synchrony requirement offered here
    pub fn required_block(&self) -> Option<BlockHash> {
      match self {
        CoordinatorMessage::BatchPreprocesses { .. } => None,
        CoordinatorMessage::BatchShares { .. } => None,
        CoordinatorMessage::BatchReattempt { .. } => None,
      }
    }

    pub fn key(&self) -> &[u8] {
      match self {
        CoordinatorMessage::BatchPreprocesses { id, .. } => &id.key,
        CoordinatorMessage::BatchShares { id, .. } => &id.key,
        CoordinatorMessage::BatchReattempt { id } => &id.key,
      }
    }
  }

  #[derive(Clone, PartialEq, Eq, Debug, Zeroize, Serialize, Deserialize)]
  pub enum ProcessorMessage {
    SubstrateBlockAck { network: NetworkId, block: u64, plans: Vec<[u8; 32]> },
    BatchPreprocess { id: SignId, block: BlockHash, preprocess: Vec<u8> },
    BatchShare { id: SignId, share: [u8; 32] },
  }
}

pub mod substrate {
  use super::*;

  #[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
  pub enum CoordinatorMessage {
    ConfirmKeyPair {
      context: SubstrateContext,
      set: ValidatorSet,
      key_pair: KeyPair,
    },
    SubstrateBlock {
      context: SubstrateContext,
      network: NetworkId,
      block: u64,
      key: Vec<u8>,
      burns: Vec<OutInstructionWithBalance>,
      batches: Vec<u32>,
    },
  }

  impl CoordinatorMessage {
    pub fn required_block(&self) -> Option<BlockHash> {
      let context = match self {
        CoordinatorMessage::ConfirmKeyPair { context, .. } => context,
        CoordinatorMessage::SubstrateBlock { context, .. } => context,
      };
      Some(context.network_latest_finalized_block)
    }
  }

  #[derive(Clone, PartialEq, Eq, Debug, Zeroize, Serialize, Deserialize)]
  pub enum ProcessorMessage {
    Update { key: Vec<u8>, batch: SignedBatch },
  }
}

macro_rules! impl_from {
  ($from: ident, $to: ident, $via: ident) => {
    impl From<$from::$to> for $to {
      fn from(msg: $from::$to) -> $to {
        $to::$via(msg)
      }
    }
  };
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum CoordinatorMessage {
  KeyGen(key_gen::CoordinatorMessage),
  Sign(sign::CoordinatorMessage),
  Coordinator(coordinator::CoordinatorMessage),
  Substrate(substrate::CoordinatorMessage),
}

impl_from!(key_gen, CoordinatorMessage, KeyGen);
impl_from!(sign, CoordinatorMessage, Sign);
impl_from!(coordinator, CoordinatorMessage, Coordinator);
impl_from!(substrate, CoordinatorMessage, Substrate);

impl CoordinatorMessage {
  pub fn required_block(&self) -> Option<BlockHash> {
    let required = match self {
      CoordinatorMessage::KeyGen(msg) => msg.required_block(),
      CoordinatorMessage::Sign(msg) => msg.required_block(),
      CoordinatorMessage::Coordinator(msg) => msg.required_block(),
      CoordinatorMessage::Substrate(msg) => msg.required_block(),
    };

    // 0 is used when Serai hasn't acknowledged *any* block for this network, which also means
    // there's no need to wait for the block in question
    if required == Some(BlockHash([0; 32])) {
      return None;
    }
    required
  }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum ProcessorMessage {
  KeyGen(key_gen::ProcessorMessage),
  Sign(sign::ProcessorMessage),
  Coordinator(coordinator::ProcessorMessage),
  Substrate(substrate::ProcessorMessage),
}

impl_from!(key_gen, ProcessorMessage, KeyGen);
impl_from!(sign, ProcessorMessage, Sign);
impl_from!(coordinator, ProcessorMessage, Coordinator);
impl_from!(substrate, ProcessorMessage, Substrate);

// Intent generation code

const COORDINATOR_UID: u8 = 0;
const PROCESSSOR_UID: u8 = 1;

const TYPE_KEY_GEN_UID: u8 = 2;
const TYPE_SIGN_UID: u8 = 3;
const TYPE_COORDINATOR_UID: u8 = 4;
const TYPE_SUBSTRATE_UID: u8 = 5;

impl CoordinatorMessage {
  /// The intent for this message, which should be unique across the validator's entire system,
  /// including all of its processors.
  ///
  /// This doesn't use H(msg.serialize()) as it's meant to be unique to intent, not unique to
  /// values. While the values should be consistent per intent, that assumption isn't required
  /// here.
  // TODO: Should this use borsh intead of bincode?
  pub fn intent(&self) -> Vec<u8> {
    match self {
      CoordinatorMessage::KeyGen(msg) => {
        // Unique since key gen ID embeds the validator set and attempt
        let (sub, id) = match msg {
          key_gen::CoordinatorMessage::GenerateKey { id, .. } => (0, id),
          key_gen::CoordinatorMessage::Commitments { id, .. } => (1, id),
          key_gen::CoordinatorMessage::Shares { id, .. } => (2, id),
        };

        let mut res = vec![COORDINATOR_UID, TYPE_KEY_GEN_UID, sub];
        res.extend(&bincode::serialize(id).unwrap());
        res
      }
      CoordinatorMessage::Sign(msg) => {
        let (sub, id) = match msg {
          // Unique since SignId includes a hash of the network, and specific transaction info
          sign::CoordinatorMessage::Preprocesses { id, .. } => (0, bincode::serialize(id).unwrap()),
          sign::CoordinatorMessage::Shares { id, .. } => (1, bincode::serialize(id).unwrap()),
          sign::CoordinatorMessage::Reattempt { id } => (2, bincode::serialize(id).unwrap()),
          // The coordinator should report all reported completions to the processor
          // Accordingly, the intent is a combination of plan ID and actual TX
          // While transaction alone may suffice, that doesn't cover cross-chain TX ID conflicts,
          // which are possible
          sign::CoordinatorMessage::Completed { id, tx, .. } => {
            (3, bincode::serialize(&(id, tx)).unwrap())
          }
        };

        let mut res = vec![COORDINATOR_UID, TYPE_SIGN_UID, sub];
        res.extend(&id);
        res
      }
      CoordinatorMessage::Coordinator(msg) => {
        let (sub, id) = match msg {
          // Unique since this embeds the batch ID (hash of it, including its network) and attempt
          coordinator::CoordinatorMessage::BatchPreprocesses { id, .. } => {
            (0, bincode::serialize(id).unwrap())
          }
          coordinator::CoordinatorMessage::BatchShares { id, .. } => {
            (1, bincode::serialize(id).unwrap())
          }
          coordinator::CoordinatorMessage::BatchReattempt { id, .. } => {
            (2, bincode::serialize(id).unwrap())
          }
        };

        let mut res = vec![COORDINATOR_UID, TYPE_COORDINATOR_UID, sub];
        res.extend(&id);
        res
      }
      CoordinatorMessage::Substrate(msg) => {
        let (sub, id) = match msg {
          // Unique since there's only one key pair for a set
          substrate::CoordinatorMessage::ConfirmKeyPair { set, .. } => {
            (0, bincode::serialize(set).unwrap())
          }
          substrate::CoordinatorMessage::SubstrateBlock { network, block, .. } => {
            (1, bincode::serialize(&(network, block)).unwrap())
          }
        };

        let mut res = vec![COORDINATOR_UID, TYPE_SUBSTRATE_UID, sub];
        res.extend(&id);
        res
      }
    }
  }
}

impl ProcessorMessage {
  /// The intent for this message, which should be unique across the validator's entire system,
  /// including all of its processors.
  ///
  /// This doesn't use H(msg.serialize()) as it's meant to be unique to intent, not unique to
  /// values. While the values should be consistent per intent, that assumption isn't required
  /// here.
  pub fn intent(&self) -> Vec<u8> {
    match self {
      ProcessorMessage::KeyGen(msg) => {
        let (sub, id) = match msg {
          // Unique since KeyGenId
          key_gen::ProcessorMessage::Commitments { id, .. } => (0, id),
          key_gen::ProcessorMessage::Shares { id, .. } => (1, id),
          key_gen::ProcessorMessage::GeneratedKeyPair { id, .. } => (2, id),
        };

        let mut res = vec![PROCESSSOR_UID, TYPE_KEY_GEN_UID, sub];
        res.extend(&bincode::serialize(id).unwrap());
        res
      }
      ProcessorMessage::Sign(msg) => {
        let (sub, id) = match msg {
          // Unique since SignId
          sign::ProcessorMessage::Preprocess { id, .. } => (0, bincode::serialize(id).unwrap()),
          sign::ProcessorMessage::Share { id, .. } => (1, bincode::serialize(id).unwrap()),
          // Unique since a processor will only sign a TX once
          sign::ProcessorMessage::Completed { id, .. } => (2, id.to_vec()),
        };

        let mut res = vec![PROCESSSOR_UID, TYPE_SIGN_UID, sub];
        res.extend(&id);
        res
      }
      ProcessorMessage::Coordinator(msg) => {
        let (sub, id) = match msg {
          coordinator::ProcessorMessage::SubstrateBlockAck { network, block, .. } => {
            (0, bincode::serialize(&(network, block)).unwrap())
          }
          // Unique since SignId
          coordinator::ProcessorMessage::BatchPreprocess { id, .. } => {
            (1, bincode::serialize(id).unwrap())
          }
          coordinator::ProcessorMessage::BatchShare { id, .. } => {
            (2, bincode::serialize(id).unwrap())
          }
        };

        let mut res = vec![PROCESSSOR_UID, TYPE_COORDINATOR_UID, sub];
        res.extend(&id);
        res
      }
      ProcessorMessage::Substrate(msg) => {
        let (sub, id) = match msg {
          // Unique since network and ID binding
          substrate::ProcessorMessage::Update { batch, .. } => {
            (0, bincode::serialize(&(batch.batch.network, batch.batch.id)).unwrap())
          }
        };

        let mut res = vec![PROCESSSOR_UID, TYPE_SUBSTRATE_UID, sub];
        res.extend(&id);
        res
      }
    }
  }
}
