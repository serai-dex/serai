use std::collections::HashMap;

use scale::{Encode, Decode};
use borsh::{BorshSerialize, BorshDeserialize};

use dkg::{Participant, ThresholdParams};

use serai_primitives::BlockHash;
use in_instructions_primitives::{Batch, SignedBatch};
use coins_primitives::OutInstructionWithBalance;
use validator_sets_primitives::{Session, KeyPair};

#[derive(Clone, Copy, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct SubstrateContext {
  pub serai_time: u64,
  pub network_latest_finalized_block: BlockHash,
}

pub mod key_gen {
  use super::*;

  #[derive(
    Clone, Copy, PartialEq, Eq, Hash, Debug, Encode, Decode, BorshSerialize, BorshDeserialize,
  )]
  pub struct KeyGenId {
    pub session: Session,
    pub attempt: u32,
  }

  #[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
  pub enum CoordinatorMessage {
    // Instructs the Processor to begin the key generation process.
    // TODO: Should this be moved under Substrate?
    GenerateKey {
      id: KeyGenId,
      params: ThresholdParams,
      shares: u16,
    },
    // Received commitments for the specified key generation protocol.
    Commitments {
      id: KeyGenId,
      commitments: HashMap<Participant, Vec<u8>>,
    },
    // Received shares for the specified key generation protocol.
    Shares {
      id: KeyGenId,
      shares: Vec<HashMap<Participant, Vec<u8>>>,
    },
    /// Instruction to verify a blame accusation.
    VerifyBlame {
      id: KeyGenId,
      accuser: Participant,
      accused: Participant,
      share: Vec<u8>,
      blame: Option<Vec<u8>>,
    },
  }

  impl CoordinatorMessage {
    pub fn required_block(&self) -> Option<BlockHash> {
      None
    }
  }

  #[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
  pub enum ProcessorMessage {
    // Created commitments for the specified key generation protocol.
    Commitments {
      id: KeyGenId,
      commitments: Vec<Vec<u8>>,
    },
    // Participant published invalid commitments.
    InvalidCommitments {
      id: KeyGenId,
      faulty: Participant,
    },
    // Created shares for the specified key generation protocol.
    Shares {
      id: KeyGenId,
      shares: Vec<HashMap<Participant, Vec<u8>>>,
    },
    // Participant published an invalid share.
    #[rustfmt::skip]
    InvalidShare {
      id: KeyGenId,
      accuser: Participant,
      faulty: Participant,
      blame: Option<Vec<u8>>,
    },
    // Resulting keys from the specified key generation protocol.
    GeneratedKeyPair {
      id: KeyGenId,
      substrate_key: [u8; 32],
      network_key: Vec<u8>,
    },
    // Blame this participant.
    Blame {
      id: KeyGenId,
      participant: Participant,
    },
  }
}

pub mod sign {
  use super::*;

  #[derive(Clone, PartialEq, Eq, Hash, Debug, Encode, Decode, BorshSerialize, BorshDeserialize)]
  pub struct SignId {
    pub session: Session,
    pub id: [u8; 32],
    pub attempt: u32,
  }

  #[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
  pub enum CoordinatorMessage {
    // Received preprocesses for the specified signing protocol.
    Preprocesses { id: SignId, preprocesses: HashMap<Participant, Vec<u8>> },
    // Received shares for the specified signing protocol.
    Shares { id: SignId, shares: HashMap<Participant, Vec<u8>> },
    // Re-attempt a signing protocol.
    Reattempt { id: SignId },
    // Completed a signing protocol already.
    Completed { session: Session, id: [u8; 32], tx: Vec<u8> },
  }

  impl CoordinatorMessage {
    pub fn required_block(&self) -> Option<BlockHash> {
      None
    }

    pub fn session(&self) -> Session {
      match self {
        CoordinatorMessage::Preprocesses { id, .. } |
        CoordinatorMessage::Shares { id, .. } |
        CoordinatorMessage::Reattempt { id } => id.session,
        CoordinatorMessage::Completed { session, .. } => *session,
      }
    }
  }

  #[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
  pub enum ProcessorMessage {
    // Participant sent an invalid message during the sign protocol.
    InvalidParticipant { id: SignId, participant: Participant },
    // Created preprocess for the specified signing protocol.
    Preprocess { id: SignId, preprocesses: Vec<Vec<u8>> },
    // Signed share for the specified signing protocol.
    Share { id: SignId, shares: Vec<Vec<u8>> },
    // Completed a signing protocol already.
    Completed { session: Session, id: [u8; 32], tx: Vec<u8> },
  }
}

pub mod coordinator {
  use super::*;

  pub fn cosign_block_msg(block_number: u64, block: [u8; 32]) -> Vec<u8> {
    const DST: &[u8] = b"Cosign";
    let mut res = vec![u8::try_from(DST.len()).unwrap()];
    res.extend(DST);
    res.extend(block_number.to_le_bytes());
    res.extend(block);
    res
  }

  #[derive(
    Clone, Copy, PartialEq, Eq, Hash, Debug, Encode, Decode, BorshSerialize, BorshDeserialize,
  )]
  pub enum SubstrateSignableId {
    CosigningSubstrateBlock([u8; 32]),
    Batch(u32),
    SlashReport,
  }

  #[derive(Clone, PartialEq, Eq, Hash, Debug, Encode, Decode, BorshSerialize, BorshDeserialize)]
  pub struct SubstrateSignId {
    pub session: Session,
    pub id: SubstrateSignableId,
    pub attempt: u32,
  }

  #[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
  pub enum CoordinatorMessage {
    CosignSubstrateBlock { id: SubstrateSignId, block_number: u64 },
    SignSlashReport { id: SubstrateSignId, report: Vec<([u8; 32], u32)> },
    SubstratePreprocesses { id: SubstrateSignId, preprocesses: HashMap<Participant, [u8; 64]> },
    SubstrateShares { id: SubstrateSignId, shares: HashMap<Participant, [u8; 32]> },
    // Re-attempt a batch signing protocol.
    BatchReattempt { id: SubstrateSignId },
  }

  impl CoordinatorMessage {
    // The Coordinator will only send Batch messages once the Batch ID has been recognized
    // The ID will only be recognized when the block is acknowledged by a super-majority of the
    // network *and the local node*
    // This synchrony obtained lets us ignore the synchrony requirement offered here
    pub fn required_block(&self) -> Option<BlockHash> {
      None
    }
  }

  #[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
  pub struct PlanMeta {
    pub session: Session,
    pub id: [u8; 32],
  }

  #[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
  pub enum ProcessorMessage {
    SubstrateBlockAck { block: u64, plans: Vec<PlanMeta> },
    InvalidParticipant { id: SubstrateSignId, participant: Participant },
    CosignPreprocess { id: SubstrateSignId, preprocesses: Vec<[u8; 64]> },
    BatchPreprocess { id: SubstrateSignId, block: BlockHash, preprocesses: Vec<[u8; 64]> },
    SlashReportPreprocess { id: SubstrateSignId, preprocesses: Vec<[u8; 64]> },
    SubstrateShare { id: SubstrateSignId, shares: Vec<[u8; 32]> },
    // TODO: Make these signatures [u8; 64]?
    CosignedBlock { block_number: u64, block: [u8; 32], signature: Vec<u8> },
    SignedSlashReport { session: Session, signature: Vec<u8> },
  }
}

pub mod substrate {
  use super::*;

  #[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
  pub enum CoordinatorMessage {
    ConfirmKeyPair {
      context: SubstrateContext,
      session: Session,
      key_pair: KeyPair,
    },
    SubstrateBlock {
      context: SubstrateContext,
      block: u64,
      burns: Vec<OutInstructionWithBalance>,
      batches: Vec<u32>,
    },
  }

  impl CoordinatorMessage {
    pub fn required_block(&self) -> Option<BlockHash> {
      let context = match self {
        CoordinatorMessage::ConfirmKeyPair { context, .. } |
        CoordinatorMessage::SubstrateBlock { context, .. } => context,
      };
      Some(context.network_latest_finalized_block)
    }
  }

  #[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
  pub enum ProcessorMessage {
    Batch { batch: Batch },
    SignedBatch { batch: SignedBatch },
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

#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
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

#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
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
const PROCESSOR_UID: u8 = 1;

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
  pub fn intent(&self) -> Vec<u8> {
    match self {
      CoordinatorMessage::KeyGen(msg) => {
        // Unique since key gen ID embeds the session and attempt
        let (sub, id) = match msg {
          key_gen::CoordinatorMessage::GenerateKey { id, .. } => (0, id),
          key_gen::CoordinatorMessage::Commitments { id, .. } => (1, id),
          key_gen::CoordinatorMessage::Shares { id, .. } => (2, id),
          key_gen::CoordinatorMessage::VerifyBlame { id, .. } => (3, id),
        };

        let mut res = vec![COORDINATOR_UID, TYPE_KEY_GEN_UID, sub];
        res.extend(&id.encode());
        res
      }
      CoordinatorMessage::Sign(msg) => {
        let (sub, id) = match msg {
          // Unique since SignId includes a hash of the network, and specific transaction info
          sign::CoordinatorMessage::Preprocesses { id, .. } => (0, id.encode()),
          sign::CoordinatorMessage::Shares { id, .. } => (1, id.encode()),
          sign::CoordinatorMessage::Reattempt { id } => (2, id.encode()),
          // The coordinator should report all reported completions to the processor
          // Accordingly, the intent is a combination of plan ID and actual TX
          // While transaction alone may suffice, that doesn't cover cross-chain TX ID conflicts,
          // which are possible
          sign::CoordinatorMessage::Completed { id, tx, .. } => (3, (id, tx).encode()),
        };

        let mut res = vec![COORDINATOR_UID, TYPE_SIGN_UID, sub];
        res.extend(&id);
        res
      }
      CoordinatorMessage::Coordinator(msg) => {
        let (sub, id) = match msg {
          // Unique since this ID contains the hash of the block being cosigned
          coordinator::CoordinatorMessage::CosignSubstrateBlock { id, .. } => (0, id.encode()),
          // Unique since there's only one of these per session/attempt, and ID is inclusive to
          // both
          coordinator::CoordinatorMessage::SignSlashReport { id, .. } => (1, id.encode()),
          // Unique since this embeds the batch ID (including its network) and attempt
          coordinator::CoordinatorMessage::SubstratePreprocesses { id, .. } => (2, id.encode()),
          coordinator::CoordinatorMessage::SubstrateShares { id, .. } => (3, id.encode()),
          coordinator::CoordinatorMessage::BatchReattempt { id, .. } => (4, id.encode()),
        };

        let mut res = vec![COORDINATOR_UID, TYPE_COORDINATOR_UID, sub];
        res.extend(&id);
        res
      }
      CoordinatorMessage::Substrate(msg) => {
        let (sub, id) = match msg {
          // Unique since there's only one key pair for a session
          substrate::CoordinatorMessage::ConfirmKeyPair { session, .. } => (0, session.encode()),
          substrate::CoordinatorMessage::SubstrateBlock { block, .. } => (1, block.encode()),
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
          key_gen::ProcessorMessage::InvalidCommitments { id, .. } => (1, id),
          key_gen::ProcessorMessage::Shares { id, .. } => (2, id),
          key_gen::ProcessorMessage::InvalidShare { id, .. } => (3, id),
          key_gen::ProcessorMessage::GeneratedKeyPair { id, .. } => (4, id),
          key_gen::ProcessorMessage::Blame { id, .. } => (5, id),
        };

        let mut res = vec![PROCESSOR_UID, TYPE_KEY_GEN_UID, sub];
        res.extend(&id.encode());
        res
      }
      ProcessorMessage::Sign(msg) => {
        let (sub, id) = match msg {
          // Unique since SignId
          sign::ProcessorMessage::InvalidParticipant { id, .. } => (0, id.encode()),
          sign::ProcessorMessage::Preprocess { id, .. } => (1, id.encode()),
          sign::ProcessorMessage::Share { id, .. } => (2, id.encode()),
          // Unique since a processor will only sign a TX once
          sign::ProcessorMessage::Completed { id, .. } => (3, id.to_vec()),
        };

        let mut res = vec![PROCESSOR_UID, TYPE_SIGN_UID, sub];
        res.extend(&id);
        res
      }
      ProcessorMessage::Coordinator(msg) => {
        let (sub, id) = match msg {
          coordinator::ProcessorMessage::SubstrateBlockAck { block, .. } => (0, block.encode()),
          // Unique since SubstrateSignId
          coordinator::ProcessorMessage::InvalidParticipant { id, .. } => (1, id.encode()),
          coordinator::ProcessorMessage::CosignPreprocess { id, .. } => (2, id.encode()),
          coordinator::ProcessorMessage::BatchPreprocess { id, .. } => (3, id.encode()),
          coordinator::ProcessorMessage::SlashReportPreprocess { id, .. } => (4, id.encode()),
          coordinator::ProcessorMessage::SubstrateShare { id, .. } => (5, id.encode()),
          // Unique since only one instance of a signature matters
          coordinator::ProcessorMessage::CosignedBlock { block, .. } => (6, block.encode()),
          coordinator::ProcessorMessage::SignedSlashReport { .. } => (7, vec![]),
        };

        let mut res = vec![PROCESSOR_UID, TYPE_COORDINATOR_UID, sub];
        res.extend(&id);
        res
      }
      ProcessorMessage::Substrate(msg) => {
        let (sub, id) = match msg {
          // Unique since network and ID binding
          substrate::ProcessorMessage::Batch { batch } => (0, (batch.network, batch.id).encode()),
          substrate::ProcessorMessage::SignedBatch { batch, .. } => {
            (1, (batch.batch.network, batch.batch.id).encode())
          }
        };

        let mut res = vec![PROCESSOR_UID, TYPE_SUBSTRATE_UID, sub];
        res.extend(&id);
        res
      }
    }
  }
}
