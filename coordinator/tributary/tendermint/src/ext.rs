use core::{hash::Hash, fmt::Debug};
use std::{sync::Arc, collections::HashSet};

use async_trait::async_trait;
use thiserror::Error;

use async_trait::async_trait;
use thiserror::Error;

use parity_scale_codec::{Encode, Decode};

use crate::{SignedMessageFor, commit_msg};

/// An alias for a series of traits required for a type to be usable as a validator ID,
/// automatically implemented for all types satisfying those traits.
pub trait ValidatorId:
  Send + Sync + Clone + Copy + PartialEq + Eq + Hash + Debug + Encode + Decode
{
}
impl<V: Send + Sync + Clone + Copy + PartialEq + Eq + Hash + Debug + Encode + Decode> ValidatorId
  for V
{
}

/// An alias for a series of traits required for a type to be usable as a signature,
/// automatically implemented for all types satisfying those traits.
pub trait Signature: Send + Sync + Clone + PartialEq + Debug + Encode + Decode {}
impl<S: Send + Sync + Clone + PartialEq + Debug + Encode + Decode> Signature for S {}

// Type aliases which are distinct according to the type system

/// A struct containing a Block Number, wrapped to have a distinct type.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Encode, Decode)]
pub struct BlockNumber(pub u64);
/// A struct containing a round number, wrapped to have a distinct type.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Encode, Decode)]
pub struct RoundNumber(pub u32);

/// A signer for a validator.
#[async_trait]
pub trait Signer: Send + Sync {
  // Type used to identify validators.
  type ValidatorId: ValidatorId;
  /// Signature type.
  type Signature: Signature;

  /// Returns the validator's current ID. Returns None if they aren't a current validator.
  async fn validator_id(&self) -> Option<Self::ValidatorId>;
  /// Sign a signature with the current validator's private key.
  async fn sign(&self, msg: &[u8]) -> Self::Signature;
}

#[async_trait]
impl<S: Signer> Signer for Arc<S> {
  type ValidatorId = S::ValidatorId;
  type Signature = S::Signature;

  async fn validator_id(&self) -> Option<Self::ValidatorId> {
    self.as_ref().validator_id().await
  }

  async fn sign(&self, msg: &[u8]) -> Self::Signature {
    self.as_ref().sign(msg).await
  }
}

/// A signer for a validator.
#[async_trait]
pub trait Signer: Send + Sync {
  // Type used to identify validators.
  type ValidatorId: ValidatorId;
  /// Signature type.
  type Signature: Signature;

  /// Returns the validator's current ID.
  async fn validator_id(&self) -> Self::ValidatorId;
  /// Sign a signature with the current validator's private key.
  async fn sign(&self, msg: &[u8]) -> Self::Signature;
}

#[async_trait]
impl<S: Signer> Signer for Arc<S> {
  type ValidatorId = S::ValidatorId;
  type Signature = S::Signature;

  async fn validator_id(&self) -> Self::ValidatorId {
    self.as_ref().validator_id().await
  }

  async fn sign(&self, msg: &[u8]) -> Self::Signature {
    self.as_ref().sign(msg).await
  }
}

/// A signature scheme used by validators.
pub trait SignatureScheme: Send + Sync {
  // Type used to identify validators.
  type ValidatorId: ValidatorId;
  /// Signature type.
  type Signature: Signature;
  /// Type representing an aggregate signature. This would presumably be a BLS signature,
  /// yet even with Schnorr signatures
  /// [half-aggregation is possible](https://eprint.iacr.org/2021/350).
  /// It could even be a threshold signature scheme, though that's currently unexpected.
  type AggregateSignature: Signature;

<<<<<<< HEAD:coordinator/tributary/tendermint/src/ext.rs
<<<<<<< HEAD:coordinator/tributary/tendermint/src/ext.rs
  /// Type representing a signer of this scheme.
  type Signer: Signer<ValidatorId = Self::ValidatorId, Signature = Self::Signature>;

=======
  /// Sign a signature with the current validator's private key.
  async fn sign(&self, msg: &[u8]) -> Self::Signature;
>>>>>>> 2947ef08 (Make sign asynchronous):substrate/tendermint/machine/src/ext.rs
=======
  /// Type representing a signer of this scheme.
  type Signer: Signer<ValidatorId = Self::ValidatorId, Signature = Self::Signature>;

>>>>>>> f3e17710 (Reduce Arcs in TendermintMachine, split Signer from SignatureScheme):substrate/tendermint/machine/src/ext.rs
  /// Verify a signature from the validator in question.
  #[must_use]
  fn verify(&self, validator: Self::ValidatorId, msg: &[u8], sig: &Self::Signature) -> bool;

  /// Aggregate signatures.
  fn aggregate(sigs: &[Self::Signature]) -> Self::AggregateSignature;
  /// Verify an aggregate signature for the list of signers.
  #[must_use]
  fn verify_aggregate(
    &self,
    signers: &[Self::ValidatorId],
    msg: &[u8],
    sig: &Self::AggregateSignature,
  ) -> bool;
}

impl<S: SignatureScheme> SignatureScheme for Arc<S> {
  type ValidatorId = S::ValidatorId;
  type Signature = S::Signature;
  type AggregateSignature = S::AggregateSignature;
  type Signer = S::Signer;

  fn verify(&self, validator: Self::ValidatorId, msg: &[u8], sig: &Self::Signature) -> bool {
    self.as_ref().verify(validator, msg, sig)
  }

  fn aggregate(sigs: &[Self::Signature]) -> Self::AggregateSignature {
    S::aggregate(sigs)
  }

  #[must_use]
  fn verify_aggregate(
    &self,
    signers: &[Self::ValidatorId],
    msg: &[u8],
    sig: &Self::AggregateSignature,
  ) -> bool {
    self.as_ref().verify_aggregate(signers, msg, sig)
  }
}

<<<<<<< HEAD:coordinator/tributary/tendermint/src/ext.rs
/// A commit for a specific block.
///
/// The list of validators have weight exceeding the threshold for a valid commit.
#[derive(PartialEq, Debug, Encode, Decode)]
=======
/// A commit for a specific block. The list of validators have weight exceeding the threshold for
/// a valid commit.
#[derive(Clone, PartialEq, Debug, Encode, Decode)]
>>>>>>> f3e17710 (Reduce Arcs in TendermintMachine, split Signer from SignatureScheme):substrate/tendermint/machine/src/ext.rs
pub struct Commit<S: SignatureScheme> {
<<<<<<< HEAD:coordinator/tributary/tendermint/src/ext.rs
  /// End time of the round which created this commit, used as the start time of the next block.
=======
  /// End time of the round, used as the start time of next round.
>>>>>>> a7f48047 (Move Commit from including the round to including the round's end_time):substrate/tendermint/src/ext.rs
  pub end_time: u64,
  /// Validators participating in the signature.
  pub validators: Vec<S::ValidatorId>,
  /// Aggregate signature.
  pub signature: S::AggregateSignature,
}

impl<S: SignatureScheme> Clone for Commit<S> {
  fn clone(&self) -> Self {
    Self {
      end_time: self.end_time,
      validators: self.validators.clone(),
      signature: self.signature.clone(),
    }
  }
}

/// Weights for the validators present.
pub trait Weights: Send + Sync {
  type ValidatorId: ValidatorId;

  /// Total weight of all validators.
  fn total_weight(&self) -> u64;
  /// Weight for a specific validator.
  fn weight(&self, validator: Self::ValidatorId) -> u64;
  /// Threshold needed for BFT consensus.
  fn threshold(&self) -> u64 {
    ((self.total_weight() * 2) / 3) + 1
  }
  /// Threshold preventing BFT consensus.
  fn fault_thresold(&self) -> u64 {
    (self.total_weight() - self.threshold()) + 1
  }

  /// Weighted round robin function.
  fn proposer(&self, block: BlockNumber, round: RoundNumber) -> Self::ValidatorId;
}

impl<W: Weights> Weights for Arc<W> {
  type ValidatorId = W::ValidatorId;

  fn total_weight(&self) -> u64 {
    self.as_ref().total_weight()
  }

  fn weight(&self, validator: Self::ValidatorId) -> u64 {
    self.as_ref().weight(validator)
  }

  fn proposer(&self, block: BlockNumber, round: RoundNumber) -> Self::ValidatorId {
    self.as_ref().proposer(block, round)
  }
}

impl<W: Weights> Weights for Arc<W> {
  type ValidatorId = W::ValidatorId;

  fn total_weight(&self) -> u64 {
    self.as_ref().total_weight()
  }

  fn weight(&self, validator: Self::ValidatorId) -> u64 {
    self.as_ref().weight(validator)
  }

  fn proposer(&self, number: BlockNumber, round: Round) -> Self::ValidatorId {
    self.as_ref().proposer(number, round)
  }
}

/// Simplified error enum representing a block's validity.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Error, Encode, Decode)]
pub enum BlockError {
  /// Malformed block which is wholly invalid.
  #[error("invalid block")]
  Fatal,
  /// Valid block by syntax, with semantics which may or may not be valid yet are locally
  /// considered invalid. If a block fails to validate with this, a slash will not be triggered.
  #[error("invalid block under local view")]
  Temporal,
}

/// Trait representing a Block.
pub trait Block: Send + Sync + Clone + PartialEq + Debug + Encode + Decode {
  // Type used to identify blocks. Presumably a cryptographic hash of the block.
  type Id: Send + Sync + Copy + Clone + PartialEq + AsRef<[u8]> + Debug + Encode + Decode;

  /// Return the deterministic, unique ID for this block.
  fn id(&self) -> Self::Id;
}

/// Trait representing the distributed system Tendermint is providing consensus over.
#[async_trait]
pub trait Network: Send + Sync {
  // Type used to identify validators.
  type ValidatorId: ValidatorId;
  /// Signature scheme used by validators.
  type SignatureScheme: SignatureScheme<ValidatorId = Self::ValidatorId>;
  /// Object representing the weights of validators.
  type Weights: Weights<ValidatorId = Self::ValidatorId>;
  /// Type used for ordered blocks of information.
  type Block: Block;

  /// Maximum block processing time in seconds. This should include both the actual processing time
  /// and the time to download the block.
  const BLOCK_PROCESSING_TIME: u32;
  /// Network latency time in seconds.
  const LATENCY_TIME: u32;
<<<<<<< HEAD:coordinator/tributary/tendermint/src/ext.rs
=======

  /// The block time is defined as the processing time plus three times the latency.
  fn block_time() -> u32 {
    Self::BLOCK_PROCESSING_TIME + (3 * Self::LATENCY_TIME)
  }
>>>>>>> fffb7a69 (Separate the block processing time from the latency):substrate/tendermint/machine/src/ext.rs

<<<<<<< HEAD:coordinator/tributary/tendermint/src/ext.rs
  /// The block time is defined as the processing time plus three times the latency.
  fn block_time() -> u32 {
    Self::BLOCK_PROCESSING_TIME + (3 * Self::LATENCY_TIME)
  }

=======
>>>>>>> f3e17710 (Reduce Arcs in TendermintMachine, split Signer from SignatureScheme):substrate/tendermint/machine/src/ext.rs
  /// Return a handle on the signer in use, usable for the entire lifetime of the machine.
  fn signer(&self) -> <Self::SignatureScheme as SignatureScheme>::Signer;
  /// Return a handle on the signing scheme in use, usable for the entire lifetime of the machine.
  fn signature_scheme(&self) -> Self::SignatureScheme;
  /// Return a handle on the validators' weights, usable for the entire lifetime of the machine.
  fn weights(&self) -> Self::Weights;

  /// Verify a commit for a given block. Intended for use when syncing or when not an active
  /// validator.
  #[must_use]
  fn verify_commit(
    &self,
    id: <Self::Block as Block>::Id,
    commit: &Commit<Self::SignatureScheme>,
  ) -> bool {
    if commit.validators.iter().collect::<HashSet<_>>().len() != commit.validators.len() {
      return false;
    }

    if !self.signature_scheme().verify_aggregate(
      &commit.validators,
      &commit_msg(commit.end_time, id.as_ref()),
      &commit.signature,
    ) {
      return false;
    }

    let weights = self.weights();
    commit.validators.iter().map(|v| weights.weight(*v)).sum::<u64>() >= weights.threshold()
  }

  /// Broadcast a message to the other validators.
  ///
  /// If authenticated channels have already been established, this will double-authenticate.
  /// Switching to unauthenticated channels in a system already providing authenticated channels is
  /// not recommended as this is a minor, temporal inefficiency, while downgrading channels may
  /// have wider implications.
  async fn broadcast(&mut self, msg: SignedMessageFor<Self>);

  /// Trigger a slash for the validator in question who was definitively malicious.
  ///
  /// The exact process of triggering a slash is undefined and left to the network as a whole.
<<<<<<< HEAD:coordinator/tributary/tendermint/src/ext.rs
  // TODO: We need to provide some evidence for this.
=======
>>>>>>> dbcddb2f (Don't spam slash):substrate/tendermint/machine/src/ext.rs
  async fn slash(&mut self, validator: Self::ValidatorId);

  /// Validate a block.
  async fn validate(&mut self, block: &Self::Block) -> Result<(), BlockError>;
<<<<<<< HEAD:coordinator/tributary/tendermint/src/ext.rs

  /// Add a block, returning the proposal for the next one.
  ///
  /// It's possible a block, which was never validated or even failed validation, may be passed
  /// here if a supermajority of validators did consider it valid and created a commit for it.
  ///
  /// This deviates from the paper which will have a local node refuse to decide on a block it
  /// considers invalid. This library acknowledges the network did decide on it, leaving handling
  /// of it to the network, and outside of this scope.
=======
  /// Add a block, returning the proposal for the next one. It's possible a block, which was never
  /// validated or even failed validation, may be passed here if a supermajority of validators did
  /// consider it valid and created a commit for it. This deviates from the paper which will have a
  /// local node refuse to decide on a block it considers invalid. This library acknowledges the
  /// network did decide on it, leaving handling of it to the network, and outside of this scope.
>>>>>>> 193281e3 (Get the result of block importing):substrate/tendermint/src/ext.rs
  async fn add_block(
    &mut self,
    block: Self::Block,
    commit: Commit<Self::SignatureScheme>,
  ) -> Option<Self::Block>;
}
