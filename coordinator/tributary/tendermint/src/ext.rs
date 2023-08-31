use core::{hash::Hash, fmt::Debug};
use std::{sync::Arc, collections::HashSet};

use async_trait::async_trait;
use thiserror::Error;

use parity_scale_codec::{Encode, Decode};

use crate::{SignedMessageFor, SlashEvent, commit_msg};

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
pub trait Signature: Send + Sync + Clone + PartialEq + Eq + Debug + Encode + Decode {}
impl<S: Send + Sync + Clone + PartialEq + Eq + Debug + Encode + Decode> Signature for S {}

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

/// A signature scheme used by validators.
pub trait SignatureScheme: Send + Sync + Clone {
  // Type used to identify validators.
  type ValidatorId: ValidatorId;
  /// Signature type.
  type Signature: Signature;
  /// Type representing an aggregate signature. This would presumably be a BLS signature,
  /// yet even with Schnorr signatures
  /// [half-aggregation is possible](https://eprint.iacr.org/2021/350).
  /// It could even be a threshold signature scheme, though that's currently unexpected.
  type AggregateSignature: Signature;

  /// Type representing a signer of this scheme.
  type Signer: Signer<ValidatorId = Self::ValidatorId, Signature = Self::Signature>;

  /// Verify a signature from the validator in question.
  #[must_use]
  fn verify(&self, validator: Self::ValidatorId, msg: &[u8], sig: &Self::Signature) -> bool;

  /// Aggregate signatures.
  /// It may panic if corrupted data passed in.
  fn aggregate(
    &self,
    validators: &[Self::ValidatorId],
    msg: &[u8],
    sigs: &[Self::Signature],
  ) -> Self::AggregateSignature;
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

  fn aggregate(
    &self,
    validators: &[Self::ValidatorId],
    msg: &[u8],
    sigs: &[Self::Signature],
  ) -> Self::AggregateSignature {
    self.as_ref().aggregate(validators, msg, sigs)
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

/// A commit for a specific block.
///
/// The list of validators have weight exceeding the threshold for a valid commit.
#[derive(PartialEq, Debug, Encode, Decode)]
pub struct Commit<S: SignatureScheme> {
  /// End time of the round which created this commit, used as the start time of the next block.
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
  fn fault_threshold(&self) -> u64 {
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
pub trait Block: Send + Sync + Clone + PartialEq + Eq + Debug + Encode + Decode {
  // Type used to identify blocks. Presumably a cryptographic hash of the block.
  type Id: Send + Sync + Copy + Clone + PartialEq + Eq + AsRef<[u8]> + Debug + Encode + Decode;

  /// Return the deterministic, unique ID for this block.
  fn id(&self) -> Self::Id;
}

/// Trait representing the distributed system Tendermint is providing consensus over.
#[async_trait]
pub trait Network: Sized + Send + Sync {
  // Type used to identify validators.
  type ValidatorId: ValidatorId;
  /// Signature scheme used by validators.
  type SignatureScheme: SignatureScheme<ValidatorId = Self::ValidatorId>;
  /// Object representing the weights of validators.
  type Weights: Weights<ValidatorId = Self::ValidatorId>;
  /// Type used for ordered blocks of information.
  type Block: Block;

  /// Maximum block processing time in milliseconds.
  ///
  /// This should include both the time to download the block and the actual processing time.
  ///
  /// BLOCK_PROCESSING_TIME + (3 * LATENCY_TIME) must be divisible by 1000.
  const BLOCK_PROCESSING_TIME: u32;
  /// Network latency time in milliseconds.
  ///
  /// BLOCK_PROCESSING_TIME + (3 * LATENCY_TIME) must be divisible by 1000.
  const LATENCY_TIME: u32;

  /// The block time, in seconds. Defined as the processing time plus three times the latency.
  fn block_time() -> u32 {
    let raw = Self::BLOCK_PROCESSING_TIME + (3 * Self::LATENCY_TIME);
    let res = raw / 1000;
    assert_eq!(res * 1000, raw);
    res
  }

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
  // TODO: We need to provide some evidence for this.
  async fn slash(&mut self, validator: Self::ValidatorId, slash_event: SlashEvent<Self>);

  /// Validate a block.
  async fn validate(&mut self, block: &Self::Block) -> Result<(), BlockError>;

  /// Add a block, returning the proposal for the next one.
  ///
  /// It's possible a block, which was never validated or even failed validation, may be passed
  /// here if a supermajority of validators did consider it valid and created a commit for it.
  ///
  /// This deviates from the paper which will have a local node refuse to decide on a block it
  /// considers invalid. This library acknowledges the network did decide on it, leaving handling
  /// of it to the network, and outside of this scope.
  async fn add_block(
    &mut self,
    block: Self::Block,
    commit: Commit<Self::SignatureScheme>,
  ) -> Option<Self::Block>;
}
