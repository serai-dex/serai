use core::{hash::Hash, fmt::Debug};
use std::sync::Arc;

use parity_scale_codec::{Encode, Decode};

use crate::SignedMessage;

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
pub struct Round(pub u32);

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

  /// Sign a signature with the current validator's private key.
  fn sign(&self, msg: &[u8]) -> Self::Signature;
  /// Verify a signature from the validator in question.
  #[must_use]
  fn verify(&self, validator: Self::ValidatorId, msg: &[u8], sig: Self::Signature) -> bool;

  /// Aggregate signatures.
  fn aggregate(sigs: &[Self::Signature]) -> Self::AggregateSignature;
  /// Verify an aggregate signature for the list of signers.
  #[must_use]
  fn verify_aggregate(
    &self,
    msg: &[u8],
    signers: &[Self::ValidatorId],
    sig: &Self::AggregateSignature,
  ) -> bool;
}

/// A commit for a specific block. The list of validators have weight exceeding the threshold for
/// a valid commit.
#[derive(Clone, PartialEq, Debug, Encode, Decode)]
pub struct Commit<S: SignatureScheme> {
  /// Validators participating in the signature.
  pub validators: Vec<S::ValidatorId>,
  /// Aggregate signature.
  pub signature: S::AggregateSignature,
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
  fn proposer(&self, number: BlockNumber, round: Round) -> Self::ValidatorId;
}

/// Simplified error enum representing a block's validity.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Encode, Decode)]
pub enum BlockError {
  /// Malformed block which is wholly invalid.
  Fatal,
  /// Valid block by syntax, with semantics which may or may not be valid yet are locally
  /// considered invalid. If a block fails to validate with this, a slash will not be triggered.
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
#[async_trait::async_trait]
pub trait Network: Send + Sync {
  // Type used to identify validators.
  type ValidatorId: ValidatorId;
  /// Signature scheme used by validators.
  type SignatureScheme: SignatureScheme<ValidatorId = Self::ValidatorId>;
  /// Object representing the weights of validators.
  type Weights: Weights<ValidatorId = Self::ValidatorId>;
  /// Type used for ordered blocks of information.
  type Block: Block;

  // Block time in seconds
  const BLOCK_TIME: u32;

  /// Return the signature scheme in use. The instance is expected to have the validators' public
  /// keys, along with an instance of the private key of the current validator.
  fn signature_scheme(&self) -> Arc<Self::SignatureScheme>;
  /// Return a reference to the validators' weights.
  fn weights(&self) -> Arc<Self::Weights>;

  /// Verify a commit for a given block. Intended for use when syncing or when not an active
  /// validator.
  #[must_use]
  fn verify_commit(
    &self,
    id: <Self::Block as Block>::Id,
    commit: &Commit<Self::SignatureScheme>,
  ) -> bool {
    if !self.signature_scheme().verify_aggregate(
      &id.encode(),
      &commit.validators,
      &commit.signature,
    ) {
      return false;
    }

    let weights = self.weights();
    commit.validators.iter().map(|v| weights.weight(*v)).sum::<u64>() >= weights.threshold()
  }

  /// Broadcast a message to the other validators. If authenticated channels have already been
  /// established, this will double-authenticate. Switching to unauthenticated channels in a system
  /// already providing authenticated channels is not recommended as this is a minor, temporal
  /// inefficiency while downgrading channels may have wider implications.
  async fn broadcast(
    &mut self,
    msg: SignedMessage<
      Self::ValidatorId,
      Self::Block,
      <Self::SignatureScheme as SignatureScheme>::Signature,
    >,
  );

  /// Trigger a slash for the validator in question who was definitively malicious.
  /// The exact process of triggering a slash is undefined and left to the network as a whole.
  // TODO: This is spammed right now.
  async fn slash(&mut self, validator: Self::ValidatorId);

  /// Validate a block.
  fn validate(&mut self, block: &Self::Block) -> Result<(), BlockError>;
  /// Add a block, returning the proposal for the next one. It's possible a block, which was never
  /// validated or even failed validation, may be passed here if a supermajority of validators did
  /// consider it valid and created a commit for it. This deviates from the paper which will have a
  /// local node refuse to decide on a block it considers invalid. This library acknowledges the
  /// network did decide on it, leaving handling of it to the network, and outside of this scope.
  fn add_block(&mut self, block: Self::Block, commit: Commit<Self::SignatureScheme>)
    -> Self::Block;
}
