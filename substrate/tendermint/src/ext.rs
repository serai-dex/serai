use core::{hash::Hash, fmt::Debug};
use std::sync::Arc;

use parity_scale_codec::{Encode, Decode};

use crate::SignedMessage;

pub trait ValidatorId:
  Send + Sync + Clone + Copy + PartialEq + Eq + Hash + Debug + Encode + Decode
{
}
impl<V: Send + Sync + Clone + Copy + PartialEq + Eq + Hash + Debug + Encode + Decode> ValidatorId
  for V
{
}

pub trait Signature: Send + Sync + Clone + PartialEq + Debug + Encode + Decode {}
impl<S: Send + Sync + Clone + PartialEq + Debug + Encode + Decode> Signature for S {}

// Type aliases which are distinct according to the type system
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Encode, Decode)]
pub struct BlockNumber(pub u32);
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Encode, Decode)]
pub struct Round(pub u16);

pub trait SignatureScheme: Send + Sync {
  type ValidatorId: ValidatorId;
  type Signature: Signature;
  type AggregateSignature: Signature;

  fn sign(&self, msg: &[u8]) -> Self::Signature;
  #[must_use]
  fn verify(&self, validator: Self::ValidatorId, msg: &[u8], sig: Self::Signature) -> bool;

  fn aggregate(sigs: &[Self::Signature]) -> Self::AggregateSignature;
  #[must_use]
  fn verify_aggregate(
    &self,
    msg: &[u8],
    signers: &[Self::ValidatorId],
    sig: Self::AggregateSignature,
  ) -> bool;
}

#[derive(Clone, PartialEq, Debug, Encode, Decode)]
pub struct Commit<S: SignatureScheme> {
  pub validators: Vec<S::ValidatorId>,
  pub signature: S::AggregateSignature,
}

pub trait Weights: Send + Sync {
  type ValidatorId: ValidatorId;

  fn total_weight(&self) -> u64;
  fn weight(&self, validator: Self::ValidatorId) -> u64;
  fn threshold(&self) -> u64 {
    ((self.total_weight() * 2) / 3) + 1
  }
  fn fault_thresold(&self) -> u64 {
    (self.total_weight() - self.threshold()) + 1
  }

  /// Weighted round robin function.
  fn proposer(&self, number: BlockNumber, round: Round) -> Self::ValidatorId;
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Encode, Decode)]
pub enum BlockError {
  // Invalid behavior entirely
  Fatal,
  // Potentially valid behavior dependent on unsynchronized state
  Temporal,
}

pub trait Block: Send + Sync + Clone + PartialEq + Debug + Encode + Decode {
  type Id: Send + Sync + Copy + Clone + PartialEq + Debug + Encode + Decode;

  fn id(&self) -> Self::Id;
}

#[async_trait::async_trait]
pub trait Network: Send + Sync {
  type ValidatorId: ValidatorId;
  type SignatureScheme: SignatureScheme<ValidatorId = Self::ValidatorId>;
  type Weights: Weights<ValidatorId = Self::ValidatorId>;
  type Block: Block;

  // Block time in seconds
  const BLOCK_TIME: u32;

  fn signature_scheme(&self) -> Arc<Self::SignatureScheme>;
  fn weights(&self) -> Arc<Self::Weights>;

  #[must_use]
  fn verify_commit(
    &self,
    id: <Self::Block as Block>::Id,
    commit: Commit<Self::SignatureScheme>,
  ) -> bool {
    if !self.signature_scheme().verify_aggregate(&id.encode(), &commit.validators, commit.signature)
    {
      return false;
    }

    let weights = self.weights();
    commit.validators.iter().map(|v| weights.weight(*v)).sum::<u64>() >= weights.threshold()
  }

  async fn broadcast(
    &mut self,
    msg: SignedMessage<
      Self::ValidatorId,
      Self::Block,
      <Self::SignatureScheme as SignatureScheme>::Signature,
    >,
  );

  // TODO: Should this take a verifiable reason?
  async fn slash(&mut self, validator: Self::ValidatorId);

  fn validate(&mut self, block: &Self::Block) -> Result<(), BlockError>;
  // Add a block and return the proposal for the next one
  fn add_block(&mut self, block: Self::Block, commit: Commit<Self::SignatureScheme>)
    -> Self::Block;
}
