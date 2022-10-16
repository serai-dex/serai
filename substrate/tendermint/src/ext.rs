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

// Type aliases which are distinct according to the type system
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Encode, Decode)]
pub struct BlockNumber(pub u32);
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Encode, Decode)]
pub struct Round(pub u16);

pub trait SignatureScheme: Send + Sync {
  type ValidatorId: ValidatorId;
  type Signature: Send + Sync + Clone + Copy + PartialEq + Debug + Encode + Decode;
  type AggregateSignature: Send + Sync + Clone + PartialEq + Debug + Encode + Decode;

  fn sign(&self, msg: &[u8]) -> Self::Signature;
  #[must_use]
  fn verify(&self, validator: Self::ValidatorId, msg: &[u8], sig: Self::Signature) -> bool;
  // Intended to be a BLS signature, a Schnorr signature half-aggregation, or a Vec<Signature>.
  fn aggregate(signatures: &[Self::Signature]) -> Self::AggregateSignature;
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
  fn add_block(&mut self, block: Self::Block) -> Self::Block;
}
