use core::{hash::Hash, fmt::Debug};

pub trait ValidatorId: Clone + Copy + PartialEq + Eq + Hash + Debug {}
impl<V: Clone + Copy + PartialEq + Eq + Hash + Debug> ValidatorId for V {}

// Type aliases which are distinct according to the type system
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct BlockNumber(pub u32);
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct Round(pub u16);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlockError {
  // Invalid behavior entirely
  Fatal,
  // Potentially valid behavior dependent on unsynchronized state
  Temporal,
}

pub trait Block: Clone + PartialEq {
  type Id: Copy + Clone + PartialEq;

  fn id(&self) -> Self::Id;
}

pub trait Network {
  type ValidatorId: ValidatorId;
  type Block: Block;

  fn total_weight(&self) -> u64;
  fn weight(&self, validator: Self::ValidatorId) -> u64;
  fn threshold(&self) -> u64 {
    ((self.total_weight() * 2) / 3) + 1
  }

  fn proposer(&self, number: BlockNumber, round: Round) -> Self::ValidatorId;

  fn validate(&mut self, block: Self::Block) -> Result<(), BlockError>;
}
