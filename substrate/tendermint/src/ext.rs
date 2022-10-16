use core::{hash::Hash, fmt::Debug};

pub trait ValidatorId: Clone + Copy + PartialEq + Eq + Hash + Debug {}
impl<V: Clone + Copy + PartialEq + Eq + Hash + Debug> ValidatorId for V {}

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

pub trait Network<V: ValidatorId, B: Block> {
  fn total_weight(&self) -> u64;
  fn weight(&self, validator: V) -> u64;
  fn threshold(&self) -> u64 {
    ((self.total_weight() * 2) / 3) + 1
  }

  fn validate(&mut self, block: B) -> Result<(), BlockError>;
}
