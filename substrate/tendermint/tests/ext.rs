use tendermint_machine::ext::{BlockError, Block, Network};

#[derive(Clone, PartialEq)]
struct TestBlock {
  id: u32,
  valid: Result<(), BlockError>,
}

impl Block for TestBlock {
  type Id = u32;

  fn id(&self) -> u32 {
    self.id
  }
}

struct TestNetwork;
impl Network<u16, TestBlock> for TestNetwork {
  fn total_weight(&self) -> u64 {
    5
  }
  fn weight(&self, id: u16) -> u64 {
    [1, 1, 1, 1, 1][usize::try_from(id).unwrap()]
  }

  fn validate(&mut self, block: TestBlock) -> Result<(), BlockError> {
    block.valid
  }
}
