use tendermint_machine::ext::*;

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
impl Network for TestNetwork {
  type ValidatorId = u16;
  type Block = TestBlock;

  fn total_weight(&self) -> u64 {
    5
  }
  fn weight(&self, id: u16) -> u64 {
    [1, 1, 1, 1, 1][usize::try_from(id).unwrap()]
  }

  fn proposer(&self, number: BlockNumber, round: Round) -> u16 {
    u16::try_from((number.0 + u32::from(round.0)) % 5).unwrap()
  }

  fn validate(&mut self, block: TestBlock) -> Result<(), BlockError> {
    block.valid
  }
}
