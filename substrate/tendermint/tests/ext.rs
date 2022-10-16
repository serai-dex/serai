use std::sync::Arc;

use tokio::sync::{RwLock, mpsc};

use tendermint_machine::{ext::*, Message, TendermintMachine, TendermintHandle};

type TestValidatorId = u16;
type TestBlockId = u32;

#[derive(Clone, PartialEq, Debug)]
struct TestBlock {
  id: TestBlockId,
  valid: Result<(), BlockError>,
}

impl Block for TestBlock {
  type Id = TestBlockId;

  fn id(&self) -> TestBlockId {
    self.id
  }
}

struct TestWeights;
impl Weights for TestWeights {
  type ValidatorId = TestValidatorId;

  fn total_weight(&self) -> u64 {
    5
  }
  fn weight(&self, id: TestValidatorId) -> u64 {
    [1, 1, 1, 1, 1][usize::try_from(id).unwrap()]
  }

  fn proposer(&self, number: BlockNumber, round: Round) -> TestValidatorId {
    TestValidatorId::try_from((number.0 + u32::from(round.0)) % 5).unwrap()
  }
}

struct TestNetwork(Arc<RwLock<Vec<TendermintHandle<Self>>>>);

#[async_trait::async_trait]
impl Network for TestNetwork {
  type ValidatorId = TestValidatorId;
  type Weights = TestWeights;
  type Block = TestBlock;

  fn weights(&self) -> Arc<TestWeights> {
    Arc::new(TestWeights)
  }

  async fn broadcast(&mut self, msg: Message<TestValidatorId, Self::Block>) {
    for handle in self.0.write().await.iter_mut() {
      handle.messages.send(msg.clone()).await.unwrap();
    }
  }

  async fn slash(&mut self, validator: TestValidatorId) {
    dbg!("Slash");
    todo!()
  }

  fn validate(&mut self, block: &TestBlock) -> Result<(), BlockError> {
    block.valid
  }

  fn add_block(&mut self, block: TestBlock) -> TestBlock {
    dbg!("Adding ", &block);
    assert!(block.valid.is_ok());
    TestBlock { id: block.id + 1, valid: Ok(()) }
  }
}

impl TestNetwork {
  async fn new(validators: usize) -> Arc<RwLock<Vec<TendermintHandle<Self>>>> {
    let arc = Arc::new(RwLock::new(vec![]));
    {
      let mut write = arc.write().await;
      for i in 0 .. validators {
        write.push(TendermintMachine::new(
          TestNetwork(arc.clone()),
          u16::try_from(i).unwrap(),
          BlockNumber(1),
          TestBlock { id: 1, valid: Ok(()) },
        ));
      }
    }
    dbg!("Created all machines");
    arc
  }
}

#[tokio::test]
async fn test() {
  TestNetwork::new(4).await;
  loop {
    tokio::task::yield_now().await;
  }
}
