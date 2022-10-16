use std::sync::Arc;

use tokio::sync::RwLock;

use tendermint_machine::{ext::*, Message, TendermintMachine, TendermintHandle};

type TestValidatorId = u16;
type TestBlockId = u32;

struct TestSignatureScheme(u16);
impl SignatureScheme for TestSignatureScheme {
  type ValidatorId = TestValidatorId;
  type Signature = [u8; 32];
  type AggregateSignature = Vec<[u8; 32]>;

  fn sign(&self, msg: &[u8]) -> [u8; 32] {
    let mut sig = [0; 32];
    sig[.. 2].copy_from_slice(&self.0.to_le_bytes());
    sig[2 .. (2 + 30.min(msg.len()))].copy_from_slice(msg);
    sig
  }

  fn verify(&self, validator: u16, msg: &[u8], sig: [u8; 32]) -> bool {
    (sig[.. 2] == validator.to_le_bytes()) && (&sig[2 ..] == &[msg, &[0; 30]].concat()[.. 30])
  }

  fn aggregate(sigs: &[[u8; 32]]) -> Vec<[u8; 32]> {
    sigs.to_vec()
  }
}

struct TestWeights;
impl Weights for TestWeights {
  type ValidatorId = TestValidatorId;

  fn total_weight(&self) -> u64 {
    4
  }
  fn weight(&self, id: TestValidatorId) -> u64 {
    [1; 4][usize::try_from(id).unwrap()]
  }

  fn proposer(&self, number: BlockNumber, round: Round) -> TestValidatorId {
    TestValidatorId::try_from((number.0 + u32::from(round.0)) % 4).unwrap()
  }
}

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

struct TestNetwork(u16, Arc<RwLock<Vec<TendermintHandle<Self>>>>);

#[async_trait::async_trait]
impl Network for TestNetwork {
  type ValidatorId = TestValidatorId;
  type SignatureScheme = TestSignatureScheme;
  type Weights = TestWeights;
  type Block = TestBlock;

  const BLOCK_TIME: u32 = 1;

  fn signature_scheme(&self) -> Arc<TestSignatureScheme> {
    Arc::new(TestSignatureScheme(self.0))
  }

  fn weights(&self) -> Arc<TestWeights> {
    Arc::new(TestWeights)
  }

  async fn broadcast(&mut self, msg: Message<TestValidatorId, Self::Block>) {
    for handle in self.1.write().await.iter_mut() {
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
        let i = u16::try_from(i).unwrap();
        write.push(TendermintMachine::new(
          TestNetwork(i, arc.clone()),
          i,
          BlockNumber(1),
          TestBlock { id: 1, valid: Ok(()) },
        ));
      }
    }
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
