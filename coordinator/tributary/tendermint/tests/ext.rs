use std::{
  sync::Arc,
  time::{UNIX_EPOCH, SystemTime, Duration},
};

use async_trait::async_trait;

use parity_scale_codec::{Encode, Decode};

use futures::SinkExt;
use tokio::{sync::RwLock, time::sleep};

use tendermint_machine::{
  ext::*, SignedMessageFor, SyncedBlockSender, SyncedBlockResultReceiver, MessageSender,
  TendermintMachine, TendermintHandle,
};

type TestValidatorId = u16;
type TestBlockId = [u8; 4];

<<<<<<< HEAD:coordinator/tributary/tendermint/tests/ext.rs
struct TestSigner(u16);
#[async_trait]
impl Signer for TestSigner {
=======
struct TestSignatureScheme(u16);
#[async_trait]
impl SignatureScheme for TestSignatureScheme {
>>>>>>> 2947ef08 (Make sign asynchronous):substrate/tendermint/machine/tests/ext.rs
  type ValidatorId = TestValidatorId;
  type Signature = [u8; 32];

<<<<<<< HEAD:coordinator/tributary/tendermint/tests/ext.rs
  async fn validator_id(&self) -> Option<TestValidatorId> {
    Some(self.0)
  }

=======
>>>>>>> 2947ef08 (Make sign asynchronous):substrate/tendermint/machine/tests/ext.rs
  async fn sign(&self, msg: &[u8]) -> [u8; 32] {
    let mut sig = [0; 32];
    sig[.. 2].copy_from_slice(&self.0.to_le_bytes());
    sig[2 .. (2 + 30.min(msg.len()))].copy_from_slice(&msg[.. 30.min(msg.len())]);
    sig
  }
}

struct TestSignatureScheme;
impl SignatureScheme for TestSignatureScheme {
  type ValidatorId = TestValidatorId;
  type Signature = [u8; 32];
  type AggregateSignature = Vec<[u8; 32]>;
  type Signer = TestSigner;

  #[must_use]
  fn verify(&self, validator: u16, msg: &[u8], sig: &[u8; 32]) -> bool {
    (sig[.. 2] == validator.to_le_bytes()) && (sig[2 ..] == [msg, &[0; 30]].concat()[.. 30])
  }

  fn aggregate(sigs: &[[u8; 32]]) -> Vec<[u8; 32]> {
    sigs.to_vec()
  }

  #[must_use]
  fn verify_aggregate(
    &self,
    signers: &[TestValidatorId],
    msg: &[u8],
    sigs: &Vec<[u8; 32]>,
  ) -> bool {
    assert_eq!(signers.len(), sigs.len());
    for sig in signers.iter().zip(sigs.iter()) {
      assert!(self.verify(*sig.0, msg, sig.1));
    }
    true
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

  fn proposer(&self, number: BlockNumber, round: RoundNumber) -> TestValidatorId {
    TestValidatorId::try_from((number.0 + u64::from(round.0)) % 4).unwrap()
  }
}

#[derive(Clone, PartialEq, Debug, Encode, Decode)]
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

#[allow(clippy::type_complexity)]
struct TestNetwork(
  u16,
  Arc<RwLock<Vec<(MessageSender<Self>, SyncedBlockSender<Self>, SyncedBlockResultReceiver)>>>,
);

#[async_trait]
impl Network for TestNetwork {
  type ValidatorId = TestValidatorId;
  type SignatureScheme = TestSignatureScheme;
  type Weights = TestWeights;
  type Block = TestBlock;

  const BLOCK_PROCESSING_TIME: u32 = 2;
  const LATENCY_TIME: u32 = 1;

  fn signer(&self) -> TestSigner {
    TestSigner(self.0)
  }

  fn signature_scheme(&self) -> TestSignatureScheme {
    TestSignatureScheme
  }

  fn weights(&self) -> TestWeights {
    TestWeights
  }

  async fn broadcast(&mut self, msg: SignedMessageFor<Self>) {
    for (messages, _, _) in self.1.write().await.iter_mut() {
      messages.send(msg.clone()).await.unwrap();
    }
  }

  async fn slash(&mut self, _: TestValidatorId) {
    dbg!("Slash");
    todo!()
  }

  async fn validate(&mut self, block: &TestBlock) -> Result<(), BlockError> {
    block.valid
  }

  async fn add_block(
    &mut self,
    block: TestBlock,
    commit: Commit<TestSignatureScheme>,
  ) -> Option<TestBlock> {
    dbg!("Adding ", &block);
    assert!(block.valid.is_ok());
    assert!(self.verify_commit(block.id(), &commit));
    Some(TestBlock { id: (u32::from_le_bytes(block.id) + 1).to_le_bytes(), valid: Ok(()) })
  }
}

impl TestNetwork {
  async fn new(
    validators: usize,
  ) -> Arc<RwLock<Vec<(MessageSender<Self>, SyncedBlockSender<Self>, SyncedBlockResultReceiver)>>>
  {
    let arc = Arc::new(RwLock::new(vec![]));
    {
      let mut write = arc.write().await;
      for i in 0 .. validators {
        let i = u16::try_from(i).unwrap();
<<<<<<< HEAD:coordinator/tributary/tendermint/tests/ext.rs
        let TendermintHandle { messages, synced_block, synced_block_result, machine } =
          TendermintMachine::new(
            TestNetwork(i, arc.clone()),
            BlockNumber(1),
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            TestBlock { id: 1u32.to_le_bytes(), valid: Ok(()) },
          )
          .await;
        tokio::task::spawn(machine.run());
        write.push((messages, synced_block, synced_block_result));
=======
        write.push(TendermintMachine::new(
          TestNetwork(i, arc.clone()),
          i,
          (BlockNumber(1), (SystemTime::now().duration_since(UNIX_EPOCH)).unwrap().as_secs()),
          TestBlock { id: 1u32.to_le_bytes(), valid: Ok(()) },
        ));
>>>>>>> 9b8f2f44 (More misc bug fixes):substrate/tendermint/tests/ext.rs
      }
    }
    arc
  }
}

#[tokio::test]
async fn test() {
  TestNetwork::new(4).await;
  sleep(Duration::from_secs(30)).await;
}
