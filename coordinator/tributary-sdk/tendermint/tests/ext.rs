#![allow(clippy::std_instead_of_alloc, clippy::std_instead_of_core)]

use core::{num::NonZero, future::Future, time::Duration};
use std::{
  sync::Arc,
  collections::{HashSet, HashMap},
};

use borsh::{BorshSerialize, BorshDeserialize};

use tokio::sync::RwLock;

use serai_db::MemDb;

use tendermint_machine::{
  InvalidAggregateSignature, SignatureScheme, Signer, Block, Commit, InvalidBlock, Blockchain,
  MessageFor, Network, SlashReason, Tendermint, TendermintHandle,
};

type TestValidator = u16;
// This is not a cryptographic hash and is solely for testing purposes
type TestBlockHash = [u8; 4];

struct TestSigner(u16);
#[expect(clippy::unused_async_trait_impl)]
impl Signer for TestSigner {
  type Validator = TestValidator;
  // This is not a cryptographic signature and is solely for testing purposes
  type Signature = [u8; 32];

  async fn validator(&self) -> TestValidator {
    self.0
  }

  async fn sign(
    &self,
    message: impl Send + IntoIterator<Item = impl AsRef<[u8]>>,
  ) -> Self::Signature {
    let mut sig = [0; 32];
    sig[.. 2].copy_from_slice(&self.0.to_le_bytes());

    let mut concat_message: Vec<u8> = vec![];
    for chunk in message {
      concat_message.extend(chunk.as_ref());
    }
    let message = concat_message;
    sig[2 .. (2 + 30.min(message.len()))].copy_from_slice(&message[.. 30.min(message.len())]);

    sig
  }
}

#[derive(Clone)]
struct TestSignatureScheme;
impl SignatureScheme for TestSignatureScheme {
  type Validator = TestValidator;
  type Signature = [u8; 32];
  type AggregateSignature = Vec<u8>;

  fn verify(
    &self,
    validator: &Self::Validator,
    message: impl IntoIterator<Item = impl AsRef<[u8]>>,
    signature: &Self::Signature,
  ) -> bool {
    let mut concat_message: Vec<u8> = vec![];
    for chunk in message {
      concat_message.extend(chunk.as_ref());
    }
    let message = concat_message;

    signature.as_slice() ==
      [
        validator.to_le_bytes().as_slice(),
        &message[.. 30.min(message.len())],
        &vec![0; 30_usize.saturating_sub(message.len())],
      ]
      .concat()
      .as_slice()
  }

  fn aggregate<'sig>(
    &self,
    _message: impl IntoIterator<Item = impl AsRef<[u8]>>,
    signatures: impl IntoIterator<Item = (&'sig Self::Validator, &'sig Self::Signature)>,
  ) -> Self::AggregateSignature
  where
    Self::Validator: 'sig,
    Self::Signature: 'sig,
  {
    borsh::to_vec(&signatures.into_iter().collect::<Vec<_>>()).unwrap()
  }

  fn verify_aggregate(
    &self,
    message: impl IntoIterator<Item = impl AsRef<[u8]>>,
    aggregate_signature: &Self::AggregateSignature,
  ) -> Result<impl IntoIterator<Item = Self::Validator>, InvalidAggregateSignature> {
    let mut concat_message = vec![];
    for chunk in message {
      concat_message.extend(chunk.as_ref());
    }
    let message = concat_message;

    let aggregate_signature = {
      let mut aggregate_signature_slice = aggregate_signature.as_slice();
      let Ok(aggregate_signature) = Vec::<(Self::Validator, Self::Signature)>::deserialize_reader(
        &mut aggregate_signature_slice,
      ) else {
        Err(InvalidAggregateSignature)?
      };
      // Check this aggregate didn't have any trailing bytes
      if !aggregate_signature_slice.is_empty() {
        Err(InvalidAggregateSignature)?;
      }
      aggregate_signature
    };

    let mut signers = HashSet::new();
    for (signer, signature) in &aggregate_signature {
      // Check this signer wasn't present multiple times
      if !signers.insert(signer) {
        Err(InvalidAggregateSignature)?;
      }
      // Check the signature was valid
      if !self.verify(signer, core::iter::once(message.as_slice()), signature) {
        Err(InvalidAggregateSignature)?;
      }
    }
    Ok(aggregate_signature.into_iter().map(|(signer, _)| signer))
  }
}

#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
struct TestBlock {
  id: TestBlockHash,
  valid: bool,
}

impl Block for TestBlock {
  type Hash = TestBlockHash;

  fn hash(&self) -> TestBlockHash {
    self.id
  }
}

struct TestNetwork {
  validator_set: HashMap<u16, NonZero<u16>>,
  all_validators: Arc<RwLock<Vec<TendermintHandle<Self>>>>,
}

impl Blockchain for TestNetwork {
  type Validator = u16;
  type ValidatorSet = HashMap<u16, NonZero<u16>>;
  type SignatureScheme = TestSignatureScheme;
  type Block = TestBlock;

  type BlockProposal = core::future::Ready<Self::Block>;

  fn genesis(&self) -> impl Send + AsRef<[u8]> {
    []
  }

  fn validator_set(&self) -> &Self::ValidatorSet {
    &self.validator_set
  }

  fn signature_scheme(&self) -> &Self::SignatureScheme {
    &TestSignatureScheme
  }

  fn validate(
    &self,
    _proposer: Self::Validator,
    block: &Self::Block,
  ) -> impl Send + Future<Output = Result<(), InvalidBlock>> {
    core::future::ready(if block.valid { Ok(()) } else { Err(InvalidBlock) })
  }

  fn add_block(
    &mut self,
    block: Self::Block,
    commit: Commit<Self::SignatureScheme>,
  ) -> impl Send + Future<Output = Self::BlockProposal> {
    assert!(block.valid);
    assert!(commit.verify(
      self.validator_set(),
      self.signature_scheme(),
      self.genesis(),
      block.hash()
    ));
    let added = u32::from_le_bytes(block.id);
    println!("Added block #{added}");
    core::future::ready(core::future::ready(TestBlock {
      id: (added + 1).to_le_bytes(),
      valid: true,
    }))
  }

  fn missed_proposal(&self, _proposer: Self::Validator) {}

  fn slash(
    &self,
    _validator: Self::Validator,
    slash_reason: SlashReason<
      <Self::SignatureScheme as SignatureScheme>::Signature,
      <Self::SignatureScheme as SignatureScheme>::AggregateSignature,
      Self::Block,
    >,
  ) {
    panic!("test environment incurred a slash: {slash_reason:?}")
  }
}

impl
  Network<
    u16,
    <TestSignatureScheme as SignatureScheme>::Signature,
    <TestSignatureScheme as SignatureScheme>::AggregateSignature,
    TestBlock,
  > for TestNetwork
{
  const LATENCY_TIME: Duration = Duration::from_secs(1);
  const BLOCK_DOWNLOADING_TIME: Duration = Duration::from_secs(1);
  const BLOCK_PROCESSING_TIME: Duration = Duration::from_secs(1);

  fn sleep(duration: Duration) -> impl Send + Future<Output = ()> {
    tokio::time::sleep(duration)
  }

  async fn broadcast(&mut self, message: MessageFor<TestNetwork>) {
    for handle in self.all_validators.write().await.iter_mut() {
      let _ = handle.message(message.clone()).await;
    }
  }
}

impl TestNetwork {
  async fn spawn(validators: usize) {
    let validator_set = (0 .. u16::try_from(validators).unwrap())
      .map(|validator| (validator, NonZero::new(1).unwrap()))
      .collect::<HashMap<_, _>>();

    let arc = Arc::new(RwLock::new(vec![]));

    for i in 0 .. validators {
      let i = u16::try_from(i).unwrap();
      let (handle, process) = Tendermint::process(
        TestNetwork { validator_set: validator_set.clone(), all_validators: arc.clone() },
        TestSigner(i),
        MemDb::new(),
        TestNetwork { validator_set: validator_set.clone(), all_validators: arc.clone() },
        TestBlock { id: 1u32.to_le_bytes(), valid: true },
      )
      .await;
      tokio::spawn(process);
      arc.write().await.push(handle);
    }
  }
}

#[tokio::test]
async fn test() {
  TestNetwork::spawn(4).await;
  tokio::time::sleep(Duration::from_secs(20)).await;
}
