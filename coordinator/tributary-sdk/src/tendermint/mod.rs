use core::{ops::Deref as _, future::Future, time::Duration, num::NonZero};
use std::{
  sync::Arc,
  io::Read as _,
  collections::{HashSet, HashMap},
  time::Instant,
};

use subtle::ConstantTimeEq as _;
use zeroize::{Zeroize as _, Zeroizing};

use transcript::{Transcript as _, RecommendedTranscript};

use ciphersuite::{
  group::{ff::PrimeField as _, GroupEncoding as _},
  *,
};
use dalek_ff_group::Ristretto;
use schnorr::{
  SchnorrSignature,
  aggregate::{SchnorrAggregator, SchnorrAggregate},
};

use serai_db::Db;

use borsh::{BorshSerialize, BorshDeserialize};
use tendermint::{
  InvalidAggregateSignature, SignatureScheme, Signer as SignerTrait, Block as BlockTrait,
  InvalidBlock, CommitFor, Blockchain as BlockchainTrait, MessageFor, SlashReasonFor, Network,
};

use tokio::sync::RwLock;

use crate::{
  TENDERMINT_MESSAGE, TRANSACTION_MESSAGE, ReadWrite as _,
  transaction::{TransactionError, Transaction as TransactionTrait},
  Transaction, BlockHeader, Block, BlockError, Blockchain, P2p,
};

pub mod tx;
use tx::TendermintTx;

const DST: &[u8] = b"Tributary Tendermint Commit Aggregator";

fn challenge(
  genesis: [u8; 32],
  key: [u8; 32],
  nonce: &[u8],
  msg: &[u8],
) -> <Ristretto as WrappedGroup>::F {
  let mut transcript = RecommendedTranscript::new(b"Tributary Chain Tendermint Message");
  transcript.append_message(b"genesis", genesis);
  transcript.append_message(b"key", key);
  transcript.append_message(b"nonce", nonce);
  transcript.append_message(b"message", msg);

  <Ristretto as WrappedGroup>::F::from_bytes_mod_order_wide(
    &transcript.challenge(b"schnorr").into(),
  )
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Signer {
  genesis: [u8; 32],
  key: Zeroizing<<Ristretto as WrappedGroup>::F>,
}

impl Signer {
  pub(crate) fn new(genesis: [u8; 32], key: Zeroizing<<Ristretto as WrappedGroup>::F>) -> Signer {
    Signer { genesis, key }
  }
}

impl SignerTrait for Signer {
  type Validator = [u8; 32];
  type Signature = [u8; 64];

  fn validator(&self) -> Self::Validator {
    (Ristretto::generator() * self.key.deref()).to_bytes()
  }

  type SignFuture = core::future::Ready<Self::Signature>;
  fn sign(&self, message: impl IntoIterator<Item = impl AsRef<[u8]>>) -> Self::SignFuture {
    let mut concat_message: Vec<u8> = vec![];
    for chunk in message {
      concat_message.extend(chunk.as_ref());
    }
    let message = concat_message;

    let mut nonce = {
      let mut nonce_transcript = RecommendedTranscript::new(b"Tributary Chain Tendermint Nonce");
      nonce_transcript.append_message(b"genesis", self.genesis);
      nonce_transcript.append_message(b"key", Zeroizing::new(self.key.deref().to_repr()).as_ref());
      nonce_transcript.append_message(b"message", &message);
      let nonce = nonce_transcript.challenge(b"nonce");

      // Ensure this will be zeroized (via the type contract) and ensure it happens now
      {
        fn drop_zeroize_on_drop(value: impl zeroize::ZeroizeOnDrop) {
          drop(value);
        }
        drop_zeroize_on_drop(nonce_transcript);
      }

      nonce
    };

    let mut nonce_arr = [0; 64];
    nonce_arr.copy_from_slice(nonce.as_ref());

    let nonce_ref: &mut [u8] = nonce.as_mut();
    nonce_ref.zeroize();
    let nonce_ref: &[u8] = nonce.as_ref();
    assert_eq!(nonce_ref, [0; 64].as_ref());

    let nonce =
      Zeroizing::new(<Ristretto as WrappedGroup>::F::from_bytes_mod_order_wide(&nonce_arr));
    nonce_arr.zeroize();

    assert!(!bool::from(nonce.ct_eq(&<Ristretto as WrappedGroup>::F::ZERO)));

    let challenge = challenge(
      self.genesis,
      (Ristretto::generator() * self.key.deref()).to_bytes(),
      (Ristretto::generator() * nonce.deref()).to_bytes().as_ref(),
      &message,
    );

    let sig = SchnorrSignature::<Ristretto>::sign(&self.key, nonce, challenge).serialize();

    let mut res = [0; 64];
    res.copy_from_slice(&sig);
    core::future::ready(res)
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Validators {
  genesis: [u8; 32],
  weights: HashMap<[u8; 32], NonZero<u16>>,
}

impl Validators {
  pub(crate) fn new(
    genesis: [u8; 32],
    validators: Vec<(<Ristretto as WrappedGroup>::G, NonZero<u16>)>,
  ) -> Option<Validators> {
    let mut total_weight = 0;
    let mut weights = HashMap::new();

    for (validator, weight) in validators {
      let validator = validator.to_bytes();
      total_weight += u64::from(u16::from(weight));
      if total_weight > u64::from(u16::MAX) {
        None?;
      }
      weights.insert(validator, weight);
    }

    (total_weight != 0).then_some(Validators { genesis, weights })
  }

  pub(crate) fn weights(&self) -> &HashMap<[u8; 32], NonZero<u16>> {
    &self.weights
  }
}

impl SignatureScheme for Validators {
  type Validator = [u8; 32];
  type Signature = [u8; 64];
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

    if !self.weights.contains_key(validator) {
      return false;
    }
    let Ok(validator_point) = Ristretto::read_G(validator.as_slice()) else {
      return false;
    };
    let Ok(actual_sig) = SchnorrSignature::<Ristretto>::read(signature.as_slice()) else {
      return false;
    };
    actual_sig
      .verify(validator_point, challenge(self.genesis, *validator, &signature[.. 32], &message))
  }

  fn aggregate<'sig>(
    &self,
    message: impl IntoIterator<Item = impl AsRef<[u8]>>,
    signatures: impl IntoIterator<Item = (&'sig Self::Validator, &'sig Self::Signature)>,
  ) -> Self::AggregateSignature
  where
    Self::Validator: 'sig,
    Self::Signature: 'sig,
  {
    let mut concat_message: Vec<u8> = vec![];
    for chunk in message {
      concat_message.extend(chunk.as_ref());
    }
    let message = concat_message;

    let mut signers = vec![];
    let mut aggregator = SchnorrAggregator::<Ristretto>::new(DST);
    for (key, sig) in signatures {
      signers.push(key);
      let actual_sig = SchnorrSignature::<Ristretto>::read(sig.as_slice()).unwrap();
      let challenge = challenge(self.genesis, *key, actual_sig.R.to_bytes().as_ref(), &message);
      aggregator.aggregate(challenge, actual_sig);
    }

    let aggregate = aggregator.complete().unwrap();

    let mut result = aggregate.serialize();
    for signer in signers {
      result.extend(signer);
    }
    result
  }

  fn verify_aggregate(
    &self,
    message: impl IntoIterator<Item = impl AsRef<[u8]>>,
    aggregate_signature: &Self::AggregateSignature,
  ) -> Result<impl IntoIterator<Item = Self::Validator>, InvalidAggregateSignature> {
    let mut concat_message: Vec<u8> = vec![];
    for chunk in message {
      concat_message.extend(chunk.as_ref());
    }
    let message = concat_message;

    let (aggregate_signature, signers) = {
      // TODO: Bound the length of this
      let mut aggregate_signature_slice = aggregate_signature.as_slice();
      let Ok(aggregate_signature) =
        SchnorrAggregate::<Ristretto>::read(&mut aggregate_signature_slice)
      else {
        Err(InvalidAggregateSignature)?
      };

      let signers = {
        let mut signers_set = HashSet::new();
        let mut signers = vec![];
        for _ in 0 .. aggregate_signature.Rs().len() {
          let mut signer = [0xff; 32];
          let Ok(()) = aggregate_signature_slice.read_exact(&mut signer) else {
            Err(InvalidAggregateSignature)?
          };
          if !signers_set.insert(signer) {
            Err(InvalidAggregateSignature)?;
          }
          signers.push(signer);
        }
        signers
      };

      if !aggregate_signature_slice.is_empty() {
        Err(InvalidAggregateSignature)?;
      }

      (aggregate_signature, signers)
    };

    let mut challenges = vec![];
    for (key, nonce) in signers.iter().zip(aggregate_signature.Rs()) {
      challenges.push(challenge(self.genesis, *key, nonce.to_bytes().as_ref(), &message));
    }

    if !aggregate_signature.verify(
      DST,
      signers
        .iter()
        .zip(challenges)
        .map(|(s, c)| (<Ristretto as GroupIo>::read_G(s.as_slice()).unwrap(), c))
        .collect::<Vec<_>>()
        .as_slice(),
    ) {
      Err(InvalidAggregateSignature)?;
    }

    Ok(signers.into_iter())
  }
}

#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct TendermintBlock(pub Vec<u8>);
impl BlockTrait for TendermintBlock {
  type Hash = [u8; 32];
  fn hash(&self) -> Self::Hash {
    BlockHeader::read(self.0.as_slice()).unwrap().hash()
  }
}

#[derive(Clone, Debug)]
pub struct TendermintNetwork<
  D: 'static + Send + Sync + for<'db> Db<Transaction<'db>: Send>,
  T: TransactionTrait,
  P: P2p,
> {
  pub(crate) genesis: [u8; 32],
  pub(crate) last_addition: Instant,

  pub(crate) validators: Validators,
  pub(crate) blockchain: Arc<RwLock<Blockchain<D, T>>>,

  pub(crate) p2p: P,
}

impl<D: 'static + Send + Sync + for<'db> Db<Transaction<'db>: Send>, T: TransactionTrait, P: P2p>
  BlockchainTrait for TendermintNetwork<D, T, P>
{
  type Validator = [u8; 32];
  type ValidatorSet = HashMap<Self::Validator, NonZero<u16>>;
  type SignatureScheme = Validators;
  type Genesis = [u8; 32];
  type Block = TendermintBlock;

  type BlockProposal = core::future::Ready<Self::Block>;

  fn genesis(&self) -> &Self::Genesis {
    &self.genesis
  }

  fn validator_set(&self) -> &Self::ValidatorSet {
    &self.validators.weights
  }

  fn signature_scheme(&self) -> &Self::SignatureScheme {
    &self.validators
  }

  fn validate(
    &self,
    _proposer: Self::Validator,
    block: &Self::Block,
  ) -> impl Send + Future<Output = Result<(), InvalidBlock>> {
    async move {
      if self.last_addition.checked_add(TARGET_BLOCK_TIME) >
        Some(Instant::now().checked_add(Duration::from_secs(1)).unwrap_or(self.last_addition))
      {
        Err(InvalidBlock)?;
      }

      let block = Block::read(block.0.as_slice()).map_err(|_| InvalidBlock)?;
      self
        .blockchain
        .read()
        .await
        .verify_block::<Self>(&block, self.signature_scheme(), false)
        .map_err(|e| match e {
          BlockError::NonLocalProvided(_) => InvalidBlock,
          BlockError::TooLargeBlock |
          BlockError::InvalidParent |
          BlockError::InvalidTransactions |
          BlockError::UnsignedAlreadyIncluded |
          BlockError::ProvidedAlreadyIncluded |
          BlockError::WrongTransactionOrder |
          BlockError::DistinctProvided |
          BlockError::TransactionError(
            TransactionError::TooLargeTransaction |
            TransactionError::InvalidSigner |
            TransactionError::InvalidNonce |
            TransactionError::InvalidSignature |
            TransactionError::InvalidContent,
          ) => {
            log::warn!("Tributary Tendermint validate returning InvalidBlock due to {e:?}");
            InvalidBlock
          }
          BlockError::TransactionError(TransactionError::ProvidedAddedToMempool) => {
            unreachable!("system transaction routed to mempool")
          }
          BlockError::TransactionError(TransactionError::TooManyInMempool) => {
            unreachable!("transaction in block was checked against mempool limits")
          }
        })
    }
  }

  fn add_block(
    &mut self,
    serialized_block: Self::Block,
    commit: CommitFor<Self>,
  ) -> impl Send + Future<Output = Self::BlockProposal> {
    #[expect(clippy::async_yields_async)]
    async move {
      // TODO: We need to assert a faulty validator set isn't flooding blocks in real time
      self.last_addition = Instant::now();

      let invalid_block = || {
        // There's a fatal flaw in the code, it's behind a hard fork, or the validators turned
        // malicious
        // All justify a halt to then achieve social consensus from
        // TODO: Under multiple validator sets, a small validator set turning malicious knocks
        // off the entire network. That's an unacceptable DoS.
        panic!("validators added invalid block to tributary {}", hex::encode(self.genesis));
      };

      // Tendermint should only give us valid commits
      assert!(commit.verify(
        self.validator_set(),
        self.signature_scheme(),
        self.genesis,
        serialized_block.hash()
      ));

      let Ok(block) = Block::read(serialized_block.0.as_slice()) else {
        return invalid_block();
      };

      let encoded_commit = borsh::to_vec(&commit).unwrap();
      loop {
        let block_res = self.blockchain.write().await.add_block::<Self>(
          &block,
          encoded_commit.clone(),
          self.signature_scheme(),
        );
        match block_res {
          Ok(()) => {
            // If we successfully added this block, break
            break;
          }
          Err(BlockError::NonLocalProvided(hash)) => {
            log::error!(
              "missing provided transaction {} which other validators on tributary {} had",
              hex::encode(hash),
              hex::encode(self.genesis)
            );
            tokio::time::sleep(core::time::Duration::from_secs(5)).await;
          }
          _ => return invalid_block(),
        }
      }

      core::future::ready(TendermintBlock(
        self.blockchain.write().await.build_block::<Self>(self.signature_scheme()).serialize(),
      ))
    }
  }

  fn missed_proposal(&self, _proposer: Self::Validator) {
    // TODO
  }

  fn slash(&self, validator: Self::Validator, slash_reason: SlashReasonFor<Self>) {
    // TODO
    tokio::runtime::Handle::current().block_on(async move {
      log::error!(
        "validator {} triggered a slash event on tributary {}",
        hex::encode(validator),
        hex::encode(self.genesis),
      );

      let tx = Transaction::Tendermint(TendermintTx { validator, slash_reason });

      // add tx to blockchain and broadcast to peers
      let mut to_broadcast = vec![TRANSACTION_MESSAGE];
      tx.write(&mut to_broadcast).unwrap();
      let signature_scheme = self.signature_scheme();
      if self.blockchain.write().await.add_transaction::<Self>(true, tx, signature_scheme) ==
        Ok(true)
      {
        self.p2p.broadcast(self.genesis, to_broadcast).await;
      }
    });
  }
}

// These effect a six-second target block time.
pub const BLOCK_DOWNLOADING_TIME: Duration = Duration::from_millis(499);
pub const BLOCK_PROCESSING_TIME: Duration = Duration::from_millis(500);
pub const LATENCY_TIME: Duration = Duration::from_millis(1667);
pub const TARGET_BLOCK_TIME: Duration = BLOCK_DOWNLOADING_TIME
  .checked_add(BLOCK_PROCESSING_TIME)
  .unwrap()
  .checked_add(LATENCY_TIME.checked_mul(3).unwrap())
  .unwrap();

impl<D: 'static + Send + Sync + for<'db> Db<Transaction<'db>: Send>, T: TransactionTrait, P: P2p>
  Network<
    [u8; 32],
    <Validators as SignatureScheme>::Signature,
    <Validators as SignatureScheme>::AggregateSignature,
    TendermintBlock,
  > for TendermintNetwork<D, T, P>
{
  const BLOCK_DOWNLOADING_TIME: Duration = BLOCK_DOWNLOADING_TIME;
  const BLOCK_PROCESSING_TIME: Duration = BLOCK_PROCESSING_TIME;
  const LATENCY_TIME: Duration = LATENCY_TIME;

  type Sleep = tokio::time::Sleep;
  fn sleep(duration: Duration) -> Self::Sleep {
    tokio::time::sleep(duration)
  }

  fn broadcast(&mut self, msg: MessageFor<Self>) -> impl Send + Future<Output = ()> {
    async move {
      let mut to_broadcast = vec![TENDERMINT_MESSAGE];
      msg.serialize(&mut to_broadcast).unwrap();
      self.p2p.broadcast(self.genesis, to_broadcast).await;
    }
  }
}
