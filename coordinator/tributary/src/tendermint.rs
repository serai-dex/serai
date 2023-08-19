use core::ops::Deref;
use std::{sync::Arc, collections::HashMap};

use async_trait::async_trait;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use rand::{SeedableRng, seq::SliceRandom};
use rand_chacha::ChaCha12Rng;

use transcript::{Transcript, RecommendedTranscript};

use ciphersuite::{
  group::{
    GroupEncoding,
    ff::{Field, PrimeField},
  },
  Ciphersuite, Ristretto,
};
use schnorr::{
  SchnorrSignature,
  aggregate::{SchnorrAggregator, SchnorrAggregate},
};

use serai_db::Db;

use scale::{Encode, Decode};
use tendermint::{
  SignedMessageFor,
  ext::{
    BlockNumber, RoundNumber, Signer as SignerTrait, SignatureScheme, Weights, Block as BlockTrait,
    BlockError as TendermintBlockError, Commit, Network,
  },
};

use tokio::{
  sync::RwLock,
  time::{Duration, sleep},
};

use crate::{
  TENDERMINT_MESSAGE, BLOCK_MESSAGE, ReadWrite, Transaction, BlockHeader, Block, BlockError,
  Blockchain, P2p,
};

const DST: &[u8] = b"Tributary Tendermint Commit Aggregator";

fn challenge(
  genesis: [u8; 32],
  key: [u8; 32],
  nonce: &[u8],
  msg: &[u8],
) -> <Ristretto as Ciphersuite>::F {
  let mut transcript = RecommendedTranscript::new(b"Tributary Chain Tendermint Message");
  transcript.append_message(b"genesis", genesis);
  transcript.append_message(b"key", key);
  transcript.append_message(b"nonce", nonce);
  transcript.append_message(b"message", msg);

  <Ristretto as Ciphersuite>::F::from_bytes_mod_order_wide(&transcript.challenge(b"schnorr").into())
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Signer {
  genesis: [u8; 32],
  key: Zeroizing<<Ristretto as Ciphersuite>::F>,
}

impl Signer {
  pub(crate) fn new(genesis: [u8; 32], key: Zeroizing<<Ristretto as Ciphersuite>::F>) -> Signer {
    Signer { genesis, key }
  }
}

#[async_trait]
impl SignerTrait for Signer {
  type ValidatorId = [u8; 32];
  type Signature = [u8; 64];

  /// Returns the validator's current ID. Returns None if they aren't a current validator.
  async fn validator_id(&self) -> Option<Self::ValidatorId> {
    Some((Ristretto::generator() * self.key.deref()).to_bytes())
  }

  /// Sign a signature with the current validator's private key.
  async fn sign(&self, msg: &[u8]) -> Self::Signature {
    let mut nonce = Zeroizing::new(RecommendedTranscript::new(b"Tributary Chain Tendermint Nonce"));
    nonce.append_message(b"genesis", self.genesis);
    nonce.append_message(b"key", Zeroizing::new(self.key.deref().to_repr()).as_ref());
    nonce.append_message(b"message", msg);
    let mut nonce = nonce.challenge(b"nonce");

    let mut nonce_arr = [0; 64];
    nonce_arr.copy_from_slice(nonce.as_ref());

    let nonce_ref: &mut [u8] = nonce.as_mut();
    nonce_ref.zeroize();
    let nonce_ref: &[u8] = nonce.as_ref();
    assert_eq!(nonce_ref, [0; 64].as_ref());

    let nonce =
      Zeroizing::new(<Ristretto as Ciphersuite>::F::from_bytes_mod_order_wide(&nonce_arr));
    nonce_arr.zeroize();

    assert!(!bool::from(nonce.ct_eq(&<Ristretto as Ciphersuite>::F::ZERO)));

    let challenge = challenge(
      self.genesis,
      (Ristretto::generator() * self.key.deref()).to_bytes(),
      (Ristretto::generator() * nonce.deref()).to_bytes().as_ref(),
      msg,
    );

    let sig = SchnorrSignature::<Ristretto>::sign(&self.key, nonce, challenge).serialize();

    let mut res = [0; 64];
    res.copy_from_slice(&sig);
    res
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Validators {
  genesis: [u8; 32],
  total_weight: u64,
  weights: HashMap<[u8; 32], u64>,
  robin: Vec<[u8; 32]>,
}

impl Validators {
  pub(crate) fn new(
    genesis: [u8; 32],
    validators: Vec<(<Ristretto as Ciphersuite>::G, u64)>,
  ) -> Option<Validators> {
    let mut total_weight = 0;
    let mut weights = HashMap::new();

    let mut transcript = RecommendedTranscript::new(b"Round Robin Randomization");
    let mut robin = vec![];
    for (validator, weight) in validators {
      let validator = validator.to_bytes();
      if weight == 0 {
        return None;
      }
      total_weight += weight;
      weights.insert(validator, weight);

      transcript.append_message(b"validator", validator);
      transcript.append_message(b"weight", weight.to_le_bytes());
      robin.extend(vec![validator; usize::try_from(weight).unwrap()]);
    }
    robin.shuffle(&mut ChaCha12Rng::from_seed(transcript.rng_seed(b"robin")));

    Some(Validators { genesis, total_weight, weights, robin })
  }
}

impl SignatureScheme for Validators {
  type ValidatorId = [u8; 32];
  type Signature = [u8; 64];
  type AggregateSignature = Vec<u8>;
  type Signer = Arc<Signer>;

  #[must_use]
  fn verify(&self, validator: Self::ValidatorId, msg: &[u8], sig: &Self::Signature) -> bool {
    if !self.weights.contains_key(&validator) {
      return false;
    }
    let Ok(validator_point) = Ristretto::read_G::<&[u8]>(&mut validator.as_ref()) else {
      return false;
    };
    let Ok(actual_sig) = SchnorrSignature::<Ristretto>::read::<&[u8]>(&mut sig.as_ref()) else {
      return false;
    };
    actual_sig.verify(validator_point, challenge(self.genesis, validator, &sig[.. 32], msg))
  }

  fn aggregate(
    &self,
    validators: &[Self::ValidatorId],
    msg: &[u8],
    sigs: &[Self::Signature],
  ) -> Self::AggregateSignature {
    assert_eq!(validators.len(), sigs.len());

    let mut aggregator = SchnorrAggregator::<Ristretto>::new(DST);
    for (key, sig) in validators.iter().zip(sigs) {
      let actual_sig = SchnorrSignature::<Ristretto>::read::<&[u8]>(&mut sig.as_ref()).unwrap();
      let challenge = challenge(self.genesis, *key, actual_sig.R.to_bytes().as_ref(), msg);
      aggregator.aggregate(challenge, actual_sig);
    }

    let aggregate = aggregator.complete().unwrap();
    aggregate.serialize()
  }

  #[must_use]
  fn verify_aggregate(
    &self,
    signers: &[Self::ValidatorId],
    msg: &[u8],
    sig: &Self::AggregateSignature,
  ) -> bool {
    let Ok(aggregate) = SchnorrAggregate::<Ristretto>::read::<&[u8]>(&mut sig.as_slice()) else {
      return false;
    };

    if signers.len() != aggregate.Rs().len() {
      return false;
    }

    let mut challenges = vec![];
    for (key, nonce) in signers.iter().zip(aggregate.Rs()) {
      challenges.push(challenge(self.genesis, *key, nonce.to_bytes().as_ref(), msg));
    }

    aggregate.verify(
      DST,
      signers
        .iter()
        .zip(challenges)
        .map(|(s, c)| (<Ristretto as Ciphersuite>::read_G(&mut s.as_slice()).unwrap(), c))
        .collect::<Vec<_>>()
        .as_slice(),
    )
  }
}

impl Weights for Validators {
  type ValidatorId = [u8; 32];

  fn total_weight(&self) -> u64 {
    self.total_weight
  }
  fn weight(&self, validator: Self::ValidatorId) -> u64 {
    self.weights[&validator]
  }
  fn proposer(&self, block: BlockNumber, round: RoundNumber) -> Self::ValidatorId {
    let block = usize::try_from(block.0).unwrap();
    let round = usize::try_from(round.0).unwrap();
    // If multiple rounds are used, a naive block + round would cause the same index to be chosen
    // in quick succesion.
    // Accordingly, if we use additional rounds, jump halfway around.
    // While this is still game-able, it's not explicitly reusing indexes immediately after each
    // other.
    self.robin
      [(block + (if round == 0 { 0 } else { round + (self.robin.len() / 2) })) % self.robin.len()]
  }
}

#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode)]
pub(crate) struct TendermintBlock(pub Vec<u8>);
impl BlockTrait for TendermintBlock {
  type Id = [u8; 32];
  fn id(&self) -> Self::Id {
    BlockHeader::read::<&[u8]>(&mut self.0.as_ref()).unwrap().hash()
  }
}

#[derive(Clone, Debug)]
pub(crate) struct TendermintNetwork<D: Db, T: Transaction, P: P2p> {
  pub(crate) genesis: [u8; 32],

  pub(crate) signer: Arc<Signer>,
  pub(crate) validators: Arc<Validators>,
  pub(crate) blockchain: Arc<RwLock<Blockchain<D, T>>>,

  pub(crate) p2p: P,
}

#[async_trait]
impl<D: Db, T: Transaction, P: P2p> Network for TendermintNetwork<D, T, P> {
  type ValidatorId = [u8; 32];
  type SignatureScheme = Arc<Validators>;
  type Weights = Arc<Validators>;
  type Block = TendermintBlock;

  // These are in seconds and create a six-second block time.
  // The block time is the latency on message delivery (where a message is some piece of data
  // embedded in a transaction), hence why it should be kept low.
  const BLOCK_PROCESSING_TIME: u32 = 3;
  const LATENCY_TIME: u32 = 1;

  fn signer(&self) -> Arc<Signer> {
    self.signer.clone()
  }
  fn signature_scheme(&self) -> Arc<Validators> {
    self.validators.clone()
  }
  fn weights(&self) -> Arc<Validators> {
    self.validators.clone()
  }

  async fn broadcast(&mut self, msg: SignedMessageFor<Self>) {
    let mut to_broadcast = vec![TENDERMINT_MESSAGE];
    to_broadcast.extend(msg.encode());
    self.p2p.broadcast(self.genesis, to_broadcast).await
  }
  async fn slash(&mut self, validator: Self::ValidatorId) {
    // TODO: Handle this slash
    log::error!(
      "validator {} triggered a slash event on tributary {}",
      hex::encode(validator),
      hex::encode(self.genesis)
    );
  }

  async fn validate(&mut self, block: &Self::Block) -> Result<(), TendermintBlockError> {
    let block =
      Block::read::<&[u8]>(&mut block.0.as_ref()).map_err(|_| TendermintBlockError::Fatal)?;
    self.blockchain.read().await.verify_block(&block).map_err(|e| match e {
      BlockError::NonLocalProvided(_) => TendermintBlockError::Temporal,
      _ => TendermintBlockError::Fatal,
    })
  }

  async fn add_block(
    &mut self,
    serialized_block: Self::Block,
    commit: Commit<Self::SignatureScheme>,
  ) -> Option<Self::Block> {
    let invalid_block = || {
      // There's a fatal flaw in the code, it's behind a hard fork, or the validators turned
      // malicious
      // All justify a halt to then achieve social consensus from
      // TODO: Under multiple validator sets, a small validator set turning malicious knocks
      // off the entire network. That's an unacceptable DoS.
      panic!("validators added invalid block to tributary {}", hex::encode(self.genesis));
    };

    // Tendermint should only produce valid commits
    assert!(self.verify_commit(serialized_block.id(), &commit));

    let Ok(block) = Block::read::<&[u8]>(&mut serialized_block.0.as_ref()) else {
      return invalid_block();
    };

    let encoded_commit = commit.encode();
    loop {
      let block_res = self.blockchain.write().await.add_block(&block, encoded_commit.clone());
      match block_res {
        Ok(()) => {
          // If we successfully added this block, broadcast it
          // TODO: Move this under the coordinator once we set up on new block notifications?
          let mut msg = serialized_block.0;
          msg.insert(0, BLOCK_MESSAGE);
          msg.extend(encoded_commit);
          self.p2p.broadcast(self.genesis, msg).await;
          break;
        }
        Err(BlockError::NonLocalProvided(hash)) => {
          log::error!(
            "missing provided transaction {} which other validators on tributary {} had",
            hex::encode(hash),
            hex::encode(self.genesis)
          );
          sleep(Duration::from_secs(Self::block_time().into())).await;
        }
        _ => return invalid_block(),
      }
    }

    Some(TendermintBlock(self.blockchain.write().await.build_block().serialize()))
  }
}
