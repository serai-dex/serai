use core::{marker::PhantomData, ops::Deref};
use std::sync::{Arc, RwLock};

use sp_application_crypto::{
  RuntimePublic as PublicTrait, Pair as PairTrait,
  sr25519::{Public, Pair, Signature},
};

use sp_runtime::traits::Block;
use sp_staking::SessionIndex;
use sp_api::ProvideRuntimeApi;

use frame_support::traits::ValidatorSet;

use tendermint_machine::ext::{BlockNumber, Round, Weights, SignatureScheme};

struct TendermintValidatorsStruct {
  session: SessionIndex,

  total_weight: u64,
  weights: Vec<u64>,

  keys: Pair,          // TODO: sp_keystore
  lookup: Vec<Public>, // TODO: sessions
}

impl TendermintValidatorsStruct {
  fn from_module<B: Block, C: Send + Sync + ProvideRuntimeApi<B>>(
    client: C,
  ) -> TendermintValidatorsStruct
  where
    C::Api: ValidatorSet<Public>,
  {
    let validators = client.runtime_api().validators();
    assert_eq!(validators.len(), 1);
    let keys = Pair::from_string("//Alice", None).unwrap();
    TendermintValidatorsStruct {
      session: client.runtime_api().session_index(),

      // TODO
      total_weight: validators.len().try_into().unwrap(),
      weights: vec![1; validators.len()],

      lookup: vec![keys.public()],
      keys,
    }
  }
}

// Wrap every access of the validators struct in something which forces calling refresh
struct Refresh<B: Block, C: Send + Sync + ProvideRuntimeApi<B>> {
  _block: PhantomData<B>,
  client: C,
  _refresh: Arc<RwLock<TendermintValidatorsStruct>>,
}
impl<B: Block, C: Send + Sync + ProvideRuntimeApi<B>> Refresh<B, C>
where
  C::Api: ValidatorSet<Public>,
{
  // If the session has changed, re-create the struct with the data on it
  fn refresh(&self) {
    let session = self._refresh.read().unwrap().session;
    if session != self.client.runtime_api().session_index() {
      *self._refresh.write().unwrap() = TendermintValidatorsStruct::from_module(self.client);
    }
  }
}

impl<B: Block, C: Send + Sync + ProvideRuntimeApi<B>> Deref for Refresh<B, C>
where
  C::Api: ValidatorSet<Public>,
{
  type Target = RwLock<TendermintValidatorsStruct>;
  fn deref(&self) -> &RwLock<TendermintValidatorsStruct> {
    self.refresh();
    &self._refresh
  }
}

pub(crate) struct TendermintValidators<B: Block, C: Send + Sync + ProvideRuntimeApi<B>>(
  Refresh<B, C>,
);
impl<B: Block, C: Send + Sync + ProvideRuntimeApi<B>> TendermintValidators<B, C>
where
  C::Api: ValidatorSet<Public>,
{
  pub(crate) fn new(client: C) -> TendermintValidators<B, C> {
    TendermintValidators(Refresh {
      _block: PhantomData,
      client,
      _refresh: Arc::new(RwLock::new(TendermintValidatorsStruct::from_module())),
    })
  }
}

impl<B: Block, C: Send + Sync + ProvideRuntimeApi<B>> SignatureScheme for TendermintValidators<B, C>
where
  C::Api: ValidatorSet<Public>,
{
  type ValidatorId = u16;
  type Signature = Signature;
  type AggregateSignature = Vec<Signature>;

  fn sign(&self, msg: &[u8]) -> Signature {
    self.0.read().unwrap().keys.sign(msg)
  }

  fn verify(&self, validator: u16, msg: &[u8], sig: &Signature) -> bool {
    self.0.read().unwrap().lookup[usize::try_from(validator).unwrap()].verify(&msg, sig)
  }

  fn aggregate(sigs: &[Signature]) -> Vec<Signature> {
    sigs.to_vec()
  }

  fn verify_aggregate(&self, validators: &[u16], msg: &[u8], sigs: &Vec<Signature>) -> bool {
    if validators.len() != sigs.len() {
      return false;
    }
    for (v, sig) in validators.iter().zip(sigs.iter()) {
      if !self.verify(*v, msg, sig) {
        return false;
      }
    }
    true
  }
}

impl<B: Block, C: Send + Sync + ProvideRuntimeApi<B>> Weights for TendermintValidators<B, C>
where
  C::Api: ValidatorSet<Public>,
{
  type ValidatorId = u16;

  fn total_weight(&self) -> u64 {
    self.0.read().unwrap().total_weight
  }

  fn weight(&self, id: u16) -> u64 {
    self.0.read().unwrap().weights[usize::try_from(id).unwrap()]
  }

  // TODO
  fn proposer(&self, number: BlockNumber, round: Round) -> u16 {
    u16::try_from(number.0 + u64::from(round.0)).unwrap()
  }
}
