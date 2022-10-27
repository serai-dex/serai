use core::{marker::PhantomData, ops::Deref};
use std::sync::{Arc, RwLock};

use sp_application_crypto::{
  RuntimePublic as PublicTrait, Pair as PairTrait,
  sr25519::{Public, Pair, Signature},
};

use sp_runtime::traits::Block;
use sp_staking::SessionIndex;
use sp_api::{BlockId, TransactionFor};

use sc_client_api::Backend;

use tendermint_machine::ext::{BlockNumber, Round, Weights, SignatureScheme};

use sp_tendermint::TendermintApi;

use crate::tendermint::TendermintClient;

struct TendermintValidatorsStruct {
  session: SessionIndex,

  total_weight: u64,
  weights: Vec<u64>,

  keys: Pair,          // TODO: sp_keystore
  lookup: Vec<Public>, // TODO: sessions
}

impl TendermintValidatorsStruct {
  fn from_module<B: Block, Be: Backend<B> + 'static, C: TendermintClient<B, Be>>(
    client: &Arc<C>,
  ) -> TendermintValidatorsStruct
  where
    TransactionFor<C, B>: Send + Sync + 'static,
    C::Api: TendermintApi<B>,
  {
    let last = client.info().best_hash;
    let api = client.runtime_api();
    let session = api.current_session(&BlockId::Hash(last)).unwrap();
    let validators = api.validators(&BlockId::Hash(last)).unwrap();
    assert_eq!(validators.len(), 1);
    let keys = Pair::from_string("//Alice", None).unwrap();
    TendermintValidatorsStruct {
      session,

      // TODO
      total_weight: validators.len().try_into().unwrap(),
      weights: vec![1; validators.len()],

      lookup: vec![keys.public()],
      keys,
    }
  }
}

// Wrap every access of the validators struct in something which forces calling refresh
struct Refresh<B: Block, Be: Backend<B> + 'static, C: TendermintClient<B, Be>>
where
  TransactionFor<C, B>: Send + Sync + 'static,
  C::Api: TendermintApi<B>,
{
  _block: PhantomData<B>,
  _backend: PhantomData<Be>,

  client: Arc<C>,
  _refresh: Arc<RwLock<TendermintValidatorsStruct>>,
}

impl<B: Block, Be: Backend<B> + 'static, C: TendermintClient<B, Be>> Refresh<B, Be, C>
where
  TransactionFor<C, B>: Send + Sync + 'static,
  C::Api: TendermintApi<B>,
{
  // If the session has changed, re-create the struct with the data on it
  fn refresh(&self) {
    let session = self._refresh.read().unwrap().session;
    if session !=
      self
        .client
        .runtime_api()
        .current_session(&BlockId::Hash(self.client.info().best_hash))
        .unwrap()
    {
      *self._refresh.write().unwrap() = TendermintValidatorsStruct::from_module(&self.client);
    }
  }
}

impl<B: Block, Be: Backend<B> + 'static, C: TendermintClient<B, Be>> Deref for Refresh<B, Be, C>
where
  TransactionFor<C, B>: Send + Sync + 'static,
  C::Api: TendermintApi<B>,
{
  type Target = RwLock<TendermintValidatorsStruct>;
  fn deref(&self) -> &RwLock<TendermintValidatorsStruct> {
    self.refresh();
    &self._refresh
  }
}

pub(crate) struct TendermintValidators<
  B: Block,
  Be: Backend<B> + 'static,
  C: TendermintClient<B, Be>,
>(Refresh<B, Be, C>)
where
  TransactionFor<C, B>: Send + Sync + 'static,
  C::Api: TendermintApi<B>;

impl<B: Block, Be: Backend<B> + 'static, C: TendermintClient<B, Be>> TendermintValidators<B, Be, C>
where
  TransactionFor<C, B>: Send + Sync + 'static,
  C::Api: TendermintApi<B>,
{
  pub(crate) fn new(client: Arc<C>) -> TendermintValidators<B, Be, C> {
    TendermintValidators(Refresh {
      _block: PhantomData,
      _backend: PhantomData,

      _refresh: Arc::new(RwLock::new(TendermintValidatorsStruct::from_module(&client))),
      client,
    })
  }
}

impl<B: Block, Be: Backend<B> + 'static, C: TendermintClient<B, Be>> SignatureScheme
  for TendermintValidators<B, Be, C>
where
  TransactionFor<C, B>: Send + Sync + 'static,
  C::Api: TendermintApi<B>,
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

impl<B: Block, Be: Backend<B> + 'static, C: TendermintClient<B, Be>> Weights
  for TendermintValidators<B, Be, C>
where
  TransactionFor<C, B>: Send + Sync + 'static,
  C::Api: TendermintApi<B>,
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
    u16::try_from(
      (number.0 + u64::from(round.0)) % u64::try_from(self.0.read().unwrap().lookup.len()).unwrap(),
    )
    .unwrap()
  }
}
