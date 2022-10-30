use core::{marker::PhantomData, ops::Deref};
use std::sync::{Arc, RwLock};

use sp_application_crypto::{
  RuntimePublic as PublicTrait, Pair as PairTrait,
  sr25519::{Public, Pair, Signature},
};

use sp_staking::SessionIndex;
use sp_api::{BlockId, ProvideRuntimeApi};

use sc_client_api::HeaderBackend;

use tendermint_machine::ext::{BlockNumber, Round, Weights, SignatureScheme};

use sp_tendermint::TendermintApi;

use crate::TendermintClient;

struct TendermintValidatorsStruct {
  session: SessionIndex,

  total_weight: u64,
  weights: Vec<u64>,

  keys: Pair, // TODO: sp_keystore
  lookup: Vec<Public>,
}

impl TendermintValidatorsStruct {
  fn from_module<T: TendermintClient>(client: &Arc<T::Client>) -> TendermintValidatorsStruct {
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

      lookup: validators,
      keys,
    }
  }
}

// Wrap every access of the validators struct in something which forces calling refresh
struct Refresh<T: TendermintClient> {
  _tc: PhantomData<T>,
  client: Arc<T::Client>,
  _refresh: Arc<RwLock<TendermintValidatorsStruct>>,
}

impl<T: TendermintClient> Refresh<T> {
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
      *self._refresh.write().unwrap() = TendermintValidatorsStruct::from_module::<T>(&self.client);
    }
  }
}

impl<T: TendermintClient> Deref for Refresh<T> {
  type Target = RwLock<TendermintValidatorsStruct>;
  fn deref(&self) -> &RwLock<TendermintValidatorsStruct> {
    self.refresh();
    &self._refresh
  }
}

pub struct TendermintValidators<T: TendermintClient>(Refresh<T>);

impl<T: TendermintClient> TendermintValidators<T> {
  pub(crate) fn new(client: Arc<T::Client>) -> TendermintValidators<T> {
    TendermintValidators(Refresh {
      _tc: PhantomData,
      _refresh: Arc::new(RwLock::new(TendermintValidatorsStruct::from_module::<T>(&client))),
      client,
    })
  }
}

impl<T: TendermintClient> SignatureScheme for TendermintValidators<T> {
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

impl<T: TendermintClient> Weights for TendermintValidators<T> {
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
