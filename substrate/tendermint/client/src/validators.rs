use core::ops::Deref;
use std::sync::{Arc, RwLock};

use async_trait::async_trait;

use tokio::sync::RwLock as AsyncRwLock;

use sp_core::Decode;
use sp_application_crypto::{
  RuntimePublic as PublicTrait,
  sr25519::{Public, Signature},
};
use sp_keystore::CryptoStore;

use sp_staking::SessionIndex;
use sp_api::{BlockId, ProvideRuntimeApi};

use sc_client_api::HeaderBackend;

use tendermint_machine::ext::{BlockNumber, Round, Weights, SignatureScheme};

use sp_tendermint::TendermintApi;

use crate::{KEY_TYPE_ID, TendermintClient};

struct TendermintValidatorsStruct {
  session: SessionIndex,

  total_weight: u64,
  weights: Vec<u64>,

  lookup: Vec<Public>,
}

impl TendermintValidatorsStruct {
  fn from_module<T: TendermintClient>(client: &Arc<T::Client>) -> Self {
    let last = client.info().finalized_hash;
    let api = client.runtime_api();
    let session = api.current_session(&BlockId::Hash(last)).unwrap();
    let validators = api.validators(&BlockId::Hash(last)).unwrap();
    assert_eq!(validators.len(), 1);

    Self {
      session,

      // TODO
      total_weight: validators.len().try_into().unwrap(),
      weights: vec![1; validators.len()],

      lookup: validators,
    }
  }
}

// Wrap every access of the validators struct in something which forces calling refresh
struct Refresh<T: TendermintClient> {
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
        .current_session(&BlockId::Hash(self.client.info().finalized_hash))
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

/// Tendermint validators observer, providing data on the active validators.
pub struct TendermintValidators<T: TendermintClient>(
  Refresh<T>,
  Arc<AsyncRwLock<Option<T::Keystore>>>,
);

impl<T: TendermintClient> TendermintValidators<T> {
  pub(crate) fn new(client: Arc<T::Client>) -> TendermintValidators<T> {
    TendermintValidators(
      Refresh {
        _refresh: Arc::new(RwLock::new(TendermintValidatorsStruct::from_module::<T>(&client))),
        client,
      },
      Arc::new(AsyncRwLock::new(None)),
    )
  }

  pub(crate) async fn set_keys(&self, keys: T::Keystore) {
    *self.1.write().await = Some(keys);
  }
}

#[async_trait]
impl<T: TendermintClient> SignatureScheme for TendermintValidators<T> {
  type ValidatorId = u16;
  type Signature = Signature;
  type AggregateSignature = Vec<Signature>;

  async fn sign(&self, msg: &[u8]) -> Signature {
    let read = self.1.read().await;
    let keys = read.as_ref().unwrap();
    let key = {
      let pubs = keys.sr25519_public_keys(KEY_TYPE_ID).await;
      if pubs.is_empty() {
        keys.sr25519_generate_new(KEY_TYPE_ID, None).await.unwrap()
      } else {
        pubs[0]
      }
    };
    Signature::decode(
      &mut keys.sign_with(KEY_TYPE_ID, &key.into(), msg).await.unwrap().unwrap().as_ref(),
    )
    .unwrap()
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
