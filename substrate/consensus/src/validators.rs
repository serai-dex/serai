use core::ops::Deref;
use std::sync::{Arc, RwLock};

use sp_application_crypto::{
  RuntimePublic as PublicTrait, Pair as PairTrait,
  sr25519::{Public, Pair, Signature},
};

use sp_staking::SessionIndex;
use pallet_session::Pallet as Session;

use tendermint_machine::ext::{BlockNumber, Round, Weights, SignatureScheme};

struct TendermintValidatorsStruct {
  session: SessionIndex,

  total_weight: u64,
  weights: Vec<u64>,

  keys: Pair,          // TODO: sp_keystore
  lookup: Vec<Public>, // TODO: sessions
}

impl TendermintValidatorsStruct {
  fn from_module() -> TendermintValidatorsStruct {
    let validators = Session::<serai_runtime::Runtime>::validators();
    assert_eq!(validators.len(), 1);
    let keys = Pair::from_string("//Alice", None).unwrap();
    TendermintValidatorsStruct {
      session: Session::<serai_runtime::Runtime>::current_index(),

      // TODO
      total_weight: validators.len().try_into().unwrap(),
      weights: vec![1; validators.len()],

      lookup: vec![keys.public()],
      keys,
    }
  }
}

// Wrap every access of the validators struct in something which forces calling refresh
struct Refresh {
  _refresh: Arc<RwLock<TendermintValidatorsStruct>>,
}
impl Refresh {
  // If the session has changed, re-create the struct with the data on it
  fn refresh(&self) {
    let session = self._refresh.read().unwrap().session;
    if session != Session::<serai_runtime::Runtime>::current_index() {
      *self._refresh.write().unwrap() = TendermintValidatorsStruct::from_module();
    }
  }
}

impl Deref for Refresh {
  type Target = RwLock<TendermintValidatorsStruct>;
  fn deref(&self) -> &RwLock<TendermintValidatorsStruct> {
    self.refresh();
    &self._refresh
  }
}

pub(crate) struct TendermintValidators(Refresh);
impl TendermintValidators {
  pub(crate) fn new() -> TendermintValidators {
    TendermintValidators(Refresh {
      _refresh: Arc::new(RwLock::new(TendermintValidatorsStruct::from_module())),
    })
  }
}

impl SignatureScheme for TendermintValidators {
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

impl Weights for TendermintValidators {
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
