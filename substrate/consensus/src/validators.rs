// TODO: This should be built around pallet_sessions (and pallet_staking?).

use sp_application_crypto::{
  RuntimePublic as PublicTrait, Pair as PairTrait,
  sr25519::{Public, Pair, Signature},
};

use tendermint_machine::ext::{BlockNumber, Round, Weights, SignatureScheme};

const VALIDATORS: usize = 1;

pub(crate) struct TendermintValidators {
  keys: Pair, // sp_keystore
  lookup: Vec<Public>, // sessions
}

impl TendermintValidators {
  pub(crate) fn new() -> TendermintValidators {
    let keys = Pair::from_string("//Alice", None).unwrap();
    TendermintValidators { lookup: vec![keys.public()], keys }
  }
}

impl SignatureScheme for TendermintValidators {
  type ValidatorId = u16;
  type Signature = Signature;
  type AggregateSignature = Vec<Signature>;

  fn sign(&self, msg: &[u8]) -> Signature {
    self.keys.sign(msg)
  }

  fn verify(&self, validator: u16, msg: &[u8], sig: &Signature) -> bool {
    self.lookup[usize::try_from(validator).unwrap()].verify(&msg, sig)
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
    VALIDATORS.try_into().unwrap()
  }
  fn weight(&self, id: u16) -> u64 {
    [1; VALIDATORS][usize::try_from(id).unwrap()]
  }

  fn proposer(&self, number: BlockNumber, round: Round) -> u16 {
    u16::try_from((number.0 + u64::from(round.0)) % u64::try_from(VALIDATORS).unwrap()).unwrap()
  }
}
