use sp_application_crypto::{
  RuntimePublic as PublicTrait, Pair as PairTrait,
  sr25519::{Public, Pair, Signature},
};

use tendermint_machine::ext::SignatureScheme;

pub(crate) struct TendermintSigner {
  keys: Pair,
  lookup: Vec<Public>,
}

impl TendermintSigner {
  pub(crate) fn new() -> TendermintSigner {
    // TODO
    let keys = Pair::from_string("//Alice", None).unwrap();
    TendermintSigner { lookup: vec![keys.public()], keys }
  }
}

impl SignatureScheme for TendermintSigner {
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
