use std::sync::{Arc, RwLock};

use sp_core::{Decode, sr25519::Signature};
use sp_runtime::traits::{Hash, Header, Block};

use sc_network::PeerId;
use sc_network_gossip::{Validator, ValidatorContext, ValidationResult};

use tendermint_machine::{SignedMessage, ext::SignatureScheme};

#[derive(Clone)]
pub struct TendermintGossip<S: SignatureScheme<ValidatorId = u16, Signature = Signature>> {
  number: Arc<RwLock<u64>>,
  signature_scheme: Arc<S>,
}

impl<S: SignatureScheme<ValidatorId = u16, Signature = Signature>> TendermintGossip<S> {
  pub(crate) fn new(number: Arc<RwLock<u64>>, signature_scheme: Arc<S>) -> TendermintGossip<S> {
    TendermintGossip { number, signature_scheme }
  }

  pub(crate) fn topic<B: Block>(number: u64) -> B::Hash {
    <<B::Header as Header>::Hashing as Hash>::hash(
      &[b"Tendermint Block Topic".as_ref(), &number.to_le_bytes()].concat(),
    )
  }
}

impl<B: Block, S: SignatureScheme<ValidatorId = u16, Signature = Signature>> Validator<B>
  for TendermintGossip<S>
{
  fn validate(
    &self,
    _: &mut dyn ValidatorContext<B>,
    _: &PeerId,
    data: &[u8],
  ) -> ValidationResult<B::Hash> {
    let msg = match SignedMessage::<u16, B, Signature>::decode(&mut &*data) {
      Ok(msg) => msg,
      Err(_) => return ValidationResult::Discard,
    };

    if msg.number().0 < *self.number.read().unwrap() {
      return ValidationResult::Discard;
    }

    if !msg.verify_signature(&self.signature_scheme) {
      return ValidationResult::Discard;
    }

    ValidationResult::ProcessAndKeep(Self::topic::<B>(msg.number().0))
  }
}
