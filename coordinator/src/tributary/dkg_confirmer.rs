use std::collections::HashMap;

use zeroize::Zeroizing;

use ciphersuite::{Ciphersuite, Ristretto};
use frost::{dkg::Participant, sign::*};
use frost_schnorrkel::Schnorrkel;

use serai_client::validator_sets::primitives::{KeyPair, set_keys_message};

use serai_db::DbTxn;

use crate::tributary::{TributarySpec, signing_protocol::SigningProtocol};

pub(crate) struct DkgConfirmer<'a, T: DbTxn> {
  pub(crate) key: &'a Zeroizing<<Ristretto as Ciphersuite>::F>,
  pub(crate) spec: &'a TributarySpec,
  pub(crate) txn: &'a mut T,
  pub(crate) attempt: u32,
}

impl<T: DbTxn> DkgConfirmer<'_, T> {
  // Convert the passed in HashMap, which uses the validators' start index for their `s` threshold
  // shares, to the indexes needed for MuSig
  fn from_threshold_i_to_musig_i(
    spec: &TributarySpec,
    mut old_map: HashMap<Participant, Vec<u8>>,
  ) -> HashMap<Participant, Vec<u8>> {
    let mut new_map = HashMap::new();
    for (musig_i, validator) in spec.validators().into_iter().enumerate() {
      let threshold_i = spec.i(validator.0).unwrap();
      if let Some(value) = old_map.remove(&threshold_i.start) {
        new_map.insert(Participant::new(u16::try_from(musig_i + 1).unwrap()).unwrap(), value);
      }
    }
    new_map
  }

  fn signing_protocol(&mut self) -> SigningProtocol<'_, T, (&'static [u8; 12], u32)> {
    let context = (b"DkgConfirmer", self.attempt);
    SigningProtocol { key: self.key, spec: self.spec, txn: self.txn, context }
  }

  fn preprocess_internal(&mut self) -> (AlgorithmSignMachine<Ristretto, Schnorrkel>, [u8; 64]) {
    let participants = self.spec.validators().iter().map(|val| val.0).collect::<Vec<_>>();
    self.signing_protocol().preprocess_internal(&participants)
  }
  // Get the preprocess for this confirmation.
  pub(crate) fn preprocess(&mut self) -> [u8; 64] {
    self.preprocess_internal().1
  }

  fn share_internal(
    &mut self,
    preprocesses: HashMap<Participant, Vec<u8>>,
    key_pair: &KeyPair,
  ) -> Result<(AlgorithmSignatureMachine<Ristretto, Schnorrkel>, [u8; 32]), Participant> {
    let participants = self.spec.validators().iter().map(|val| val.0).collect::<Vec<_>>();
    let msg = set_keys_message(&self.spec.set(), key_pair);
    self.signing_protocol().share_internal(&participants, preprocesses, &msg)
  }
  // Get the share for this confirmation, if the preprocesses are valid.
  pub(crate) fn share(
    &mut self,
    preprocesses: HashMap<Participant, Vec<u8>>,
    key_pair: &KeyPair,
  ) -> Result<[u8; 32], Participant> {
    self.share_internal(preprocesses, key_pair).map(|(_, share)| share)
  }

  pub(crate) fn complete(
    &mut self,
    preprocesses: HashMap<Participant, Vec<u8>>,
    key_pair: &KeyPair,
    shares: HashMap<Participant, Vec<u8>>,
  ) -> Result<[u8; 64], Participant> {
    let shares = Self::from_threshold_i_to_musig_i(self.spec, shares);

    let machine = self
      .share_internal(preprocesses, key_pair)
      .expect("trying to complete a machine which failed to preprocess")
      .0;

    self.signing_protocol().complete_internal(machine, shares)
  }
}
