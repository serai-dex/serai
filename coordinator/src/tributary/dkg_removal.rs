use core::ops::Deref;
use std::collections::HashMap;

use zeroize::Zeroizing;

use ciphersuite::{
  group::{Group, GroupEncoding},
  Ciphersuite, Ristretto,
};
use frost::{dkg::Participant, sign::*};
use frost_schnorrkel::Schnorrkel;

use serai_client::{Public, SeraiAddress, validator_sets::primitives::remove_participant_message};

use serai_db::DbTxn;

use crate::tributary::{TributarySpec, signing_protocol::SigningProtocol};

pub(crate) struct DkgRemoval<'a, T: DbTxn> {
  pub(crate) key: &'a Zeroizing<<Ristretto as Ciphersuite>::F>,
  pub(crate) spec: &'a TributarySpec,
  pub(crate) txn: &'a mut T,
  pub(crate) removing: [u8; 32],
  pub(crate) attempt: u32,
}

impl<T: DbTxn> DkgRemoval<'_, T> {
  fn signing_protocol(&mut self) -> SigningProtocol<'_, T, (&'static [u8; 10], [u8; 32], u32)> {
    let context = (b"DkgRemoval", self.removing, self.attempt);
    SigningProtocol { key: self.key, spec: self.spec, txn: self.txn, context }
  }

  fn preprocess_internal(
    &mut self,
    participants: Option<&[<Ristretto as Ciphersuite>::G]>,
  ) -> (AlgorithmSignMachine<Ristretto, Schnorrkel>, [u8; 64]) {
    // We won't know the participants when we first preprocess
    // If we don't, we use our key alone as the participant
    let just_us = [<Ristretto as Ciphersuite>::G::generator() * self.key.deref()];
    let to_musig = if let Some(participants) = participants { participants } else { &just_us };

    let (machine, preprocess) = self.signing_protocol().preprocess_internal(to_musig);

    // If we're now specifying participants, confirm the commitments were the same
    if participants.is_some() {
      let (_, theoretical_preprocess) = self.signing_protocol().preprocess_internal(&just_us);
      assert_eq!(theoretical_preprocess, preprocess);
    }

    (machine, preprocess)
  }
  // Get the preprocess for this confirmation.
  pub(crate) fn preprocess(&mut self) -> [u8; 64] {
    self.preprocess_internal(None).1
  }

  fn threshold_i_map_to_musig_i_map_with_keys(
    spec: &TributarySpec,
    mut map: HashMap<Participant, Vec<u8>>,
  ) -> (Vec<<Ristretto as Ciphersuite>::G>, HashMap<Participant, Vec<u8>>) {
    let spec_validators = spec.validators();
    let key_from_threshold_i = |threshold_i| {
      for (key, _) in &spec_validators {
        if threshold_i == spec.i(*key).unwrap().start {
          return *key;
        }
      }
      panic!("requested info for threshold i which doesn't exist")
    };

    // Substrate expects these signers to be sorted by key
    let mut sorted = vec![];
    let threshold_is = map.keys().cloned().collect::<Vec<_>>();
    for threshold_i in threshold_is {
      sorted.push((key_from_threshold_i(threshold_i), map.remove(&threshold_i).unwrap()));
    }
    sorted.sort_by(|(key1, _), (key2, _)| key1.to_bytes().cmp(&key2.to_bytes()));

    // Now that signers are sorted, with their shares, create a map with the is needed for MuSig
    let mut participant = vec![];
    let mut map = HashMap::new();
    for (musig_i, (key, share)) in sorted.into_iter().enumerate() {
      participant.push(key);
      map.insert(Participant::new(u16::try_from(musig_i).unwrap() + 1).unwrap(), share);
    }

    (participant, map)
  }

  fn share_internal(
    &mut self,
    preprocesses: HashMap<Participant, Vec<u8>>,
  ) -> Result<(AlgorithmSignatureMachine<Ristretto, Schnorrkel>, [u8; 32]), Participant> {
    let (participants, preprocesses) =
      Self::threshold_i_map_to_musig_i_map_with_keys(self.spec, preprocesses);
    let msg = remove_participant_message(&self.spec.set(), Public(self.removing));
    self.signing_protocol().share_internal(&participants, preprocesses, &msg)
  }
  // Get the share for this confirmation, if the preprocesses are valid.
  pub(crate) fn share(
    &mut self,
    preprocesses: HashMap<Participant, Vec<u8>>,
  ) -> Result<[u8; 32], Participant> {
    self.share_internal(preprocesses).map(|(_, share)| share)
  }

  pub(crate) fn complete(
    &mut self,
    preprocesses: HashMap<Participant, Vec<u8>>,
    shares: HashMap<Participant, Vec<u8>>,
  ) -> Result<(Vec<SeraiAddress>, [u8; 64]), Participant> {
    let (participants, shares) = Self::threshold_i_map_to_musig_i_map_with_keys(self.spec, shares);
    let signers = participants.iter().map(|key| SeraiAddress(key.to_bytes())).collect::<Vec<_>>();

    let machine = self
      .share_internal(preprocesses)
      .expect("trying to complete a machine which failed to preprocess")
      .0;

    let signature = self.signing_protocol().complete_internal(machine, shares)?;
    Ok((signers, signature))
  }
}
