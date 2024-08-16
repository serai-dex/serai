use core::marker::PhantomData;
use std::collections::HashMap;

use zeroize::Zeroizing;

use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};
use dkg::{Participant, ThresholdCore, ThresholdKeys, evrf::EvrfCurve};

use serai_validator_sets_primitives::Session;

use borsh::{BorshSerialize, BorshDeserialize};
use serai_db::{Get, DbTxn, create_db};

use crate::KeyGenParams;

pub(crate) struct Params<P: KeyGenParams> {
  pub(crate) t: u16,
  pub(crate) n: u16,
  pub(crate) substrate_evrf_public_keys:
    Vec<<<Ristretto as EvrfCurve>::EmbeddedCurve as Ciphersuite>::G>,
  pub(crate) network_evrf_public_keys:
    Vec<<<P::ExternalNetworkCurve as EvrfCurve>::EmbeddedCurve as Ciphersuite>::G>,
}

#[derive(BorshSerialize, BorshDeserialize)]
struct RawParams {
  t: u16,
  substrate_evrf_public_keys: Vec<[u8; 32]>,
  network_evrf_public_keys: Vec<Vec<u8>>,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub(crate) struct Participations {
  pub(crate) substrate_participations: HashMap<Participant, Vec<u8>>,
  pub(crate) network_participations: HashMap<Participant, Vec<u8>>,
}

create_db!(
  KeyGenDb {
    ParamsDb: (session: &Session) -> RawParams,
    ParticipationsDb: (session: &Session) -> Participations,
    KeySharesDb: (session: &Session) -> Vec<u8>,
  }
);

pub(crate) struct KeyGenDb<P: KeyGenParams>(PhantomData<P>);
impl<P: KeyGenParams> KeyGenDb<P> {
  pub(crate) fn set_params(txn: &mut impl DbTxn, session: Session, params: Params<P>) {
    assert_eq!(params.substrate_evrf_public_keys.len(), params.network_evrf_public_keys.len());

    ParamsDb::set(
      txn,
      &session,
      &RawParams {
        t: params.t,
        substrate_evrf_public_keys: params
          .substrate_evrf_public_keys
          .into_iter()
          .map(|key| key.to_bytes())
          .collect(),
        network_evrf_public_keys: params
          .network_evrf_public_keys
          .into_iter()
          .map(|key| key.to_bytes().as_ref().to_vec())
          .collect(),
      },
    )
  }

  pub(crate) fn params(getter: &impl Get, session: Session) -> Option<Params<P>> {
    ParamsDb::get(getter, &session).map(|params| Params {
      t: params.t,
      n: params
        .network_evrf_public_keys
        .len()
        .try_into()
        .expect("amount of keys exceeded the amount allowed during a DKG"),
      substrate_evrf_public_keys: params
        .substrate_evrf_public_keys
        .into_iter()
        .map(|key| {
          <<Ristretto as EvrfCurve>::EmbeddedCurve as Ciphersuite>::read_G(&mut key.as_slice())
            .unwrap()
        })
        .collect(),
      network_evrf_public_keys: params
        .network_evrf_public_keys
        .into_iter()
        .map(|key| {
          <<P::ExternalNetworkCurve as EvrfCurve>::EmbeddedCurve as Ciphersuite>::read_G::<&[u8]>(
            &mut key.as_ref(),
          )
          .unwrap()
        })
        .collect(),
    })
  }

  pub(crate) fn set_participations(
    txn: &mut impl DbTxn,
    session: Session,
    participations: &Participations,
  ) {
    ParticipationsDb::set(txn, &session, participations)
  }
  pub(crate) fn participations(getter: &impl Get, session: Session) -> Option<Participations> {
    ParticipationsDb::get(getter, &session)
  }

  pub(crate) fn set_key_shares(
    txn: &mut impl DbTxn,
    session: Session,
    substrate_keys: &[ThresholdKeys<Ristretto>],
    network_keys: &[ThresholdKeys<P::ExternalNetworkCurve>],
  ) {
    assert_eq!(substrate_keys.len(), network_keys.len());

    let mut keys = Zeroizing::new(vec![]);
    for (substrate_keys, network_keys) in substrate_keys.iter().zip(network_keys) {
      keys.extend(substrate_keys.serialize().as_slice());
      keys.extend(network_keys.serialize().as_slice());
    }
    KeySharesDb::set(txn, &session, &keys);
  }

  #[allow(clippy::type_complexity)]
  pub(crate) fn key_shares(
    getter: &impl Get,
    session: Session,
  ) -> Option<(Vec<ThresholdKeys<Ristretto>>, Vec<ThresholdKeys<P::ExternalNetworkCurve>>)> {
    let keys = KeySharesDb::get(getter, &session)?;
    let mut keys: &[u8] = keys.as_ref();

    let mut substrate_keys = vec![];
    let mut network_keys = vec![];
    while !keys.is_empty() {
      substrate_keys.push(ThresholdKeys::new(ThresholdCore::read(&mut keys).unwrap()));
      let mut these_network_keys = ThresholdKeys::new(ThresholdCore::read(&mut keys).unwrap());
      P::tweak_keys(&mut these_network_keys);
      network_keys.push(these_network_keys);
    }
    Some((substrate_keys, network_keys))
  }
}
