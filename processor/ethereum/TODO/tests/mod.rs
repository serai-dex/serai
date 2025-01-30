// TODO

use std::{sync::Arc, collections::HashMap};

use rand_core::OsRng;

use k256::{Scalar, ProjectivePoint};
use frost::{curve::Secp256k1, Participant, ThresholdKeys, tests::key_gen as frost_key_gen};

use alloy_core::{
  primitives::{Address, U256, Bytes, Signature, TxKind},
  hex::FromHex,
};
use alloy_consensus::{SignableTransaction, TxLegacy};

use alloy_rpc_types_eth::TransactionReceipt;
use alloy_simple_request_transport::SimpleRequest;
use alloy_provider::{Provider, RootProvider};

use crate::crypto::{address, deterministically_sign, PublicKey};

#[cfg(test)]
mod crypto;

#[cfg(test)]
use contracts::tests as abi;
#[cfg(test)]
mod router;

pub fn key_gen() -> (HashMap<Participant, ThresholdKeys<Secp256k1>>, PublicKey) {
  let mut keys = frost_key_gen::<_, Secp256k1>(&mut OsRng);
  let mut group_key = keys[&Participant::new(1).unwrap()].group_key();

  let mut offset = Scalar::ZERO;
  while PublicKey::new(group_key).is_none() {
    offset += Scalar::ONE;
    group_key += ProjectivePoint::GENERATOR;
  }
  for keys in keys.values_mut() {
    *keys = keys.offset(offset);
  }
  let public_key = PublicKey::new(group_key).unwrap();

  (keys, public_key)
}
