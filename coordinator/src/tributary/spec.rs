use core::{ops::Range, fmt::Debug};
use std::{io, collections::HashMap};

use transcript::{Transcript, RecommendedTranscript};

use ciphersuite::{group::GroupEncoding, Ciphersuite, Ristretto};
use frost::Participant;

use scale::Encode;
use borsh::{BorshSerialize, BorshDeserialize};

use serai_client::{primitives::PublicKey, validator_sets::primitives::ValidatorSet};

fn borsh_serialize_validators<W: io::Write>(
  validators: &Vec<(<Ristretto as Ciphersuite>::G, u16)>,
  writer: &mut W,
) -> Result<(), io::Error> {
  let len = u16::try_from(validators.len()).unwrap();
  BorshSerialize::serialize(&len, writer)?;
  for validator in validators {
    BorshSerialize::serialize(&validator.0.to_bytes(), writer)?;
    BorshSerialize::serialize(&validator.1, writer)?;
  }
  Ok(())
}

fn borsh_deserialize_validators<R: io::Read>(
  reader: &mut R,
) -> Result<Vec<(<Ristretto as Ciphersuite>::G, u16)>, io::Error> {
  let len: u16 = BorshDeserialize::deserialize_reader(reader)?;
  let mut res = vec![];
  for _ in 0 .. len {
    let compressed: [u8; 32] = BorshDeserialize::deserialize_reader(reader)?;
    let point = Option::from(<Ristretto as Ciphersuite>::G::from_bytes(&compressed))
      .ok_or_else(|| io::Error::other("invalid point for validator"))?;
    let weight: u16 = BorshDeserialize::deserialize_reader(reader)?;
    res.push((point, weight));
  }
  Ok(res)
}

#[derive(Clone, PartialEq, Eq, Debug, BorshSerialize, BorshDeserialize)]
pub struct TributarySpec {
  serai_block: [u8; 32],
  start_time: u64,
  set: ValidatorSet,
  #[borsh(
    serialize_with = "borsh_serialize_validators",
    deserialize_with = "borsh_deserialize_validators"
  )]
  validators: Vec<(<Ristretto as Ciphersuite>::G, u16)>,
}

impl TributarySpec {
  pub fn new(
    serai_block: [u8; 32],
    start_time: u64,
    set: ValidatorSet,
    set_participants: Vec<(PublicKey, u16)>,
  ) -> TributarySpec {
    let mut validators = vec![];
    for (participant, shares) in set_participants {
      let participant = <Ristretto as Ciphersuite>::read_G::<&[u8]>(&mut participant.0.as_ref())
        .expect("invalid key registered as participant");
      validators.push((participant, shares));
    }

    Self { serai_block, start_time, set, validators }
  }

  pub fn set(&self) -> ValidatorSet {
    self.set
  }

  pub fn genesis(&self) -> [u8; 32] {
    // Calculate the genesis for this Tributary
    let mut genesis = RecommendedTranscript::new(b"Serai Tributary Genesis");
    // This locks it to a specific Serai chain
    genesis.append_message(b"serai_block", self.serai_block);
    genesis.append_message(b"session", self.set.session.0.to_le_bytes());
    genesis.append_message(b"network", self.set.network.encode());
    let genesis = genesis.challenge(b"genesis");
    let genesis_ref: &[u8] = genesis.as_ref();
    genesis_ref[.. 32].try_into().unwrap()
  }

  pub fn start_time(&self) -> u64 {
    self.start_time
  }

  pub fn n(&self, removed_validators: &[<Ristretto as Ciphersuite>::G]) -> u16 {
    self
      .validators
      .iter()
      .map(|(validator, weight)| if removed_validators.contains(validator) { 0 } else { *weight })
      .sum()
  }

  pub fn t(&self) -> u16 {
    // t doesn't change with regards to the amount of removed validators
    ((2 * self.n(&[])) / 3) + 1
  }

  pub fn i(
    &self,
    removed_validators: &[<Ristretto as Ciphersuite>::G],
    key: <Ristretto as Ciphersuite>::G,
  ) -> Option<Range<Participant>> {
    let mut all_is = HashMap::new();
    let mut i = 1;
    for (validator, weight) in &self.validators {
      all_is.insert(
        *validator,
        Range { start: Participant::new(i).unwrap(), end: Participant::new(i + weight).unwrap() },
      );
      i += weight;
    }

    let original_i = all_is.get(&key)?.clone();
    let mut result_i = original_i.clone();
    for removed_validator in removed_validators {
      let removed_i = all_is
        .get(removed_validator)
        .expect("removed validator wasn't present in set to begin with");
      // If the queried key was removed, return None
      if &original_i == removed_i {
        return None;
      }

      // If the removed was before the queried, shift the queried down accordingly
      if removed_i.start < original_i.start {
        let removed_shares = u16::from(removed_i.end) - u16::from(removed_i.start);
        result_i.start = Participant::new(u16::from(original_i.start) - removed_shares).unwrap();
        result_i.end = Participant::new(u16::from(original_i.end) - removed_shares).unwrap();
      }
    }
    Some(result_i)
  }

  pub fn reverse_lookup_i(
    &self,
    removed_validators: &[<Ristretto as Ciphersuite>::G],
    i: Participant,
  ) -> Option<<Ristretto as Ciphersuite>::G> {
    for (validator, _) in &self.validators {
      if self.i(removed_validators, *validator).map_or(false, |range| range.contains(&i)) {
        return Some(*validator);
      }
    }
    None
  }

  pub fn validators(&self) -> Vec<(<Ristretto as Ciphersuite>::G, u64)> {
    self.validators.iter().map(|(validator, weight)| (*validator, u64::from(*weight))).collect()
  }
}
