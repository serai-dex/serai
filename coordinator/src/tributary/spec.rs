use core::{ops::Range, fmt::Debug};
use std::io;

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

  pub fn n(&self) -> u16 {
    self.validators.iter().map(|(_, weight)| weight).sum()
  }

  pub fn t(&self) -> u16 {
    ((2 * self.n()) / 3) + 1
  }

  pub fn i(&self, key: <Ristretto as Ciphersuite>::G) -> Option<Range<Participant>> {
    let mut i = 1;
    for (validator, weight) in &self.validators {
      if validator == &key {
        return Some(Range {
          start: Participant::new(i).unwrap(),
          end: Participant::new(i + weight).unwrap(),
        });
      }
      i += weight;
    }
    None
  }

  pub fn validators(&self) -> Vec<(<Ristretto as Ciphersuite>::G, u64)> {
    self.validators.iter().map(|(validator, weight)| (*validator, u64::from(*weight))).collect()
  }
}
