//! Random event generators mirroring [`events`](crate::events).
//!
//! Every function takes only an RNG and produces a random [`Event`].

use rand_core::{CryptoRng, RngCore};

use serai_abi::{
  primitives::{
    address::SeraiAddress,
    test_helpers::{
      random_block_hash, random_external_address, random_external_network_id, random_serai_address,
    },
    validator_sets::{KeyShares, Session, ValidatorSet},
  },
  Event,
};

use crate::{events, test_helpers::random_amount};

/// Random event generators for [`Event::ValidatorSets`] variants.
pub mod validator_sets {
  use crate::test_helpers::random_network_id;
  use super::*;

  /// Creates a random [`Event::ValidatorSets(SetDecided)`] event.
  pub fn set_decided<R: RngCore + CryptoRng>(rng: &mut R, num_validators: usize) -> Event {
    let network = random_network_id(rng);
    let session = Session(rng.next_u32());
    let validators: Vec<(SeraiAddress, KeyShares)> =
      (0 .. num_validators).map(|_| (random_serai_address(rng), KeyShares::ONE)).collect();
    events::validator_sets::set_decided(ValidatorSet { network, session }, validators)
  }

  /// Creates a random [`Event::ValidatorSets(Allocation)`] event.
  pub fn allocation<R: RngCore + CryptoRng>(rng: &mut R) -> Event {
    events::validator_sets::allocation(
      random_serai_address(rng),
      random_network_id(rng),
      random_amount(rng),
    )
  }

  /// Creates a random [`Event::ValidatorSets(Deallocation)`] event.
  pub fn deallocation<R: RngCore + CryptoRng>(rng: &mut R) -> Event {
    events::validator_sets::deallocation(
      random_serai_address(rng),
      random_network_id(rng),
      random_amount(rng),
    )
  }

  /// Creates a random [`Event::ValidatorSets(Slashes)`] event.
  pub fn slash_report<R: RngCore + CryptoRng>(rng: &mut R) -> Event {
    events::validator_sets::slash_report(
      serai_primitives::test_helpers::random_external_validator_set(rng),
    )
  }

  /// Creates a random [`Event::ValidatorSets(SetEmbeddedEllipticCurveKeys)`] event.
  pub fn set_embedded_elliptic_curve_keys<R: RngCore + CryptoRng>(
    rng: &mut R,
    network: serai_primitives::network_id::NetworkId,
  ) -> Event {
    events::validator_sets::set_embedded_elliptic_curve_keys(
      random_serai_address(rng),
      serai_primitives::test_helpers::random_embedded_elliptic_curve_keys(rng, network),
    )
  }
}

/// Random event generators for [`Event::Coins`] variants.
pub mod coins {
  use super::*;

  /// Creates a random [`Event::Coins(BurnWithInstruction)`] event.
  pub fn burn_with_instruction<R: RngCore + CryptoRng>(rng: &mut R) -> Event {
    events::coins::burn_with_instruction(
      random_serai_address(rng),
      random_external_address(rng),
      random_amount(rng),
    )
  }
}

/// Random event generators for [`Event::InInstructions`] variants.
pub mod in_instructions {
  use super::*;
  use bitvec::vec::BitVec as Bv;

  /// Creates a random [`Event::InInstructions(Batch)`] event.
  pub fn batch<R: RngCore + CryptoRng>(rng: &mut R) -> Event {
    let network = random_external_network_id(rng);
    let publishing_session = Session(rng.next_u32());
    let id = rng.next_u32();
    let external_network_block_hash = random_block_hash(rng);
    let in_instructions_hash: [u8; 32] = {
      let mut h = [0u8; 32];
      rng.fill_bytes(&mut h);
      h
    };

    let num_results = usize::try_from(rng.next_u64() % 20).unwrap();
    let mut bits = Bv::with_capacity(num_results);
    for _ in 0 .. num_results {
      bits.push(rng.next_u64() % 2 == 0);
    }

    events::in_instructions::batch(
      network,
      publishing_session,
      id,
      external_network_block_hash,
      in_instructions_hash,
      serai_primitives::BitVec::<
        { serai_abi::in_instructions::IN_INSTRUCTION_RESULTS_BOUND },
      >::try_from(bits)
      .unwrap(),
    )
  }
}
