//! Random event, state, and block generator for fuzz testing.

use std::collections::HashMap;

use rand_core::{OsRng, RngCore};

use serai_abi::{
  Event, validator_sets,
  primitives::{
    address::SeraiAddress,
    crypto::KeyPair,
    network_id::{ExternalNetworkId, NetworkId},
    validator_sets::{ExternalValidatorSet, KeyShares, Session, ValidatorSet},
  },
};
use serai_primitives::test_helpers::{
  random_external_address, random_external_key, random_keypair, random_serai_address,
};

use crate::test_helpers::*;

/// Random event, state, and block generator.
pub struct EventFuzzer {
  /// Available validator addresses.
  pub validators: Vec<SeraiAddress>,
  /// All networks.
  networks: Vec<NetworkId>,
  /// Running stake ledger: `(network, validator) -> accumulated_stake`.
  stakes: HashMap<(ExternalNetworkId, SeraiAddress), u64>,
  /// Sets that have been decided but have not yet set their keys.
  pending_keys: HashMap<ExternalValidatorSet, Vec<SeraiAddress>>,
  /// Next session number per network.
  pub next_session: HashMap<ExternalNetworkId, u32>,
  /// Keypairs indexed by public key bytes, for signing cosigns.
  pub keypairs: HashMap<[u8; 32], schnorrkel::Keypair>,
}

impl EventFuzzer {
  pub fn new() -> Self {
    // OsRng.next_u64() % 17 = 0..16, + 4 means from 4..20 validators per test
    let num_validators = usize::try_from((OsRng.next_u64() % 17) + 4).unwrap();

    let validators: Vec<SeraiAddress> =
      (0 .. num_validators).map(|_| random_serai_address(&mut OsRng)).collect();

    let networks: Vec<NetworkId> = NetworkId::all().collect();

    Self {
      validators,
      networks,
      stakes: HashMap::new(),
      pending_keys: HashMap::new(),
      next_session: HashMap::new(),
      keypairs: HashMap::new(),
    }
  }

  /// Pick a random element from a slice.
  fn pick<'a, T>(&mut self, slice: &'a [T]) -> &'a T {
    let i = OsRng.next_u64() % u64::try_from(slice.len()).unwrap();
    &slice[usize::try_from(i).unwrap()]
  }

  /// Generate a random amount using a weighted distribution.
  fn random_amount(&mut self) -> u64 {
    match OsRng.next_u64() % 100 {
      0 ..= 24 => (OsRng.next_u64() % 10) + 1,
      25 ..= 59 => (OsRng.next_u64() % 990) + 11,
      60 ..= 84 => (OsRng.next_u64() % 99_000) + 1_001,
      _ => (OsRng.next_u64() % 9_900_000) + 100_001,
    }
  }

  /// Generate a random allocation event.
  fn random_allocation(&mut self) -> Event {
    let validator = *self.pick(&self.validators.clone());
    let network = *self.pick(&self.networks.clone());
    let amount = self.random_amount();
    if let Ok(ext) = ExternalNetworkId::try_from(network) {
      *self.stakes.entry((ext, validator)).or_default() += amount;
    }
    allocation_event(validator, network, amount)
  }

  /// Generate a random deallocation event. Returns `None` if no validator has stake.
  fn random_deallocation(&mut self) -> Option<Event> {
    // ~25% chance of generating a Serai deallocation
    if OsRng.next_u64() % 4 == 0 {
      let validator = *self.pick(&self.validators.clone());
      let amount = self.random_amount();
      return Some(deallocation_event(validator, NetworkId::Serai, amount));
    }

    let candidates: Vec<((ExternalNetworkId, SeraiAddress), u64)> = self
      .stakes
      .iter()
      .filter(|(_v, &stake)| stake > 0)
      .map(|(&validator, &stake)| (validator, stake))
      .collect();
    if candidates.is_empty() {
      return None;
    }
    let &((network, validator), current_stake) = self.pick(&candidates);
    // Use weighted amount, clamped to current_stake so we don't underflow
    let amount = self.random_amount().min(current_stake).max(1);
    *self.stakes.entry((network, validator)).or_default() -= amount;
    Some(deallocation_event(validator, NetworkId::External(network), amount))
  }

  /// Generate a random SetDecided event.
  fn random_set_decided(&mut self) -> Option<Event> {
    let external_networks: Vec<ExternalNetworkId> =
      self.networks.iter().copied().filter_map(|n| ExternalNetworkId::try_from(n).ok()).collect();
    let network = *self.pick(&external_networks);
    let session_num = *self.next_session.entry(network).or_insert(0);
    let set = ExternalValidatorSet { network, session: Session(session_num) };

    // Don't double-decide a set that's already pending keys
    if self.pending_keys.contains_key(&set) {
      return None;
    }

    // Pick 1..=min(3, validators.len()) random validators for this set
    let max_count = self.validators.len().min(3);
    let count =
      usize::try_from((OsRng.next_u64() % u64::try_from(max_count).unwrap()) + 1).unwrap();

    // Shuffle-pick by swapping from a clone
    let mut pool = self.validators.clone();
    let mut chosen = Vec::with_capacity(count);
    for _ in 0 .. count {
      let i = usize::try_from(OsRng.next_u64() % u64::try_from(pool.len()).unwrap()).unwrap();
      chosen.push(pool.swap_remove(i));
    }

    self.pending_keys.insert(set, chosen.clone());

    let validators_with_shares: Vec<(SeraiAddress, KeyShares)> =
      chosen.into_iter().map(|v| (v, KeyShares::ONE)).collect();

    Some(set_decided_event(
      ValidatorSet { network: NetworkId::External(network), session: Session(session_num) },
      validators_with_shares,
    ))
  }

  /// Generate a random SetKeys event for a pending (decided but not yet keyed) set.
  fn random_set_keys(&mut self) -> Option<Event> {
    if self.pending_keys.is_empty() {
      return None;
    }

    let keys: Vec<ExternalValidatorSet> = self.pending_keys.keys().copied().collect();
    let i = usize::try_from(OsRng.next_u64() % u64::try_from(keys.len()).unwrap()).unwrap();
    let set = keys[i];
    // Remove from pending
    self.pending_keys.remove(&set);

    // Advance session for this network so the next SetDecided gets session+1
    *self.next_session.entry(set.network).or_insert(0) += 1;

    let (keypair, public) = random_keypair(&mut OsRng);
    self.keypairs.insert(public.0, keypair);
    let external_key = random_external_key(&mut OsRng);
    let key_pair = KeyPair(public, external_key);

    Some(Event::ValidatorSets(validator_sets::Event::SetKeys { set, key_pair }))
  }

  /// Generate a random BurnWithInstruction event.
  fn random_burn(&mut self) -> Event {
    burn_with_instruction_event(
      random_serai_address(&mut OsRng),
      random_external_address(&mut OsRng),
      self.random_amount(),
    )
  }

  /// Generate random events for a single block.
  fn generate_block_events(&mut self) -> Vec<Vec<Event>> {
    let num_events = OsRng.next_u64() % 8; // 0..=7 events per block
    if num_events == 0 {
      return vec![];
    }

    let mut alloc_count = 0u64;
    let mut dealloc_count = 0u64;
    let mut set_decided_count = 0u64;
    let mut set_keys_count = 0u64;
    let mut burn_count = 0u64;

    for _ in 0 .. num_events {
      match OsRng.next_u64() % 100 {
        0 ..= 35 => alloc_count += 1,
        36 ..= 55 => dealloc_count += 1,
        56 ..= 70 => set_decided_count += 1,
        71 ..= 85 => set_keys_count += 1,
        86 ..= 99 => burn_count += 1,
        _ => unreachable!(),
      }
    }

    let mut events = Vec::new();

    for _ in 0 .. alloc_count {
      events.push(self.random_allocation());
    }
    for _ in 0 .. dealloc_count {
      if let Some(e) = self.random_deallocation() {
        events.push(e);
      }
    }
    for _ in 0 .. set_decided_count {
      if let Some(e) = self.random_set_decided() {
        events.push(e);
      }
    }
    for _ in 0 .. set_keys_count {
      if let Some(event) = self.random_set_keys() {
        events.push(event);
      }
    }
    for _ in 0 .. burn_count {
      events.push(self.random_burn());
    }

    // Shuffle the events to test order-independence
    for i in (1 .. events.len()).rev() {
      let j = usize::try_from(OsRng.next_u64() % u64::try_from(i + 1).unwrap()).unwrap();
      events.swap(i, j);
    }

    if events.is_empty() {
      vec![]
    } else {
      vec![events]
    }
  }

  /// Generate multiple blocks of random events.
  pub fn generate_blocks(&mut self, count: usize) -> Vec<Vec<Vec<Event>>> {
    let mut blocks = Vec::with_capacity(count);
    for _ in 0 .. count {
      blocks.push(self.generate_block_events());
    }
    blocks
  }
}
