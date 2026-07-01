//! Random event, state, and block generator for fuzz testing.

use std::collections::{HashMap, HashSet};

use rand_core::{CryptoRng, RngCore};

use serai_abi::{
  primitives::{
    address::SeraiAddress,
    crypto::{EmbeddedEllipticCurveKeys, KeyPair},
    network_id::{ExternalNetworkId, NetworkId},
    validator_sets::{ExternalValidatorSet, KeyShares, Session, Slash, ValidatorSet},
    test_helpers::{
      random_embedded_elliptic_curve_keys, random_external_address, random_external_network_key,
      random_schnorrkel_keypair, random_serai_address, random_serai_addresses, random_block_hash,
      all_networks, all_external_networks,
    },
  },
  validator_sets, Event,
};
use bitvec::vec::BitVec as Bv;

use crate::{
  events,
  test_helpers::{pick, random_amount},
};

/// Random event, state, and block generator.
pub struct BlockEventsFuzzer<R: RngCore + CryptoRng> {
  /// The random number generator used for all random choices.
  pub rng: R,
  /// Available validator addresses.
  pub validators: Vec<SeraiAddress>,
  /// Running stake ledger: `(network, validator) -> accumulated_stake`.
  stakes: HashMap<(NetworkId, SeraiAddress), u64>,
  /// Sets that have been decided but have not yet set their keys.
  pending_keys: HashMap<ExternalValidatorSet, Vec<SeraiAddress>>,
  /// Next session number per network.
  pub next_session: HashMap<ExternalNetworkId, u32>,
  /// Keypairs indexed by public key bytes, for signing cosigns.
  pub keypairs: HashMap<[u8; 32], schnorrkel::Keypair>,
  /// Networks that have already received a Batch event this block.
  batches_this_block: HashSet<ExternalNetworkId>,
  /// Next batch ID per network (increments by 1 per batch).
  batch_ids: HashMap<ExternalNetworkId, u32>,
  /// Cached auxiliary keys per (network, validator) - stable across sessions so that every
  /// SetEmbeddedEllipticCurveKeys event for the same pair always carries the same key value,
  /// keeping the DB consistent with historical events. Uses `NetworkId` to handle both
  /// external and Serai networks uniformly.
  auxiliary_key_cache: HashMap<(NetworkId, SeraiAddress), EmbeddedEllipticCurveKeys>,
  /// Sets that have completed keygen (SetKeys was received), eligible for AcceptedHandover.
  keyed_networks: Vec<ExternalNetworkId>,
  /// Serai sessions that have been decided, eligible for a Serai AcceptedHandover.
  completed_serai_sessions: Vec<u32>,
}

impl<R: RngCore + CryptoRng> BlockEventsFuzzer<R> {
  /// Create a new [`BlockEventsFuzzer`]
  pub fn new(mut rng: R) -> Self {
    // By default picks 4 validators in a test (3 honest + 1 faulty)
    let num_validators = 4;
    serai_env::log::debug!("[MOCK_SERAI] starting with {num_validators} validators");
    let initial_validators = random_serai_addresses(&mut rng, num_validators);

    Self {
      rng,
      validators: initial_validators,
      stakes: HashMap::new(),
      pending_keys: HashMap::new(),
      next_session: HashMap::new(),
      keypairs: HashMap::new(),
      batches_this_block: HashSet::new(),
      batch_ids: HashMap::new(),
      auxiliary_key_cache: HashMap::new(),
      keyed_networks: Vec::new(),
      completed_serai_sessions: Vec::new(),
    }
  }

  /// Create a new [`BlockEventsFuzzer`] with a given num of validators.
  pub fn new_with_validators(mut rng: R, num_validators: usize) -> Self {
    let initial_validators = random_serai_addresses(&mut rng, num_validators);

    Self {
      rng,
      validators: initial_validators,
      stakes: HashMap::new(),
      pending_keys: HashMap::new(),
      next_session: HashMap::new(),
      keypairs: HashMap::new(),
      batches_this_block: HashSet::new(),
      batch_ids: HashMap::new(),
      auxiliary_key_cache: HashMap::new(),
      keyed_networks: Vec::new(),
      completed_serai_sessions: Vec::new(),
    }
  }

  /// Create a new fuzzer seeding extra validators into the pool.
  pub fn new_with_extra_validators(
    mut rng: R,
    num_validators: usize,
    extra_validators: &[SeraiAddress],
  ) -> Self {
    let mut initial_validators = random_serai_addresses(&mut rng, num_validators);
    initial_validators.extend_from_slice(extra_validators);

    Self {
      rng,
      validators: initial_validators,
      stakes: HashMap::new(),
      pending_keys: HashMap::new(),
      next_session: HashMap::new(),
      keypairs: HashMap::new(),
      batches_this_block: HashSet::new(),
      batch_ids: HashMap::new(),
      auxiliary_key_cache: HashMap::new(),
      keyed_networks: Vec::new(),
      completed_serai_sessions: Vec::new(),
    }
  }

  /// Generate a random allocation event.
  fn random_allocation(&mut self) -> Event {
    let validator = *pick(&mut self.rng, &self.validators.clone());
    let network = *pick(&mut self.rng, &all_networks());
    let amount = random_amount(&mut self.rng);
    if let Ok(external_network) = ExternalNetworkId::try_from(network) {
      *self.stakes.entry((NetworkId::External(external_network), validator)).or_default() += amount;
    }
    events::validator_sets::allocation(validator, network, amount)
  }

  /// Generate a random deallocation event. Returns `None` if no validator has stake.
  /// But if no validator has stake it has a 50/50 chance to generate a 0 amount deallocation.
  fn random_deallocation(&mut self) -> Option<Event> {
    let candidates: Vec<((NetworkId, SeraiAddress), u64)> = self
      .stakes
      .iter()
      .filter(|(_v, &stake)| stake > 0)
      .map(|(&validator, &stake)| (validator, stake))
      .collect();
    if candidates.is_empty() {
      // Coin flip: 50% chance to create a 0-amount deallocation with a random
      // validator and network, even when no validator has live stake.
      if self.rng.next_u64() % 2 == 0 {
        let validator = *pick(&mut self.rng, &self.validators);
        let network = *pick(&mut self.rng, &all_networks());
        return Some(events::validator_sets::deallocation(validator, network, 0));
      }
      return None;
    }

    let &((network, validator), current_stake) = pick(&mut self.rng, &candidates);
    // Use weighted amount, clamped to current_stake so we don't underflow
    let amount = random_amount(&mut self.rng).min(current_stake);
    *self.stakes.entry((network, validator)).or_default() -= amount;
    Some(events::validator_sets::deallocation(validator, network, amount))
  }

  /// Generate a SetDecided event.
  /// Returns an empty vec if an external set for the chosen network is already pending keys.
  fn random_set_decided(&mut self) -> Option<Event> {
    let network = *pick(&mut self.rng, &all_external_networks());
    let session_num = *self.next_session.entry(network).or_insert(0);
    let set = ExternalValidatorSet { network, session: Session(session_num) };

    // Don't double-decide a set that's already pending keys
    if self.pending_keys.contains_key(&set) {
      return None;
    }

    let max_count = self.validators.len().min(3);
    let count =
      usize::try_from((self.rng.next_u64() % u64::try_from(max_count).unwrap()) + 1).unwrap();

    // Shuffle-pick by swapping from a clone
    let mut pool = self.validators.clone();
    let mut chosen = Vec::with_capacity(count);
    for _ in 0 .. count {
      let i = usize::try_from(self.rng.next_u64() % u64::try_from(pool.len()).unwrap()).unwrap();
      chosen.push(pool.swap_remove(i));
    }

    self.pending_keys.insert(set, chosen.clone());

    let validators_with_shares: Vec<(SeraiAddress, KeyShares)> =
      chosen.into_iter().map(|v| (v, KeyShares::ONE)).collect();

    // Advance next session number
    *self.next_session.entry(network).or_insert(0) += 1;

    Some(events::validator_sets::set_decided(
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
    let i = usize::try_from(self.rng.next_u64() % u64::try_from(keys.len()).unwrap()).unwrap();
    let set = keys[i];
    // Remove from pending
    self.pending_keys.remove(&set);

    // Advance session for this network so the next SetDecided gets session+1
    *self.next_session.entry(set.network).or_insert(0) += 1;

    let (keypair, public) = random_schnorrkel_keypair(&mut self.rng);
    self.keypairs.insert(public.0, keypair);
    let external_key = random_external_network_key(&mut self.rng);
    let key_pair = KeyPair(public, external_key);

    self.keyed_networks.push(set.network);
    Some(Event::ValidatorSets(validator_sets::Event::SetKeys { set, key_pair }))
  }

  /// Generate a standalone `SetEmbeddedEllipticCurveKeys` for a random validator on any network,
  /// including `NetworkId::Serai`. Uses the key cache so repeated events for the same
  /// (network, validator) pair always carry the same key value.
  fn random_embedded_key_event(&mut self) -> Event {
    let validator = *pick(&mut self.rng, &self.validators.clone());

    // Pick uniformly from all networks (Serai + external).
    let network = *pick(&mut self.rng, &all_networks());

    let keys = *self
      .auxiliary_key_cache
      .entry((network, validator))
      .or_insert_with(|| random_embedded_elliptic_curve_keys(&mut self.rng, network));

    Event::ValidatorSets(validator_sets::Event::SetEmbeddedEllipticCurveKeys { validator, keys })
  }

  /// Generate a random BurnWithInstruction event.
  pub fn random_burn(&mut self) -> Event {
    events::coins::burn_with_instruction(
      random_serai_address(&mut self.rng),
      random_external_address(&mut self.rng),
      random_amount(&mut self.rng),
    )
  }

  /// Generate a random Batch event.
  pub fn random_batch(&mut self) -> Option<Event> {
    // Only produce batches for networks that have at least one active session
    let eligible: Vec<ExternalNetworkId> =
      all_external_networks().into_iter().filter(|n| self.keyed_networks.contains(n)).collect();
    if eligible.is_empty() {
      return None;
    }

    let network = *pick(&mut self.rng, &eligible);
    if self.batches_this_block.contains(&network) {
      return None;
    }
    self.batches_this_block.insert(network);

    // Use the last keyed session as the publishing session
    let publishing_session = self.next_session.get(&network).copied().unwrap_or(0);
    let id = self.batch_ids.entry(network).and_modify(|id| *id += 1).or_insert(0);

    let num_results = usize::try_from(self.rng.next_u64() % 20).unwrap();
    let mut bits = Bv::with_capacity(num_results);
    for _ in 0 .. num_results {
      bits.push(self.rng.next_u64() % 2 == 0);
    }

    Some(events::in_instructions::batch(
      network,
      Session(publishing_session),
      *id,
      random_block_hash(&mut self.rng),
      random_block_hash(&mut self.rng).0,
      serai_primitives::BitVec::try_from(bits).unwrap(),
    ))
  }

  /// Generate a random Slashes event for an external network set that has set its keys.
  /// Also produces an AcceptedHandover event for the same set.
  pub fn random_slash_report(&mut self) -> Option<(Event, Event)> {
    // Find networks that have at least one session completed (keys have been set)
    let eligible: Vec<ExternalNetworkId> =
      all_external_networks().into_iter().filter(|n| self.keyed_networks.contains(n)).collect();
    if eligible.is_empty() {
      return None;
    }

    let network = *pick(&mut self.rng, &eligible);
    // Session is the most recently keyed session for this network
    let session_num = self.next_session.get(&network).copied().unwrap_or(0);
    let set = ExternalValidatorSet { network, session: Session(session_num) };

    // Build a random SlashReport
    let num_slashes = usize::try_from(self.rng.next_u64() % 4).unwrap() + 1; // 1..=4
    let mut slashes = Vec::with_capacity(num_slashes);
    for _ in 0 .. num_slashes {
      slashes.push(if (self.rng.next_u64() % 4) == 0 {
        Slash::Fatal
      } else {
        Slash::Points(self.rng.next_u32() % 100_000)
      });
    }

    let handover = Event::ValidatorSets(validator_sets::Event::AcceptedHandover {
      set: ValidatorSet { network: NetworkId::External(set.network), session: set.session },
    });

    Some((events::validator_sets::slash_report(set), handover))
  }

  /// Generate random events for a single block.
  fn generate_random_block_events_inner(&mut self) -> Vec<Event> {
    // New blocks, reset network batch counter
    self.batches_this_block.clear();

    let num_events = self.rng.next_u64() % 8; // 0..=7 events per block
    if num_events == 0 {
      return vec![];
    }

    let mut alloc_count = 0u64;
    let mut dealloc_count = 0u64;
    let mut set_decided_count = 0u64;
    let mut set_keys_count = 0u64;
    let mut burn_count = 0u64;
    let mut batch_count = 0u64;
    let mut slash_report_count = 0u64;
    let mut embedded_key_count = 0u64;

    for _ in 0 .. num_events {
      match self.rng.next_u64() % 8 {
        0 => alloc_count += 1,
        1 => dealloc_count += 1,
        2 => set_decided_count += 1,
        3 => set_keys_count += 1,
        4 => burn_count += 1,
        5 => batch_count += 1,
        6 => slash_report_count += 1,
        7 => embedded_key_count += 1,
        _ => unreachable!(),
      }
    }

    let mut events = Vec::new();

    // Emit SetEmbeddedEllipticCurveKeys for ALL validators on ALL networks FIRST.
    // This upholds the chain invariant that every validator must have auxiliary keys set
    // before any event (allocation, set_decided, batch, etc.) that references them.
    //
    // If the pair is new (never before seen), always emit. If already cached, only emit
    // with 50% probability to allow occasional key rotations without spamming every block.
    for &network in &all_networks() {
      for &validator in &self.validators {
        let is_new = !self.auxiliary_key_cache.contains_key(&(network, validator));
        if is_new || self.rng.next_u64() % 2 == 0 {
          let keys = *self
            .auxiliary_key_cache
            .entry((network, validator))
            .or_insert_with(|| random_embedded_elliptic_curve_keys(&mut self.rng, network));
          events.push(Event::ValidatorSets(validator_sets::Event::SetEmbeddedEllipticCurveKeys {
            validator,
            keys,
          }));
        }
      }
    }

    // Generate other events that reference validators
    for _ in 0 .. alloc_count {
      events.push(self.random_allocation());
    }
    for _ in 0 .. dealloc_count {
      if let Some(e) = self.random_deallocation() {
        events.push(e);
      }
    }
    for _ in 0 .. set_decided_count {
      if let Some(event) = self.random_set_decided() {
        events.push(event);
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
    for _ in 0 .. batch_count {
      if let Some(event) = self.random_batch() {
        events.push(event);
      }
    }
    for _ in 0 .. slash_report_count {
      if let Some((slash_event, handover_event)) = self.random_slash_report() {
        events.push(slash_event);
        events.push(handover_event);
      }
    }
    for _ in 0 .. embedded_key_count {
      events.push(self.random_embedded_key_event());
    }

    for i in (1 .. events.len()).rev() {
      let j = usize::try_from(self.rng.next_u64() % u64::try_from(i + 1).unwrap()).unwrap();
      events.swap(i, j);
    }

    events
  }

  /// Generate a single block of fully random events (all types available).
  fn generate_full_random_block(&mut self) -> Vec<Vec<Event>> {
    vec![self.generate_random_block_events_inner()]
  }

  /// Generate Block 0.
  ///
  /// Produces exactly:
  ///   1. SetEmbeddedEllipticCurveKeys for every validator on every network
  ///   2. SetDecided for Serai s0, Bitcoin s0, Ethereum s0, Monero s0, Serai s1
  ///   3. AcceptedHandover for Serai s0
  fn genesis_block(&mut self) -> Vec<Vec<Event>> {
    let mut events = Vec::new();

    // 1. SetEmbeddedEllipticCurveKeys for every validator on every network
    for &network in &all_networks() {
      for &validator in &self.validators {
        let keys = *self
          .auxiliary_key_cache
          .entry((network, validator))
          .or_insert_with(|| random_embedded_elliptic_curve_keys(&mut self.rng, network));
        events.push(Event::ValidatorSets(validator_sets::Event::SetEmbeddedEllipticCurveKeys {
          validator,
          keys,
        }));
      }
    }

    // 2. SetDecided for each network (session 0) plus an extra Serai session 1
    let all_validators_shares: Vec<(SeraiAddress, KeyShares)> =
      self.validators.iter().map(|&v| (v, KeyShares::ONE)).collect();

    for network in all_networks() {
      events.push(events::validator_sets::set_decided(
        ValidatorSet { network, session: Session(0) },
        all_validators_shares.clone(),
      ));

      // Track external network state: mark session 0 as pending keys,
      // set next_session to 1 for the next decision.
      if let Ok(external) = ExternalNetworkId::try_from(network) {
        let set = ExternalValidatorSet { network: external, session: Session(0) };
        self.pending_keys.insert(set, self.validators.clone());
        self.next_session.insert(external, 1);
      }
    }

    // Serai session 1
    events.push(events::validator_sets::set_decided(
      ValidatorSet { network: NetworkId::Serai, session: Session(1) },
      all_validators_shares.clone(),
    ));

    // 3. AcceptedHandover for Serai session 0
    events.push(Event::ValidatorSets(validator_sets::Event::AcceptedHandover {
      set: ValidatorSet { network: NetworkId::Serai, session: Session(0) },
    }));

    // Track Serai session 1 as awaiting handover acceptance
    // (session 0 was already accepted above, so don't add it)
    self.completed_serai_sessions.push(1);

    vec![events]
  }

  /// Generate a bootstrap block.
  ///
  /// Forces a SetKeys for all pending external sets (from genesis).
  fn generate_bootstrap_block(&mut self) -> Vec<Vec<Event>> {
    let mut events = Vec::new();

    // 1. SetEmbeddedEllipticCurveKeys
    for &network in &all_networks() {
      for &validator in &self.validators {
        if !self.auxiliary_key_cache.contains_key(&(network, validator)) {
          let keys = *self
            .auxiliary_key_cache
            .entry((network, validator))
            .or_insert_with(|| random_embedded_elliptic_curve_keys(&mut self.rng, network));
          events.push(Event::ValidatorSets(validator_sets::Event::SetEmbeddedEllipticCurveKeys {
            validator,
            keys,
          }));
        }
      }
    }

    // 2. Allocate stake to external-network validators before the forced SetKeys.
    {
      let pending_sets: Vec<ExternalValidatorSet> = self.pending_keys.keys().copied().collect();
      for &set in &pending_sets {
        let validators = self.pending_keys[&set].clone();
        for &validator in &validators {
          let amount = random_amount(&mut self.rng);
          *self.stakes.entry((NetworkId::External(set.network), validator)).or_default() += amount;
          events.push(events::validator_sets::allocation(
            validator,
            NetworkId::External(set.network),
            amount,
          ));
        }
      }
    }

    // 3. SetKeys.
    let pending: Vec<ExternalValidatorSet> = self.pending_keys.keys().copied().collect();
    for &set in &pending {
      self.pending_keys.remove(&set);

      let (keypair, public) = random_schnorrkel_keypair(&mut self.rng);
      self.keypairs.insert(public.0, keypair);
      let external_key = random_external_network_key(&mut self.rng);
      let key_pair = KeyPair(public, external_key);

      events.push(Event::ValidatorSets(validator_sets::Event::SetKeys { set, key_pair }));
    }

    vec![events]
  }

  /// Generate `count` blocks of random events.
  pub fn generate_blocks(&mut self, count: usize) -> Vec<Vec<Vec<Event>>> {
    let mut blocks = Vec::with_capacity(count);
    for _ in 0 .. count {
      blocks.push(self.generate_full_random_block());
    }
    blocks
  }

  /// Generate `count` blocks, starting with a forced keygen sequence (3 blocks)
  /// to guarantee at least one global session forms, followed by random blocks.
  pub fn generate_blocks_with_keygen(&mut self, count: u64) -> Vec<Vec<Vec<Event>>> {
    assert!(count >= 4, "need at least 4 block for genesis");

    let mut blocks = Vec::with_capacity(usize::try_from(count).unwrap());

    blocks.push(self.genesis_block());

    for block_idx in 1 .. count {
      if block_idx == 1 {
        blocks.push(self.generate_bootstrap_block());
      } else {
        blocks.push(self.generate_full_random_block());
      }
    }

    blocks
  }
}
