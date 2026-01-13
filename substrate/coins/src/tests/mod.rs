#![expect(clippy::as_conversions, clippy::same_name_method)]

use std::{
  sync::{Mutex, LazyLock},
  collections::HashMap,
};

use scale::{Encode as _, DecodeAll as _};
use sp_core::{Pair as _, sr25519::Pair};

use frame_support::{weights::Weight, derive_impl, construct_runtime};

use serai_abi::{
  primitives::{coin::*, balance::*, address::*, instructions::*},
  TransactionContext as _,
};

use crate::{self as coins, CoinsInstance, LiquidityTokensInstance, GenesisLiquidityTokensInstance};

mod clippy;
mod mint;
mod burn;
mod transfer;

construct_runtime!(
  pub enum Test
  {
    System: frame_system,
    Timestamp: pallet_timestamp,
    Core: serai_core_pallet,
    Coins: coins::<CoinsInstance>,
    LiquidityTokens: coins::<LiquidityTokensInstance>,
    GenesisLiquidityTokens: coins::<GenesisLiquidityTokensInstance>,
  }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
  type AccountId = SeraiAddress;
  type Lookup = frame_support::sp_runtime::traits::IdentityLookup<Self::AccountId>;
  type Block = frame_system::mocking::MockBlock<Test>;
  type BlockLength = serai_core_pallet::Limits;
  type BlockWeights = serai_core_pallet::Limits;
}

impl From<serai_abi::Call> for RuntimeCall {
  fn from(_call: serai_abi::Call) -> Self {
    unimplemented!();
  }
}

#[derive_impl(pallet_timestamp::config_preludes::TestDefaultConfig)]
impl pallet_timestamp::Config for Test {}

impl serai_core_pallet::Config for Test {
  const PROTOCOL_ID: [u8; 32] = [0; 32];
  const SIGNATURE_VERIFICATION_WEIGHT: Weight = Weight::zero();
  type PreInherents = ();
}

static ALLOW_MINT: LazyLock<Mutex<bool>> = LazyLock::new(|| Mutex::new(true));
/// An `AllowMint` for testing purposes which defers to a static value.
///
/// This is unsound in any multi-threaded context and generally a bad idea. It is here solely for
/// testing.
pub struct StaticAllowMint;
impl crate::AllowMint for StaticAllowMint {
  fn is_allowed(_balance: &Balance) -> bool {
    *ALLOW_MINT.lock().unwrap()
  }
}

impl crate::Config<CoinsInstance> for Test {
  type AllowMint = crate::AlwaysAllowMint;
}
impl crate::Config<LiquidityTokensInstance> for Test {
  type AllowMint = crate::AlwaysAllowMint;
}
// We use `GenesisLiquidityTokens` to test `AllowMint`
impl crate::Config<GenesisLiquidityTokensInstance> for Test {
  type AllowMint = StaticAllowMint;
}

pub(crate) fn new_test_ext(coins: Vec<(SeraiAddress, Balance)>) -> sp_io::TestExternalities {
  let mut externalities = sp_io::TestExternalities::new_empty();
  externalities.execute_with(|| {
    let system = frame_system::GenesisConfig::<Test>::default();
    let coins = crate::GenesisConfig::<Test, CoinsInstance> {
      accounts: coins,
      _instance: Default::default(),
    };
    let liquidity_tokens = crate::GenesisConfig::<Test, LiquidityTokensInstance> {
      accounts: vec![],
      _instance: Default::default(),
    };
    let genesis_liquidity_tokens = crate::GenesisConfig::<Test, GenesisLiquidityTokensInstance> {
      accounts: vec![],
      _instance: Default::default(),
    };
    Core::genesis(&RuntimeGenesisConfig {
      system,
      coins,
      liquidity_tokens,
      genesis_liquidity_tokens,
    });
  });
  externalities
}

/// A representation of the state for testing purposes.
///
/// This serves as the primary harness for testing the logic implemented. It not only tracks the
/// expected state but also asserts the equivalency of the state to the expected state. The literal
/// tests primarily orchestrate flows to be tested via this harness.
///
/// The tests themselves may still have assertions present, as part of sanity (and to be robust
/// against the harness being faulty), but they are expected to primarily defer to this for all
/// expected checks.
struct State(HashMap<Vec<u8>, HashMap<(SeraiAddress, Coin), Amount>>, Vec<serai_abi::Event>);
impl State {
  fn pallet<I: 'static>() -> Vec<u8> {
    let instance = core::any::TypeId::of::<I>();
    if instance == core::any::TypeId::of::<CoinsInstance>() {
      b"Coins".to_vec()
    } else if instance == core::any::TypeId::of::<LiquidityTokensInstance>() {
      b"LiquidityTokens".to_vec()
    } else if instance == core::any::TypeId::of::<GenesisLiquidityTokensInstance>() {
      b"GenesisLiquidityTokens".to_vec()
    } else {
      panic!("unrecognized instance")
    }
  }

  fn new() -> Self {
    Self(
      [
        (Self::pallet::<CoinsInstance>(), HashMap::new()),
        (Self::pallet::<LiquidityTokensInstance>(), HashMap::new()),
        (Self::pallet::<GenesisLiquidityTokensInstance>(), HashMap::new()),
      ]
      .into_iter()
      .collect(),
      vec![],
    )
  }

  fn supply_root_key(pallet: &[u8]) -> Vec<u8> {
    [sp_core::twox_128(pallet).as_slice(), sp_core::twox_128(b"Supply").as_slice()].concat()
  }

  fn balances_root_key(pallet: &[u8]) -> Vec<u8> {
    [sp_core::twox_128(pallet).as_slice(), sp_core::twox_128(b"Balances").as_slice()].concat()
  }

  fn length_of_map(root_key: &[u8]) -> usize {
    let mut last_key = root_key.to_vec();
    let mut res = 0;
    while {
      let next_key = sp_io::storage::next_key(&last_key).unwrap_or(vec![]);
      let in_map = next_key.starts_with(root_key);
      last_key = next_key;
      in_map
    } {
      res += 1;
    }
    res
  }

  /// Compare the state to the current storage.
  fn verify(&self) {
    // First, we verify the `Balances` map while calculating what `Supply` should look like
    let mut supplies = HashMap::new();
    for (pallet, balances) in &self.0 {
      assert_eq!(Self::length_of_map(&Self::balances_root_key(pallet)), balances.len());

      let mut pallet_supplies = HashMap::new();
      for ((address, coin), amount) in balances {
        let amount = *amount;

        // Check with the typed function
        if pallet == &Self::pallet::<CoinsInstance>() {
          assert_eq!(Coins::balance(address, coin), amount);
        } else if pallet == &Self::pallet::<LiquidityTokensInstance>() {
          assert_eq!(LiquidityTokens::balance(address, coin), amount);
        } else if pallet == &Self::pallet::<GenesisLiquidityTokensInstance>() {
          assert_eq!(GenesisLiquidityTokens::balance(address, coin), amount);
        } else {
          panic!("unrecognized instance")
        }

        // Check the underlying storage
        let stored_amount = Amount::decode_all(
          &mut sp_io::storage::get(
            &[
              Self::balances_root_key(pallet).as_slice(),
              (sp_core::blake2_128(&address.0), address, coin).encode().as_slice(),
            ]
            .concat(),
          )
          .unwrap()
          .as_ref(),
        )
        .unwrap();
        assert_eq!(amount, stored_amount);

        let supply = pallet_supplies.entry(coin).or_insert(Amount(0));
        *supply = (*supply + amount).unwrap();
      }
      supplies.insert(pallet, pallet_supplies);
    }

    // Then we verify the `Supply` map
    for (pallet, supplies) in supplies {
      assert_eq!(supplies.len(), Self::length_of_map(&Self::supply_root_key(pallet)));
      for (coin, supply) in supplies {
        if pallet == &Self::pallet::<CoinsInstance>() {
          assert_eq!(Coins::supply(coin), supply);
        } else if pallet == &Self::pallet::<LiquidityTokensInstance>() {
          assert_eq!(LiquidityTokens::supply(coin), supply);
        } else if pallet == &Self::pallet::<GenesisLiquidityTokensInstance>() {
          assert_eq!(GenesisLiquidityTokens::supply(coin), supply);
        } else {
          panic!("unrecognized instance")
        }

        let stored_supply = Amount::decode_all(
          &mut sp_io::storage::get(
            &[Self::supply_root_key(pallet).as_slice(), coin.encode().as_slice()].concat(),
          )
          .unwrap()
          .as_ref(),
        )
        .unwrap();
        assert_eq!(supply, stored_supply);
      }
    }

    // We also verify the emitted events
    let emitted_events = Core::events()
      .iter()
      .flat_map(IntoIterator::into_iter)
      .map(|event| borsh::from_slice::<serai_abi::Event>(event.as_slice()).unwrap())
      .filter(|event| matches!(event, serai_abi::Event::Coins(_)))
      .collect::<Vec<_>>();
    assert_eq!(&emitted_events, &self.1);
  }

  /// Update the state with a mint.
  ///
  /// This will then compare the state to the current storage.
  fn mint<I: 'static>(&mut self, to: SeraiAddress, coins: Balance) {
    let pallet = Self::pallet::<I>();

    // Update our view of the balances
    let balances = self.0.get_mut(&pallet).unwrap();
    let value = balances.entry((to, coins.coin)).or_insert(Amount(0));
    *value = (*value + coins.amount).unwrap();

    // Update our event log
    if core::any::TypeId::of::<I>() == core::any::TypeId::of::<CoinsInstance>() {
      self.1.push((serai_abi::coins::Event::Mint { to, coins }).into());
    }

    self.verify();
  }

  fn burn_internal<I: 'static>(&mut self, from: SeraiAddress, coins: Balance) {
    let pallet = Self::pallet::<I>();

    // Update our view of the balances
    let balances = self.0.get_mut(&pallet).unwrap();
    let value = balances.entry((from, coins.coin)).or_insert(Amount(0));
    *value = (*value - coins.amount).unwrap();

    if *value == Amount(0) {
      balances.remove(&(from, coins.coin));
    }
  }

  /// Update the state with a burn.
  ///
  /// This will then compare the state to the current storage.
  fn burn<I: 'static>(&mut self, from: SeraiAddress, coins: Balance) {
    self.burn_internal::<I>(from, coins);

    // Update our event log
    if core::any::TypeId::of::<I>() == core::any::TypeId::of::<CoinsInstance>() {
      self.1.push((serai_abi::coins::Event::Burn { from, coins }).into());
    }

    self.verify();
  }

  /// Update the state with a burn with instruction.
  ///
  /// This will then compare the state to the current storage.
  fn burn_with_instruction<I: 'static>(
    &mut self,
    from: SeraiAddress,
    instruction: OutInstructionWithBalance,
  ) {
    self.burn_internal::<I>(from, instruction.balance.into());

    // Update our event log
    if core::any::TypeId::of::<I>() == core::any::TypeId::of::<CoinsInstance>() {
      self.1.push((serai_abi::coins::Event::BurnWithInstruction { from, instruction }).into());
    }

    self.verify();
  }

  /// Update the state with a transfer.
  ///
  /// This will then compare the state to the current storage.
  fn transfer<I: 'static>(&mut self, from: SeraiAddress, to: SeraiAddress, coins: Balance) {
    let balances = self.0.get_mut(&Self::pallet::<I>()).unwrap();

    {
      let value = balances.entry((from, coins.coin)).or_insert(Amount(0));
      *value = (*value - coins.amount).unwrap();
      if *value == Amount(0) {
        balances.remove(&(from, coins.coin));
      }
    }

    {
      let value = balances.entry((to, coins.coin)).or_insert(Amount(0));
      *value = (*value + coins.amount).unwrap();
      if *value == Amount(0) {
        balances.remove(&(to, coins.coin));
      }
    }

    // Update our event log
    if core::any::TypeId::of::<I>() == core::any::TypeId::of::<CoinsInstance>() {
      self.1.push((serai_abi::coins::Event::Transfer { from, to, coins }).into());
    }

    self.verify();
  }
}
