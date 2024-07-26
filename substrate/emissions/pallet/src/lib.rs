#![cfg_attr(not(feature = "std"), no_std)]

#[allow(clippy::cast_possible_truncation, clippy::no_effect_underscore_binding, clippy::empty_docs)]
#[frame_support::pallet]
pub mod pallet {
  use super::*;
  use frame_system::pallet_prelude::*;
  use frame_support::{pallet_prelude::*, sp_runtime::SaturatedConversion};

  use sp_std::{vec, vec::Vec, ops::Mul, collections::btree_map::BTreeMap};
  use sp_runtime;

  use coins_pallet::{Config as CoinsConfig, Pallet as Coins, AllowMint};
  use dex_pallet::{Config as DexConfig, Pallet as Dex};

  use validator_sets_pallet::{Pallet as ValidatorSets, Config as ValidatorSetsConfig};
  use genesis_liquidity_pallet::{Pallet as GenesisLiquidity, Config as GenesisLiquidityConfig};

  use serai_primitives::*;
  use validator_sets_primitives::{MAX_KEY_SHARES_PER_SET, Session};
  use emissions_primitives::*;

  #[pallet::config]
  pub trait Config:
    frame_system::Config<AccountId = PublicKey>
    + ValidatorSetsConfig
    + CoinsConfig
    + DexConfig
    + GenesisLiquidityConfig
  {
    type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
  }

  #[pallet::genesis_config]
  #[derive(Clone, PartialEq, Eq, Debug, Encode, Decode)]
  pub struct GenesisConfig<T: Config> {
    /// Networks to spawn Serai with.
    pub networks: Vec<(NetworkId, Amount)>,
    /// List of participants to place in the initial validator sets.
    pub participants: Vec<T::AccountId>,
  }

  impl<T: Config> Default for GenesisConfig<T> {
    fn default() -> Self {
      GenesisConfig { networks: Default::default(), participants: Default::default() }
    }
  }

  #[pallet::error]
  pub enum Error<T> {
    NetworkHasEconomicSecurity,
    NoValueForCoin,
  }

  #[pallet::event]
  pub enum Event<T: Config> {}

  #[pallet::pallet]
  pub struct Pallet<T>(PhantomData<T>);

  #[pallet::storage]
  #[pallet::getter(fn participants)]
  pub(crate) type Participants<T: Config> = StorageMap<
    _,
    Identity,
    NetworkId,
    BoundedVec<(PublicKey, u64), ConstU32<{ MAX_KEY_SHARES_PER_SET }>>,
    OptionQuery,
  >;

  #[pallet::storage]
  #[pallet::getter(fn session)]
  pub type CurrentSession<T: Config> = StorageMap<_, Identity, NetworkId, u32, ValueQuery>;

  #[pallet::storage]
  #[pallet::getter(fn economic_security_reached)]
  pub(crate) type EconomicSecurityReached<T: Config> =
    StorageMap<_, Identity, NetworkId, bool, ValueQuery>;

  #[pallet::storage]
  #[pallet::getter(fn last_swap_volume)]
  pub(crate) type LastSwapVolume<T: Config> = StorageMap<_, Identity, NetworkId, u64, OptionQuery>;

  #[pallet::storage]
  pub(crate) type GenesisCompleteBlock<T: Config> = StorageValue<_, u64, OptionQuery>;

  #[pallet::genesis_build]
  impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
    fn build(&self) {
      for (id, stake) in self.networks.clone() {
        let mut participants = vec![];
        for p in self.participants.clone() {
          participants.push((p, stake.0));
        }
        Participants::<T>::set(id, Some(participants.try_into().unwrap()));
        CurrentSession::<T>::set(id, 0);
        EconomicSecurityReached::<T>::set(id, false);
      }
    }
  }

  #[pallet::hooks]
  impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
    fn on_initialize(n: BlockNumberFor<T>) -> Weight {
      if GenesisCompleteBlock::<T>::get().is_none() &&
        GenesisLiquidity::<T>::genesis_complete().is_some()
      {
        GenesisCompleteBlock::<T>::set(Some(n.saturated_into::<u64>()));
      }

      // we wait 1 extra block after genesis ended to see the changes. We only need this extra
      // block in dev&test networks where we start the chain with accounts that already has some
      // staked SRI. So when we check for ec-security pre-genesis we look like we are economically
      // secure. The reason for this although we only check for it once the genesis is complete(so
      // if the genesis complete we shouldn't be economically secure because the funds are not
      // enough) is because ValidatorSets pallet runs before the genesis pallet in runtime.
      //  So ValidatorSets pallet sees the old state until next block.
      let gcb = GenesisCompleteBlock::<T>::get();
      let genesis_ended = gcb.is_some() && (n.saturated_into::<u64>() > gcb.unwrap());

      // we accept we reached economic security once we can mint smallest amount of a network's coin
      for coin in COINS {
        let check = genesis_ended && !Self::economic_security_reached(coin.network());
        if check && <T as CoinsConfig>::AllowMint::is_allowed(&Balance { coin, amount: Amount(1) })
        {
          EconomicSecurityReached::<T>::set(coin.network(), true);
        }
      }

      // check if we got a new session
      let mut session_changed = false;
      let session = ValidatorSets::<T>::session(NetworkId::Serai).unwrap_or(Session(0));
      if session.0 > Self::session(NetworkId::Serai) {
        session_changed = true;
        CurrentSession::<T>::set(NetworkId::Serai, session.0);
      }

      // update participants per session before the genesis and after the genesis
      // we update them after reward distribution.
      if !genesis_ended && session_changed {
        Self::update_participants();
      }

      // emissions start only after genesis period and happens once per session.
      // so we don't do anything before that time.
      if !(genesis_ended && session_changed) {
        return Weight::zero(); // TODO
      }

      // figure out the amount of blocks in the last session. Session is at least 1
      // if we come here.
      let block_count = ValidatorSets::<T>::session_begin_block(NetworkId::Serai, session) -
        ValidatorSets::<T>::session_begin_block(NetworkId::Serai, Session(session.0 - 1));

      // get total reward for this epoch
      let pre_ec_security = Self::pre_ec_security();
      let mut distances = BTreeMap::new();
      let mut total_distance: u64 = 0;
      let reward_this_epoch = if pre_ec_security {
        // calculate distance to economic security per network
        for n in NETWORKS {
          if n == NetworkId::Serai {
            continue;
          }

          let required = ValidatorSets::<T>::required_stake_for_network(n);
          let mut current = ValidatorSets::<T>::total_allocated_stake(n).unwrap_or(Amount(0)).0;
          if current > required {
            current = required;
          }

          let distance = required - current;
          distances.insert(n, distance);
          total_distance = total_distance.saturating_add(distance);
        }

        // add serai network portion(20%)
        let new_total_distance =
          total_distance.saturating_mul(10) / (10 - SERAI_VALIDATORS_DESIRED_PERCENTAGE);
        distances.insert(NetworkId::Serai, new_total_distance - total_distance);
        total_distance = new_total_distance;

        if Self::initial_period(n) {
          // rewards are fixed for initial period
          block_count * INITIAL_REWARD_PER_BLOCK
        } else {
          // rewards for pre-economic security is
          // (STAKE_REQUIRED - CURRENT_STAKE) / blocks_until(SECURE_BY).
          let block_reward = total_distance / Self::blocks_until(SECURE_BY);
          block_count * block_reward
        }
      } else {
        // post ec security
        block_count * REWARD_PER_BLOCK
      };

      // get swap volumes
      let mut volume_per_network: BTreeMap<NetworkId, u64> = BTreeMap::new();
      for c in COINS {
        // this should return 0 for SRI and so it shouldn't affect the total volume.
        let current_volume = Dex::<T>::swap_volume(c).unwrap_or(0);
        volume_per_network.insert(
          c.network(),
          (*volume_per_network.get(&c.network()).unwrap_or(&0)).saturating_add(current_volume),
        );
      }

      // map current volumes to epoch volumes
      let mut total_volume = 0u64;
      for (n, vol) in &mut volume_per_network {
        let last_volume = Self::last_swap_volume(n).unwrap_or(0);
        let vol_this_epoch = vol.saturating_sub(last_volume);

        // update the current volume
        LastSwapVolume::<T>::set(n, Some(*vol));

        total_volume = total_volume.saturating_add(vol_this_epoch);
        *vol = vol_this_epoch;
      }

      // map epoch ec-security-distance/volume to rewards
      let rewards_per_network = if pre_ec_security {
        distances
          .into_iter()
          .map(|(n, distance)| {
            // calculate how much each network gets based on distance to ec-security
            let reward = u64::try_from(
              u128::from(reward_this_epoch).saturating_mul(u128::from(distance)) /
                u128::from(total_distance),
            )
            .unwrap();
            (n, reward)
          })
          .collect::<BTreeMap<NetworkId, u64>>()
      } else {
        volume_per_network
          .into_iter()
          .map(|(n, vol)| {
            // 20% of the reward goes to the Serai network and rest is distributed among others
            // based on swap-volume.
            let reward = if n == NetworkId::Serai {
              reward_this_epoch / 5
            } else {
              let reward = reward_this_epoch - (reward_this_epoch / 5);
              // TODO: It is highly unlikely but what to do in case of 0 total volume?
              if total_volume != 0 {
                u64::try_from(
                  u128::from(reward).saturating_mul(u128::from(vol)) / u128::from(total_volume),
                )
                .unwrap()
              } else {
                0
              }
            };
            (n, reward)
          })
          .collect::<BTreeMap<NetworkId, u64>>()
      };

      // distribute the rewards within the network
      for (n, reward) in rewards_per_network {
        let (validators_reward, pool_reward) = if n == NetworkId::Serai {
          (reward, 0)
        } else {
          // calculate pool vs validator share
          let capacity = ValidatorSets::<T>::total_allocated_stake(n).unwrap_or(Amount(0)).0;
          let required = ValidatorSets::<T>::required_stake_for_network(n);
          let unused_capacity = capacity.saturating_sub(required);

          let distribution = unused_capacity.saturating_mul(ACCURACY_MULTIPLIER) / capacity;
          let total = DESIRED_DISTRIBUTION.saturating_add(distribution);

          let validators_reward = DESIRED_DISTRIBUTION.saturating_mul(reward) / total;
          let pool_reward = reward.saturating_sub(validators_reward);
          (validators_reward, pool_reward)
        };

        // distribute validators rewards
        if Self::distribute_to_validators(n, validators_reward).is_err() {
          // TODO: log the failure
          continue;
        }

        // send the rest to the pool
        let coin_count = u64::try_from(n.coins().len()).unwrap();
        for c in n.coins() {
          // assumes reward is equally distributed between network coins.
          if Coins::<T>::mint(
            Dex::<T>::get_pool_account(*c),
            Balance { coin: Coin::Serai, amount: Amount(pool_reward / coin_count) },
          )
          .is_err()
          {
            // TODO: log the failure
            continue;
          }
        }
      }

      Self::update_participants();
      Weight::zero() // TODO
    }
  }

  impl<T: Config> Pallet<T> {
    fn blocks_until(block: u64) -> u64 {
      let current = <frame_system::Pallet<T>>::block_number().saturated_into::<u64>();
      block.saturating_sub(current)
    }

    fn initial_period(n: BlockNumberFor<T>) -> bool {
      // TODO: we should wait for exactly 2 months according to paper. This waits double the time
      // it took until genesis complete since we assume it will be done in a month. We know genesis
      // period blocks is a month but there will be delay until oracilization is done and genesis
      // completed and emissions start happening. If we wait exactly 2 months and the delay is big
      // enough we might not be able to distribute all funds we want to in this period.
      // In the current case we will distribute more than we want to. What to do?
      let genesis_complete_block = GenesisCompleteBlock::<T>::get();
      genesis_complete_block.is_some() &&
        (n.saturated_into::<u64>() < (3 * genesis_complete_block.unwrap()))
    }

    /// Returns true if any of the external networks haven't reached economic security yet.
    fn pre_ec_security() -> bool {
      for n in NETWORKS {
        if n == NetworkId::Serai {
          continue;
        }

        if !Self::economic_security_reached(n) {
          return true;
        }
      }
      false
    }

    fn distribute_to_validators(n: NetworkId, reward: u64) -> DispatchResult {
      // distribute among network's set based on
      // -> (key shares * stake per share) + ((stake % stake per share) / 2)
      let stake_per_share = ValidatorSets::<T>::allocation_per_key_share(n).unwrap().0;
      let mut scores = vec![];
      let mut total_score = 0u64;
      for (p, amount) in Self::participants(n).unwrap() {
        let remainder = amount % stake_per_share;
        let score = (amount - remainder) + (remainder / 2);

        total_score = total_score.saturating_add(score);
        scores.push((p, score));
      }

      // stake the rewards
      for (p, score) in scores {
        let p_reward = u64::try_from(
          u128::from(reward).saturating_mul(u128::from(score)) / u128::from(total_score),
        )
        .unwrap();

        Coins::<T>::mint(p, Balance { coin: Coin::Serai, amount: Amount(p_reward) })?;
        ValidatorSets::<T>::deposit_stake(n, p, Amount(p_reward))?;
      }

      Ok(())
    }

    pub fn swap_to_staked_sri(
      to: PublicKey,
      network: NetworkId,
      balance: Balance,
    ) -> DispatchResult {
      // check the network didn't reach the economic security yet
      if Self::economic_security_reached(network) {
        Err(Error::<T>::NetworkHasEconomicSecurity)?;
      }

      // calculate how much SRI the balance makes
      let value =
        Dex::<T>::security_oracle_value(balance.coin).ok_or(Error::<T>::NoValueForCoin)?;
      // TODO: may panic? It might be best for this math ops to return the result as is instead of
      // doing an unwrap so that it can be properly dealt with.
      let sri_amount = balance.amount.mul(value);

      // Mint & stake the SRI for the network.
      Coins::<T>::mint(to, Balance { coin: Coin::Serai, amount: sri_amount })?;
      // TODO: deposit_stake lets staking less than per key share. Should we allow that here?
      ValidatorSets::<T>::deposit_stake(network, to, sri_amount)?;
      Ok(())
    }

    fn update_participants() {
      for n in NETWORKS {
        // TODO: `participants_for_latest_decided_set` returns keys with key shares but we
        // store keys with actual stake amounts. Pr https://github.com/serai-dex/serai/pull/518
        // supposed to change that and so this pr relies and that pr.
        let participants = ValidatorSets::<T>::participants_for_latest_decided_set(n)
          .unwrap()
          .into_iter()
          .map(|(key, shares)| {
            let amount = match n {
              NetworkId::Serai => shares * 50_000 * 10_u64.pow(8),
              NetworkId::Bitcoin | NetworkId::Ethereum => shares * 1_000_000 * 10_u64.pow(8),
              NetworkId::Monero => shares * 100_000 * 10_u64.pow(8),
            };
            (key, amount)
          })
          .collect::<Vec<_>>();

        Participants::<T>::set(n, Some(participants.try_into().unwrap()));
      }
    }
  }
}

pub use pallet::*;
