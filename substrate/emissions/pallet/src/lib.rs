#![cfg_attr(not(feature = "std"), no_std)]

#[allow(clippy::cast_possible_truncation, clippy::no_effect_underscore_binding)]
#[frame_support::pallet]
pub mod pallet {
  use super::*;
  use frame_system::pallet_prelude::*;
  use frame_support::{pallet_prelude::*, sp_runtime::SaturatedConversion};

  use sp_std::{vec, vec::Vec, collections::btree_map::BTreeMap};
  use sp_session::ShouldEndSession;
  use sp_runtime;

  use coins_pallet::{Config as CoinsConfig, Pallet as Coins, AllowMint};
  use dex_pallet::{Config as DexConfig, Pallet as Dex};

  use validator_sets_pallet::{Pallet as ValidatorSets, Config as ValidatorSetsConfig};
  use pallet_babe::{Pallet as Babe, Config as BabeConfig};

  use serai_primitives::{NetworkId, NETWORKS, *};
  use serai_validator_sets_primitives::MAX_KEY_SHARES_PER_SET;
  use emissions_primitives::*;

  #[pallet::config]
  pub trait Config:
    frame_system::Config<AccountId = PublicKey>
    + ValidatorSetsConfig
    + BabeConfig
    + CoinsConfig
    + DexConfig
  {
    type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
  }

  #[pallet::genesis_config]
  #[derive(Clone, PartialEq, Eq, Debug, Encode, Decode)]
  pub struct GenesisConfig<T: Config> {
    /// Networks to spawn Serai with.
    pub networks: Vec<NetworkId>,
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
    GenesisPeriodEnded,
    AmountOverflowed,
    NotEnoughLiquidity,
    CanOnlyRemoveFullAmount,
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
  #[pallet::getter(fn epoch_begin_block)]
  pub(crate) type EpochBeginBlock<T: Config> = StorageMap<_, Identity, u64, u64, ValueQuery>;

  #[pallet::storage]
  #[pallet::getter(fn economic_security_reached)]
  pub(crate) type EconomicSecurityReached<T: Config> =
    StorageMap<_, Identity, NetworkId, BlockNumberFor<T>, ValueQuery>;

  #[pallet::storage]
  #[pallet::getter(fn last_swap_volume)]
  pub(crate) type LastSwapVolume<T: Config> = StorageMap<_, Identity, NetworkId, u64, OptionQuery>;

  #[pallet::genesis_build]
  impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
    fn build(&self) {
      for id in self.networks.clone() {
        let mut participants = vec![];
        for p in self.participants.clone() {
          participants.push((p, 0u64));
        }
        Participants::<T>::set(id, Some(participants.try_into().unwrap()));
      }

      EpochBeginBlock::<T>::set(0, 0);
    }
  }

  #[pallet::hooks]
  impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
    /// Since we are on `on_finalize`, session should have already rotated.
    /// We can distribute the rewards for the last set.
    fn on_finalize(n: BlockNumberFor<T>) {
      // we accept we reached economic security once we can mint smallest amount of a network's coin
      for coin in COINS {
        let existing = EconomicSecurityReached::<T>::get(coin.network());
        if existing == 0u32.into() &&
          <T as CoinsConfig>::AllowMint::is_allowed(&Balance { coin, amount: Amount(1) })
        {
          EconomicSecurityReached::<T>::set(coin.network(), n);
        }
      }

      // emissions start only after genesis period and happens once per epoch
      // so we don't do anything before that time.
      if !(n >= BLOCKS_PER_MONTH.into() && T::ShouldEndSession::should_end_session(n)) {
        return;
      }

      // figure out the amount of blocks in the last epoch
      // TODO: we use epoch index here but should we use SessionIndex since this is how we decide
      // whether time to distribute the rewards or not? Because apparently epochs != Sessions
      // since we can skip some epochs if the chain is offline more than epoch duration??
      let epoch = Babe::<T>::current_epoch().epoch_index - 1;
      let block_count = n.saturated_into::<u64>() - Self::epoch_begin_block(epoch);

      // get total reward for this epoch
      let pre_ec_security = Self::pre_ec_security();
      let mut distances = BTreeMap::new();
      let mut total_distance: u64 = 0;
      let reward_this_epoch = if Self::initial_period(n) {
        // rewards are fixed for initial period
        block_count * INITIAL_REWARD_PER_BLOCK
      } else if pre_ec_security {
        // calculate distance to economic security per network
        let mut total_required: u64 = 0;
        let mut total_current: u64 = 0;
        for n in NETWORKS {
          if n == NetworkId::Serai {
            continue;
          }

          let required = ValidatorSets::<T>::required_stake_for_network(n);
          let mut current = ValidatorSets::<T>::total_allocated_stake(n).unwrap_or(Amount(0)).0;
          if current > required {
            current = required;
          }

          distances.insert(n, required - current);
          total_required = total_required.saturating_add(required);
          total_current = total_current.saturating_add(current);
        }
        total_distance = total_required.saturating_sub(total_current);

        // add serai network portion(20%)
        let new_total_distance =
          total_distance.saturating_mul(10) / (10 - SERAI_VALIDATORS_DESIRED_PERCENTAGE);
        distances.insert(NetworkId::Serai, new_total_distance - total_distance);
        total_distance = new_total_distance;

        // rewards for pre-economic security is
        // (STAKE_REQUIRED - CURRENT_STAKE) / blocks_until(SECURE_BY).
        let block_reward = total_distance / Self::blocks_until(SECURE_BY);
        block_count * block_reward
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
      let rewards_per_network = distances
        .into_iter()
        .map(|(n, distance)| {
          let reward = if pre_ec_security {
            // calculate how much each network gets based on distance to ec-security
            reward_this_epoch.saturating_mul(distance) / total_distance
          } else {
            // 20% of the reward goes to the Serai network and rest is distributed among others
            // based on swap-volume.
            if n == NetworkId::Serai {
              reward_this_epoch / 5
            } else {
              let reward = reward_this_epoch - (reward_this_epoch / 5);
              reward.saturating_mul(*volume_per_network.get(&n).unwrap_or(&0)) / total_volume
            }
          };
          (n, reward)
        })
        .collect::<BTreeMap<NetworkId, u64>>();

      // distribute the rewards within the network
      for (n, reward) in rewards_per_network {
        // calculate pool vs validator share
        let capacity = ValidatorSets::<T>::total_allocated_stake(n).unwrap_or(Amount(0)).0;
        let required = ValidatorSets::<T>::required_stake_for_network(n);
        let unused_capacity = capacity.saturating_sub(required);

        let distribution = unused_capacity.saturating_mul(ACCURACY_MULTIPLIER) / capacity;
        let total = DESIRED_DISTRIBUTION.saturating_add(distribution);

        let validators_reward = DESIRED_DISTRIBUTION.saturating_mul(reward) / total;
        let pool_reward = total - validators_reward;

        // distribute validators rewards
        Self::distribute_to_validators(n, validators_reward);

        // send the rest to the pool
        let coin_count = u64::try_from(n.coins().len()).unwrap();
        for c in n.coins() {
          // TODO: we just print a warning here instead of unwrap?
          // assumes reward is equally distributed between network coins.
          Coins::<T>::mint(
            Dex::<T>::get_pool_account(*c),
            Balance { coin: Coin::Serai, amount: Amount(pool_reward / coin_count) },
          )
          .unwrap();
        }
      }

      // set the begin block and participants
      EpochBeginBlock::<T>::set(epoch, n.saturated_into::<u64>());
      for n in NETWORKS {
        // TODO: `participants_for_latest_decided_set` returns keys with key shares but we
        // store keys with actual stake amounts. Pr https://github.com/serai-dex/serai/pull/518
        // supposed to change that and so this pr relies and that pr.
        Participants::<T>::set(n, ValidatorSets::<T>::participants_for_latest_decided_set(n));
      }
    }
  }

  impl<T: Config> Pallet<T> {
    fn blocks_until(block: u64) -> u64 {
      let current = <frame_system::Pallet<T>>::block_number().saturated_into::<u64>();
      block.saturating_sub(current)
    }

    fn initial_period(n: BlockNumberFor<T>) -> bool {
      n >= BLOCKS_PER_MONTH.into() && n < (3 * BLOCKS_PER_MONTH).into()
    }

    /// Returns true if any of the external networks haven't reached economic security yet.
    fn pre_ec_security() -> bool {
      for n in NETWORKS {
        if n == NetworkId::Serai {
          continue;
        }

        if Self::economic_security_reached(n) == 0u32.into() {
          return true;
        }
      }
      false
    }

    fn distribute_to_validators(n: NetworkId, reward: u64) {
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
        let p_reward = reward.saturating_mul(score) / total_score;
        // TODO: print a warning here?
        let _ = ValidatorSets::<T>::deposit_stake(n, p, Amount(p_reward));
      }
    }
  }
}

pub use pallet::*;
