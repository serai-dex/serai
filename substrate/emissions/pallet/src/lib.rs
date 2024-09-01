#![cfg_attr(not(feature = "std"), no_std)]

#[allow(
  unreachable_patterns,
  clippy::cast_possible_truncation,
  clippy::no_effect_underscore_binding,
  clippy::empty_docs
)]
#[frame_support::pallet]
pub mod pallet {
  use super::*;
  use frame_system::{pallet_prelude::*, RawOrigin};
  use frame_support::{pallet_prelude::*, sp_runtime::SaturatedConversion};

  use sp_std::{vec, vec::Vec, ops::Mul, collections::btree_map::BTreeMap};

  use coins_pallet::{Config as CoinsConfig, Pallet as Coins};
  use dex_pallet::{Config as DexConfig, Pallet as Dex};

  use validator_sets_pallet::{Pallet as ValidatorSets, Config as ValidatorSetsConfig};
  use genesis_liquidity_pallet::{Pallet as GenesisLiquidity, Config as GenesisLiquidityConfig};

  use economic_security_pallet::{Config as EconomicSecurityConfig, Pallet as EconomicSecurity};

  use serai_primitives::*;
  use validator_sets_primitives::{MAX_KEY_SHARES_PER_SET, Session};
  pub use emissions_primitives as primitives;
  use primitives::*;

  #[pallet::config]
  pub trait Config:
    frame_system::Config<AccountId = PublicKey>
    + ValidatorSetsConfig
    + CoinsConfig
    + DexConfig
    + GenesisLiquidityConfig
    + EconomicSecurityConfig
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
    InsufficientAllocation,
  }

  #[pallet::event]
  pub enum Event<T: Config> {}

  #[pallet::pallet]
  pub struct Pallet<T>(PhantomData<T>);

  // TODO: Remove this. This should be the sole domain of validator-sets
  #[pallet::storage]
  #[pallet::getter(fn participants)]
  pub(crate) type Participants<T: Config> = StorageMap<
    _,
    Identity,
    NetworkId,
    BoundedVec<(PublicKey, u64), ConstU32<{ MAX_KEY_SHARES_PER_SET }>>,
    OptionQuery,
  >;

  // TODO: Remove this too
  #[pallet::storage]
  #[pallet::getter(fn session)]
  pub type CurrentSession<T: Config> = StorageMap<_, Identity, NetworkId, u32, ValueQuery>;

  #[pallet::storage]
  pub(crate) type LastSwapVolume<T: Config> = StorageMap<_, Identity, Coin, u64, OptionQuery>;

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
      }
    }
  }

  #[pallet::hooks]
  impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
    fn on_initialize(n: BlockNumberFor<T>) -> Weight {
      let genesis_ended = GenesisLiquidity::<T>::genesis_complete_block().is_some();

      // check if we got a new session
      let mut session_changed = false;
      let session = ValidatorSets::<T>::session(NetworkId::Serai).unwrap_or(Session(0));
      if session.0 > Self::session(NetworkId::Serai) {
        session_changed = true;
        CurrentSession::<T>::set(NetworkId::Serai, session.0);
      }

      // update participants per session before the genesis
      // after the genesis, we update them after reward distribution.
      if (!genesis_ended) && session_changed {
        Self::update_participants();
      }

      // We only want to distribute emissions if the genesis period is over AND the session has
      // ended
      if !(genesis_ended && session_changed) {
        return Weight::zero(); // TODO
      }

      // figure out the amount of blocks in the last session
      // Since the session has changed, we're now at least at session 1
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

        // add serai network portion (20%)
        let new_total_distance =
          total_distance.saturating_mul(100) / (100 - SERAI_VALIDATORS_DESIRED_PERCENTAGE);
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

      // map epoch ec-security-distance/volume to rewards
      let (rewards_per_network, volume_per_network, volume_per_coin) = if pre_ec_security {
        (
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
            .collect::<BTreeMap<NetworkId, u64>>(),
          None,
          None,
        )
      } else {
        // get swap volumes
        let mut volume_per_coin: BTreeMap<Coin, u64> = BTreeMap::new();
        for c in COINS {
          // this should return 0 for SRI and so it shouldn't affect the total volume.
          let current_volume = Dex::<T>::swap_volume(c).unwrap_or(0);
          let last_volume = LastSwapVolume::<T>::get(c).unwrap_or(0);
          let vol_this_epoch = current_volume.saturating_sub(last_volume);

          // update the current volume
          LastSwapVolume::<T>::set(c, Some(current_volume));
          volume_per_coin.insert(c, vol_this_epoch);
        }

        // aggregate per network
        let mut total_volume = 0u64;
        let mut volume_per_network: BTreeMap<NetworkId, u64> = BTreeMap::new();
        for (c, vol) in &volume_per_coin {
          volume_per_network.insert(
            c.network(),
            (*volume_per_network.get(&c.network()).unwrap_or(&0)).saturating_add(*vol),
          );
          total_volume = total_volume.saturating_add(*vol);
        }

        (
          volume_per_network
            .iter()
            .map(|(n, vol)| {
              // 20% of the reward goes to the Serai network and rest is distributed among others
              // based on swap-volume.
              let reward = if *n == NetworkId::Serai {
                reward_this_epoch / 5
              } else {
                let reward = reward_this_epoch - (reward_this_epoch / 5);
                // TODO: It is highly unlikely but what to do in case of 0 total volume?
                if total_volume != 0 {
                  u64::try_from(
                    u128::from(reward).saturating_mul(u128::from(*vol)) / u128::from(total_volume),
                  )
                  .unwrap()
                } else {
                  0
                }
              };
              (*n, reward)
            })
            .collect::<BTreeMap<NetworkId, u64>>(),
          Some(volume_per_network),
          Some(volume_per_coin),
        )
      };

      // distribute the rewards within the network
      for (n, reward) in rewards_per_network {
        let (validators_reward, network_pool_reward) = if n == NetworkId::Serai {
          (reward, 0)
        } else {
          // calculate pool vs validator share
          let capacity = ValidatorSets::<T>::total_allocated_stake(n).unwrap_or(Amount(0)).0;
          let required = ValidatorSets::<T>::required_stake_for_network(n);
          let unused_capacity = capacity.saturating_sub(required);

          let distribution = unused_capacity.saturating_mul(ACCURACY_MULTIPLIER) / capacity;
          let total = DESIRED_DISTRIBUTION.saturating_add(distribution);

          let validators_reward = DESIRED_DISTRIBUTION.saturating_mul(reward) / total;
          let network_pool_reward = reward.saturating_sub(validators_reward);
          (validators_reward, network_pool_reward)
        };

        // distribute validators rewards
        Self::distribute_to_validators(n, validators_reward);

        // send the rest to the pool
        if network_pool_reward != 0 {
          // these should be available to unwrap if we have a network_pool_reward. Because that
          // means we had an unused capacity hence in a post-ec era.
          let vpn = volume_per_network.as_ref().unwrap();
          let vpc = volume_per_coin.as_ref().unwrap();
          for c in n.coins() {
            let pool_reward = u64::try_from(
              u128::from(network_pool_reward).saturating_mul(u128::from(vpc[c])) /
                u128::from(vpn[&n]),
            )
            .unwrap();

            if Coins::<T>::mint(
              Dex::<T>::get_pool_account(*c),
              Balance { coin: Coin::Serai, amount: Amount(pool_reward) },
            )
            .is_err()
            {
              // TODO: log the failure
              continue;
            }
          }
        }
      }

      // TODO: we have the past session participants here in the emissions pallet so that we can
      // distribute rewards to them in the next session. Ideally we should be able to fetch this
      // information from valiadtor sets pallet.
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
      #[cfg(feature = "fast-epoch")]
      let initial_period_duration = FAST_EPOCH_INITIAL_PERIOD;

      #[cfg(not(feature = "fast-epoch"))]
      let initial_period_duration = 2 * MONTHS;

      let genesis_complete_block = GenesisLiquidity::<T>::genesis_complete_block();
      genesis_complete_block.is_some() &&
        (n.saturated_into::<u64>() < (genesis_complete_block.unwrap() + initial_period_duration))
    }

    /// Returns true if any of the external networks haven't reached economic security yet.
    fn pre_ec_security() -> bool {
      for n in NETWORKS {
        if n == NetworkId::Serai {
          continue;
        }

        if EconomicSecurity::<T>::economic_security_block(n).is_none() {
          return true;
        }
      }
      false
    }

    // Distribute the reward among network's set based on
    // -> (key shares * stake per share) + ((stake % stake per share) / 2)
    fn distribute_to_validators(n: NetworkId, reward: u64) {
      let stake_per_share = ValidatorSets::<T>::allocation_per_key_share(n).unwrap().0;
      let mut scores = vec![];
      let mut total_score = 0u64;
      for (p, amount) in Self::participants(n).unwrap() {
        let remainder = amount % stake_per_share;
        let score = amount - (remainder / 2);

        total_score = total_score.saturating_add(score);
        scores.push((p, score));
      }

      // stake the rewards
      for (p, score) in scores {
        let p_reward = u64::try_from(
          u128::from(reward).saturating_mul(u128::from(score)) / u128::from(total_score),
        )
        .unwrap();

        Coins::<T>::mint(p, Balance { coin: Coin::Serai, amount: Amount(p_reward) }).unwrap();
        if ValidatorSets::<T>::distribute_block_rewards(n, p, Amount(p_reward)).is_err() {
          // TODO: log the failure
          continue;
        }
      }
    }

    pub fn swap_to_staked_sri(
      to: PublicKey,
      network: NetworkId,
      balance: Balance,
    ) -> DispatchResult {
      // check the network didn't reach the economic security yet
      if EconomicSecurity::<T>::economic_security_block(network).is_some() {
        Err(Error::<T>::NetworkHasEconomicSecurity)?;
      }

      // swap half of the liquidity for SRI to form PoL.
      let half = balance.amount.0 / 2;
      let path = BoundedVec::try_from(vec![balance.coin, Coin::Serai]).unwrap();
      let origin = RawOrigin::Signed(POL_ACCOUNT.into());
      Dex::<T>::swap_exact_tokens_for_tokens(
        origin.clone().into(),
        path,
        half,
        1, // minimum out, so we accept whatever we get.
        POL_ACCOUNT.into(),
      )?;

      // get how much we got for our swap
      let sri_amount = Coins::<T>::balance(POL_ACCOUNT.into(), Coin::Serai).0;

      // add liquidity
      Dex::<T>::add_liquidity(
        origin.clone().into(),
        balance.coin,
        half,
        sri_amount,
        1,
        1,
        POL_ACCOUNT.into(),
      )?;

      // use last block spot price to calculate how much SRI the balance makes.
      let last_block = <frame_system::Pallet<T>>::block_number() - 1u32.into();
      let value = Dex::<T>::spot_price_for_block(last_block, balance.coin)
        .ok_or(Error::<T>::NoValueForCoin)?;
      // TODO: may panic? It might be best for this math ops to return the result as is instead of
      // doing an unwrap so that it can be properly dealt with.
      let sri_amount = balance.amount.mul(value);

      // Mint
      Coins::<T>::mint(to, Balance { coin: Coin::Serai, amount: sri_amount })?;

      // Stake the SRI for the network.
      ValidatorSets::<T>::allocate(
        frame_system::RawOrigin::Signed(to).into(),
        network,
        sri_amount,
      )?;
      Ok(())
    }

    fn update_participants() {
      for n in NETWORKS {
        let participants = ValidatorSets::<T>::participants_for_latest_decided_set(n)
          .unwrap()
          .into_iter()
          .map(|(key, _)| (key, ValidatorSets::<T>::allocation((n, key)).unwrap_or(Amount(0)).0))
          .collect::<Vec<_>>();

        Participants::<T>::set(n, Some(participants.try_into().unwrap()));
      }
    }
  }
}

pub use pallet::*;
