#![cfg_attr(not(feature = "std"), no_std)]

#[frame_support::pallet]
pub mod pallet {
  use scale::{Encode, Decode};
  use scale_info::TypeInfo;

  use frame_system::pallet_prelude::*;
  use frame_support::pallet_prelude::*;

  use serai_primitives::*;
  use validator_sets_primitives::*;

  #[pallet::config]
  pub trait Config: frame_system::Config + TypeInfo {
    type RuntimeEvent: IsType<<Self as frame_system::Config>::RuntimeEvent> + From<Event<Self>>;
  }

  #[pallet::genesis_config]
  #[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen)]
  pub struct GenesisConfig<T: Config> {
    /// Bond requirement to join the initial validator set.
    /// Every participant at genesis will automatically be assumed to have this much bond.
    /// This bond cannot be withdrawn however as there's no stake behind it.
    pub bond: Amount,
    /// Amount of coins to spawn the network with in the initial validator set.
    pub coins: Coin,
    /// List of participants to place in the genesis set.
    pub participants: Vec<T::AccountId>,
  }

  #[cfg(feature = "std")]
  impl<T: Config> Default for GenesisConfig<T> {
    fn default() -> Self {
      GenesisConfig { bond: Amount(0), coins: Coin(0), participants: vec![] }
    }
  }

  // Max of 16 coins per validator set
  // At launch, we'll have BTC, ETH, DAI, and XMR
  // In the future, these will be split into separate validator sets, so we're already not
  // planning expansion beyond just a few coins per validator set
  // The only case which really makes sense for multiple coins in a validator set is:
  // 1) The coins are small, easy to run, and make no sense to be in their own set
  // In this case, it's still hard to ask validators to run 16 different nodes
  // 2) The coins are all on the same network yet there's no DEX on-chain
  // In these cases, it'd be hard to find and justify 16 different coins from that single chain
  // This could probably be just 8, yet 16 is a hedge for the unforseen
  // If necessary, this can be increased with a fork
  type MaxCoinsPerSet = ConstU32<16>;

  // Support keys up to 96 bytes (BLS12-381 G2)
  const MAX_KEY_LEN: u32 = 96;
  type MaxKeyLen = ConstU32<MAX_KEY_LEN>;

  #[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, TypeInfo, MaxEncodedLen)]
  pub struct ValidatorSet<T: Config> {
    bond: Amount,
    coins: BoundedVec<Coin, MaxCoinsPerSet>,

    // Participant and their amount bonded to this set
    // Limit each set to 100 participants for now
    participants: BoundedVec<(T::AccountId, Amount), ConstU32<100>>,
  }

  #[pallet::pallet]
  #[pallet::generate_store(pub(super) trait Store)]
  pub struct Pallet<T>(PhantomData<T>);

  /// The details of a validator set instance.
  #[pallet::storage]
  #[pallet::getter(fn validator_set)]
  pub type ValidatorSets<T: Config> =
    StorageMap<_, Twox64Concat, ValidatorSetInstance, ValidatorSet<T>, OptionQuery>;

  type Key = BoundedVec<u8, MaxKeyLen>;

  /// The key for a given validator set instance coin.
  #[pallet::storage]
  #[pallet::getter(fn key)]
  pub type Keys<T: Config> =
    StorageMap<_, Twox64Concat, (ValidatorSetInstance, Coin), Key, OptionQuery>;

  /// If an account has voted for a specific key or not. Prevents them from voting multiple times.
  #[pallet::storage]
  #[pallet::getter(fn voted)]
  pub type Voted<T: Config> = StorageMap<_, Blake2_128Concat, (T::AccountId, Key), (), OptionQuery>;

  /// How many times a key has been voted for. Once consensus is reached, the keys will be adopted.
  #[pallet::storage]
  #[pallet::getter(fn vote_count)]
  pub type VoteCount<T: Config> =
    StorageMap<_, Blake2_128Concat, (ValidatorSetInstance, Coin, Key), u16, ValueQuery>;

  #[pallet::genesis_build]
  impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
    fn build(&self) {
      // Start at 1 to leave 0 available for a future design where Serai itself has a distinct
      // validator set for its Tendermint consensus
      let mut coins = Vec::new();
      for coin in 0 .. self.coins.0 {
        coins.push(Coin(coin));
      }

      let mut participants = Vec::new();
      for participant in self.participants.clone() {
        participants.push((participant, self.bond));
      }

      ValidatorSets::<T>::set(
        ValidatorSetInstance(Session(0), ValidatorSetIndex(1)),
        Some(ValidatorSet {
          bond: self.bond,
          coins: BoundedVec::try_from(coins).unwrap(),
          participants: BoundedVec::try_from(participants).unwrap(),
        }),
      );
    }
  }

  #[pallet::event]
  #[pallet::generate_deposit(pub(super) fn deposit_event)]
  pub enum Event<T: Config> {
    Vote {
      voter: T::AccountId,
      instance: ValidatorSetInstance,
      coin: Coin,
      key: Key,
      // Amount of votes the key now has
      votes: u16,
    },
    KeyGen {
      instance: ValidatorSetInstance,
      coin: Coin,
      key: Key,
    },
  }

  #[pallet::error]
  pub enum Error<T> {
    /// Validator Set doesn't exist.
    NonExistentValidatorSet,
    /// Non-validator is voting.
    NotValidator,
    /// Validator Set already generated keys.
    AlreadyGeneratedKeys,
    /// Vvalidator has already voted for these keys.
    AlreadyVoted,
  }

  #[pallet::call]
  impl<T: Config> Pallet<T> {
    #[pallet::weight(0)] // TODO
    pub fn vote(
      origin: OriginFor<T>,
      index: ValidatorSetIndex,
      coin: Coin,
      key: Key,
    ) -> DispatchResult {
      let signer = ensure_signed(origin)?;
      // TODO: Do we need to check key is within bounds?

      // TODO: Get session
      let session: Session = Session(0);

      // Confirm a key hasn't been set for this set instance
      let instance = ValidatorSetInstance(session, index);
      if Keys::<T>::get((instance, coin)).is_some() {
        Err(Error::<T>::AlreadyGeneratedKeys)?;
      }

      // Confirm the signer is a validator in the set
      let set = ValidatorSets::<T>::get(instance).ok_or(Error::<T>::NonExistentValidatorSet)?;

      if set.participants.iter().any(|participant| participant.0 == signer) {
        Err(Error::<T>::NotValidator)?;
      }

      // Confirm this signer hasn't already voted for these keys
      if Voted::<T>::get((&signer, &key)).is_some() {
        Err(Error::<T>::AlreadyVoted)?;
      }
      Voted::<T>::set((&signer, &key), Some(()));

      // Add their vote
      let votes = VoteCount::<T>::mutate((instance, coin, &key), |value| {
        *value += 1;
        *value
      });

      Self::deposit_event(Event::Vote { voter: signer, instance, coin, key: key.clone(), votes });

      // If we've reached consensus, set the key
      if usize::try_from(votes).unwrap() == set.participants.len() {
        Keys::<T>::set((instance, coin), Some(key.clone()));
        Self::deposit_event(Event::KeyGen { instance, coin, key });
      }

      Ok(())
    }
  }

  // TODO: Support choosing validator set participants to form a Tendermint session
  // TODO: Support session rotation
}

pub use pallet::*;
