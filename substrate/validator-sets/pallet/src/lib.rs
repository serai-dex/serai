#![cfg_attr(not(feature = "std"), no_std)]

#[frame_support::pallet]
pub mod pallet {
  use frame_support::pallet_prelude::*;

  use validator_sets_primitives::*;

  #[cfg(not(feature = "std"))]
  pub trait Info {}
  #[cfg(feature = "std")]
  pub trait Info: scale_info::TypeInfo {}

  #[pallet::config]
  pub trait Config: frame_system::Config + Info {}

  #[pallet::genesis_config]
  #[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode, MaxEncodedLen)]
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

  #[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode, MaxEncodedLen)]
  #[cfg_attr(feature = "std", derive(scale_info::TypeInfo))]
  pub struct ValidatorSet<T: Config> {
    bond: Amount,
    coins: BoundedVec<Coin, MaxCoinsPerSet>,

    // Participant and their amount bonded to this set
    // Limit each set to 100 participants for now
    participants: BoundedVec<(T::AccountId, Amount), ConstU32<100>>,
  }

  impl<T: Config> Default for ValidatorSet<T> {
    fn default() -> Self {
      ValidatorSet {
        bond: Amount(0),
        coins: BoundedVec::default(),
        participants: BoundedVec::default(),
      }
    }
  }

  #[pallet::pallet]
  #[pallet::generate_store(pub(super) trait Store)]
  pub struct Pallet<T>(PhantomData<T>);

  #[pallet::storage]
  #[pallet::getter(fn validator_set)]
  pub type ValidatorSets<T: Config> =
    StorageMap<_, Identity, ValidatorSetInstance, ValidatorSet<T>, ValueQuery>;

  #[pallet::storage]
  #[pallet::getter(fn key)]
  pub type Keys<T: Config> =
    StorageMap<_, Identity, (ValidatorSetInstance, Coin), BoundedVec<u8, MaxKeyLen>, ValueQuery>;

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
        ValidatorSet {
          bond: self.bond,
          coins: BoundedVec::try_from(coins).unwrap(),
          participants: BoundedVec::try_from(participants).unwrap(),
        },
      );
    }
  }

  /*
  TODO: Support voting on keys
  #[pallet::call]
  impl<T: Config> Pallet<T> {
    pub fn vote()
  }
  */

  // TODO: Support choosing validator set participants to form a Tendermint session
  // TODO: Support session rotation
}

pub use pallet::*;
