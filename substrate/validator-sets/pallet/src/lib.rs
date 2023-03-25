#![cfg_attr(not(feature = "std"), no_std)]

#[frame_support::pallet]
pub mod pallet {
  use scale::{Encode, Decode};
  use scale_info::TypeInfo;

  use frame_system::pallet_prelude::*;
  use frame_support::pallet_prelude::*;

  use serai_primitives::*;
  pub use validator_sets_primitives as primitives;
  use primitives::*;

  #[pallet::config]
  pub trait Config: frame_system::Config + TypeInfo {
    type RuntimeEvent: IsType<<Self as frame_system::Config>::RuntimeEvent> + From<Event<Self>>;
  }

  #[pallet::genesis_config]
  #[derive(Clone, PartialEq, Eq, Debug, Encode, Decode)]
  pub struct GenesisConfig<T: Config> {
    /// Bond requirement to join the initial validator sets.
    /// Every participant at genesis will automatically be assumed to have this much bond.
    /// This bond cannot be withdrawn however as there's no stake behind it.
    pub bond: Amount,
    /// Networks to spawn Serai with.
    pub networks: Vec<(NetworkId, Network)>,
    /// List of participants to place in the initial validator sets.
    pub participants: Vec<T::AccountId>,
  }

  #[cfg(feature = "std")]
  impl<T: Config> Default for GenesisConfig<T> {
    fn default() -> Self {
      GenesisConfig { bond: Amount(1), networks: vec![], participants: vec![] }
    }
  }

  // Support keys up to 96 bytes (BLS12-381 G2)
  const MAX_KEY_LEN: u32 = 96;
  type MaxKeyLen = ConstU32<MAX_KEY_LEN>;

  #[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, TypeInfo, MaxEncodedLen)]
  pub struct ValidatorSetData<T: Config> {
    bond: Amount,
    network: Network,

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
    StorageMap<_, Twox64Concat, ValidatorSet, ValidatorSetData<T>, OptionQuery>;

  type Key = BoundedVec<u8, MaxKeyLen>;

  /// The key for a given validator set instance.
  #[pallet::storage]
  #[pallet::getter(fn key)]
  pub type Keys<T: Config> = StorageMap<_, Twox64Concat, ValidatorSet, Key, OptionQuery>;

  /// If an account has voted for a specific key or not. Prevents them from voting multiple times.
  #[pallet::storage]
  #[pallet::getter(fn voted)]
  pub type Voted<T: Config> = StorageMap<_, Blake2_128Concat, (T::AccountId, Key), (), OptionQuery>;

  /// How many times a key has been voted for. Once consensus is reached, the keys will be adopted.
  #[pallet::storage]
  #[pallet::getter(fn vote_count)]
  pub type VoteCount<T: Config> =
    StorageMap<_, Blake2_128Concat, (ValidatorSet, Key), u16, ValueQuery>;

  #[pallet::genesis_build]
  impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
    fn build(&self) {
      let mut participants = Vec::new();
      for participant in self.participants.clone() {
        participants.push((participant, self.bond));
      }
      let participants = BoundedVec::try_from(participants).unwrap();

      for (id, network) in self.networks.clone() {
        ValidatorSets::<T>::set(
          ValidatorSet { session: Session(0), network: id },
          Some(ValidatorSetData { bond: self.bond, network, participants: participants.clone() }),
        );
      }
    }
  }

  #[pallet::event]
  #[pallet::generate_deposit(pub(super) fn deposit_event)]
  pub enum Event<T: Config> {
    Vote {
      voter: T::AccountId,
      set: ValidatorSet,
      key: Key,
      // Amount of votes the key now has
      votes: u16,
    },
    KeyGen {
      set: ValidatorSet,
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
    #[pallet::call_index(0)]
    #[pallet::weight(0)] // TODO
    pub fn vote(origin: OriginFor<T>, network: NetworkId, key: Key) -> DispatchResult {
      let signer = ensure_signed(origin)?;
      // TODO: Do we need to check the key is within the length bounds?
      // The docs suggest the BoundedVec will create/write, yet not read, which could be an issue
      // if it can be passed in

      // TODO: Get session
      let session: Session = Session(0);

      // Confirm a key hasn't been set for this set instance
      let set = ValidatorSet { session, network };
      if Keys::<T>::get(set).is_some() {
        Err(Error::<T>::AlreadyGeneratedKeys)?;
      }

      // Confirm the signer is a validator in the set
      let data = ValidatorSets::<T>::get(set).ok_or(Error::<T>::NonExistentValidatorSet)?;
      if data.participants.iter().any(|participant| participant.0 == signer) {
        Err(Error::<T>::NotValidator)?;
      }

      // Confirm this signer hasn't already voted for these keys
      if Voted::<T>::get((&signer, &key)).is_some() {
        Err(Error::<T>::AlreadyVoted)?;
      }
      Voted::<T>::set((&signer, &key), Some(()));

      // Add their vote
      let votes = VoteCount::<T>::mutate((set, &key), |value| {
        *value += 1;
        *value
      });

      Self::deposit_event(Event::Vote { voter: signer, set, key: key.clone(), votes });

      // If we've reached consensus, set the key
      if usize::try_from(votes).unwrap() == data.participants.len() {
        Keys::<T>::set(set, Some(key.clone()));
        Self::deposit_event(Event::KeyGen { set, key });
      }

      Ok(())
    }
  }

  // TODO: Support session rotation
}

pub use pallet::*;
