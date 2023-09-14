#![cfg_attr(not(feature = "std"), no_std)]

#[allow(deprecated, clippy::let_unit_value)] // TODO
#[frame_support::pallet]
pub mod pallet {
  use scale_info::TypeInfo;

  use sp_core::sr25519::{Public, Signature};
  use sp_std::vec;
  use sp_std::vec::Vec;
  use sp_application_crypto::RuntimePublic;
  use sp_runtime::traits::SaturatedConversion;

  use frame_system::pallet_prelude::*;
  use frame_support::pallet_prelude::*;

  use pallet_babe::{Config as BabeConfig, Pallet as Babe};

  use serai_primitives::*;
  pub use validator_sets_primitives as primitives;
  use primitives::*;

  #[pallet::config]
  pub trait Config: frame_system::Config<AccountId = Public> + BabeConfig + TypeInfo {
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

  impl<T: Config> Default for GenesisConfig<T> {
    fn default() -> Self {
      GenesisConfig {
        bond: Amount(1),
        networks: Default::default(),
        participants: Default::default(),
      }
    }
  }

  #[pallet::pallet]
  pub struct Pallet<T>(PhantomData<T>);

  /// The details of a validator set instance.
  #[pallet::storage]
  #[pallet::getter(fn validator_set)]
  pub type ValidatorSets<T: Config> =
    StorageMap<_, Twox64Concat, ValidatorSet, ValidatorSetData, OptionQuery>;

  /// The MuSig key for a validator set.
  #[pallet::storage]
  #[pallet::getter(fn musig_key)]
  pub type MuSigKeys<T: Config> = StorageMap<_, Twox64Concat, ValidatorSet, Public, OptionQuery>;

  /// The key pair for a given validator set instance.
  #[pallet::storage]
  #[pallet::getter(fn keys)]
  pub type Keys<T: Config> = StorageMap<_, Twox64Concat, ValidatorSet, KeyPair, OptionQuery>;

  /// The Validators that has enough bond allocated
  /// and set to be joining to the validator set
  /// in the next session.
  #[pallet::storage]
  #[pallet::getter(fn joining_validators)]
  #[pallet::unbounded]
  pub type JoiningValidators<T: Config> =
    StorageMap<_, Twox64Concat, ValidatorSet, Vec<(T::AccountId, Amount)>, ValueQuery>;

  /// The Validators that has enough bond deallocated
  /// and set to be leaving to the validator set
  /// in the next session.
  #[pallet::storage]
  #[pallet::getter(fn leaving_validators)]
  #[pallet::unbounded]
  pub type LeavingValidators<T: Config> =
    StorageMap<_, Twox64Concat, ValidatorSet, Vec<(T::AccountId, Amount)>, ValueQuery>;

  /// The Validators that has enough bond deallocated
  /// to still remain in the validator set but freed
  /// some funds.
  #[pallet::storage]
  #[pallet::getter(fn deallocating_validators)]
  #[pallet::unbounded]
  pub type DeallocatingValidators<T: Config> =
    StorageMap<_, Twox64Concat, ValidatorSet, Vec<(T::AccountId, Amount)>, ValueQuery>;

  #[pallet::storage]
  #[pallet::getter(fn current_session)]
  pub type CurrentSessionIndex<T> = StorageValue<_, Session, ValueQuery>;

  #[pallet::event]
  #[pallet::generate_deposit(pub(super) fn deposit_event)]
  pub enum Event<T: Config> {
    NewSet { set: ValidatorSet },
    KeyGen { set: ValidatorSet, key_pair: KeyPair },
  }

  #[pallet::genesis_build]
  impl<T: Config> BuildGenesisConfig for GenesisConfig<T> {
    fn build(&self) {
      let hash_set =
        self.participants.iter().map(|key| key.0).collect::<hashbrown::HashSet<[u8; 32]>>();
      if hash_set.len() != self.participants.len() {
        panic!("participants contained duplicates");
      }

      let mut participants = Vec::new();
      for participant in self.participants.clone() {
        participants.push((participant, self.bond));
      }
      let participants = BoundedVec::try_from(participants).unwrap();

      for (id, network) in self.networks.clone() {
        let set = ValidatorSet { session: Session(0), network: id };
        // TODO: Should this be split up? Substrate will read this entire struct into mem on every
        // read, not just accessed variables
        ValidatorSets::<T>::set(
          set,
          Some(ValidatorSetData { bond: self.bond, network, participants: participants.clone() }),
        );

        MuSigKeys::<T>::set(set, Some(musig_key(set, &self.participants)));
        Pallet::<T>::deposit_event(Event::NewSet { set })
      }

      CurrentSessionIndex::<T>::mutate(|v| {
        *v = Session(0);
      });
    }
  }

  #[pallet::error]
  pub enum Error<T> {
    /// Validator Set doesn't exist.
    NonExistentValidatorSet,
    /// Validator Set already generated keys.
    AlreadyGeneratedKeys,
    /// An invalid MuSig signature was provided.
    BadSignature,
    /// Not enough bond to participate in a set.
    InSufficientBond,
    /// Validator wasn't registered or active.
    NonExistentValidator,
    /// Trying to deallocate more than allocated.
    InSufficientAllocation,
  }

  #[pallet::hooks]
  impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
    /// Called when a block is initialized.
    fn on_initialize(n: BlockNumberFor<T>) -> Weight {
      // fire new_set 100 blocks prior to session change.
      // we can "predict" next session start by getting the
      // next epoch time from babe since sessions rotate on epoch change.
      // This is only approximation since slots != blocks.
      let next_start: u64 = Babe::<T>::next_epoch().start_slot.into();
      if next_start - 100 <= n.saturated_into::<u64>() {
        // TODO: only for serai or for all networks?
        // TODO: this fires for all the blocks until the epoch changes
        // check whether you already fired for this session
        let set = ValidatorSet {
          session: Session(Self::current_session().0 + 1),
          network: NetworkId::Serai,
        };
        Pallet::<T>::deposit_event(Event::NewSet { set })
      }
      Weight::zero() // TODO
    }
  }

  impl<T: Config> Pallet<T> {
    fn verify_signature(
      set: ValidatorSet,
      key_pair: &KeyPair,
      signature: &Signature,
    ) -> Result<(), Error<T>> {
      if Keys::<T>::get(set).is_some() {
        Err(Error::AlreadyGeneratedKeys)?
      }

      let Some(musig_key) = MuSigKeys::<T>::get(set) else { Err(Error::NonExistentValidatorSet)? };
      if !musig_key.verify(&set_keys_message(&set, key_pair), signature) {
        Err(Error::BadSignature)?;
      }

      Ok(())
    }

    /// Will set the given account to validator list if the allocated bond is enough.
    pub fn add_participant(
      account: T::AccountId,
      amount: Amount,
      network: NetworkId,
    ) -> DispatchResult {
      let key = ValidatorSet { session: Self::current_session(), network };
      if amount < Self::validator_set(key).unwrap().bond {
        Err(Error::<T>::InSufficientBond)?;
      }

      // Since this participant will be included after the next session, save it for the set
      // where it will be active.
      let participant_set =
        ValidatorSet { session: Session(Self::current_session().0 + 2), network };
      JoiningValidators::<T>::try_mutate_exists(participant_set, |existing| {
        if existing.is_some() {
          existing.as_mut().unwrap().push((account, amount));
        } else {
          *existing = Some(vec![(account, amount)]);
        }
        Ok::<_, Error<T>>(())
      })?;

      Ok(())
    }

    /// This function will set the participant for leaving if remaining bond
    /// fells short for the bond requirement of the set after the deallocation.
    pub fn maybe_remove_participant(
      account: T::AccountId,
      amount: Amount,
      network: NetworkId,
    ) -> DispatchResult {
      let current_set =
        Self::validator_set(ValidatorSet { session: Self::current_session(), network }).unwrap();
      let effective_session = Session(Self::current_session().0 + 2);

      match current_set.participants.iter().find(|p| p.0 == account) {
        Some(p) => {
          // check validator has enough to deallocate
          if amount > p.1 {
            Err(Error::<T>::InSufficientAllocation)?;
          }

          // if the remaining bond is not enough
          // remove from the validator set.
          // deallocate all bond instead of just "amount"
          // since they will be leaving.
          let key = ValidatorSet { session: effective_session, network };
          let left = p.1 - amount;
          if left < current_set.bond {
            // add to the leaving set
            LeavingValidators::<T>::try_mutate_exists(key, |existing| {
              if existing.is_some() {
                existing.as_mut().unwrap().push((account, p.1));
              } else {
                *existing = Some(vec![(account, p.1)]);
              }
              Ok::<_, Error<T>>(())
            })?;
          } else {
            // add to deallocation set
            DeallocatingValidators::<T>::try_mutate_exists(key, |existing| {
              if existing.is_some() {
                existing.as_mut().unwrap().push((account, amount));
              } else {
                *existing = Some(vec![(account, amount)]);
              }
              Ok::<_, Error<T>>(())
            })?;
          }

          Ok(())
        }
        None => {
          // check whether it is still in the joining set before getting active
          let key = ValidatorSet { session: effective_session, network };
          let mut joining_set = JoiningValidators::<T>::get(key);
          let index = joining_set
            .iter()
            .position(|entries| entries.0 == account)
            .ok_or(Error::<T>::NonExistentValidator)?;
          let mut p = joining_set[index];

          // check validator has enough to deallocate
          if amount > p.1 {
            Err(Error::<T>::InSufficientAllocation)?;
          }

          // check whether still says or leaves
          p.1 = p.1 - amount;
          let deallocation_amount = if p.1 < current_set.bond {
            // remove from the set
            joining_set.remove(index);
            p.1
          } else {
            joining_set[index] = p;
            amount
          };

          // add to deallocation set
          DeallocatingValidators::<T>::try_mutate_exists(key, |existing| {
            if existing.is_some() {
              existing.as_mut().unwrap().push((p.0, deallocation_amount));
            } else {
              *existing = Some(vec![(p.0, deallocation_amount)]);
            }
            Ok::<_, Error<T>>(())
          })?;

          JoiningValidators::<T>::set(key, joining_set);
          Ok(())
        }
      }
    }

    pub fn genesis_validator_set(network: NetworkId) -> Vec<T::AccountId> {
      let mut current = Vec::new();
      let key = ValidatorSet { session: Session(0), network };
      for p in Self::validator_set(key).unwrap().participants {
        current.push(p.0);
      }
      current
    }

    pub fn next_validator_set(new_index: u32, network: NetworkId) -> Vec<T::AccountId> {
      let mut key = ValidatorSet { session: Session(new_index), network };
      let mut joining = Self::joining_validators(key).iter().map(|(id, _)| *id).collect::<Vec<_>>();
      let leaving = Self::leaving_validators(key).iter().map(|(id, _)| *id).collect::<Vec<_>>();

      // TODO: remove this assert after tests
      assert_eq!(new_index - 2, Self::current_session().0);
      key = ValidatorSet { session: Self::current_session(), network };
      let mut current = Self::validator_set(key)
        .unwrap()
        .participants
        .iter()
        .map(|(id, _)| *id)
        .collect::<Vec<_>>();

      // remove the validators who wanted to leave
      current.retain(|id| !leaving.contains(id));

      // Ignore the ones who is already in the current set.
      // These are the ones who wants to increase their bond,
      // which will happen at the start of the session.
      joining.retain(|id| !current.contains(id));

      // add new ones,
      current.extend(joining);

      current
    }

    /// Makes a new validator set for the given session index with the given `validators`
    /// as participants. All validators in `validators`, must be present either
    /// in `JoiningValidators` or the current active validator set.
    /// Does not fire the `Event::NewSet`, since this expected to fired
    /// prior to this call for a given session index.
    pub fn start_session(new_index: u32, network: NetworkId, validators: Vec<T::AccountId>) {
      // validator sets for index 0 is already set in the genesis build.
      if new_index == 0 {
        return;
      }

      // get the bond of the validators, prepare participants.
      let mut participants = Vec::new();
      let joining =
        JoiningValidators::<T>::get(ValidatorSet { session: Session(new_index), network });
      let leaving =
        DeallocatingValidators::<T>::get(ValidatorSet { session: Session(new_index), network });
      let prev =
        Self::validator_set(ValidatorSet { session: Session(new_index - 1), network }).unwrap();
      for v in validators.into_iter() {
        let mut bond = Amount(0);
        for (id, amount) in prev.participants.iter() {
          if *id == v {
            bond = bond + *amount;
            break;
          }
        }

        for (id, amount) in joining.iter() {
          if *id == v {
            bond = bond + *amount;
            break;
          }
        }

        for (id, amount) in leaving.iter() {
          if *id == v {
            bond = bond - *amount;
            break;
          }
        }

        if bond == Amount(0) {
          panic!("Something went horribly wrong. Session validator {v:?} wasn't in any set.");
        }

        participants.push((v, bond));
      }

      // insert the new set for the session
      let new_set = ValidatorSet { session: Session(new_index), network };
      let new_data = ValidatorSetData {
        bond: prev.bond,
        network: prev.network,
        participants: BoundedVec::try_from(participants).unwrap(),
      };
      ValidatorSets::<T>::set(new_set, Some(new_data));

      // update the current session index
      CurrentSessionIndex::<T>::mutate(|v| {
        *v = Session(new_index);
      });
    }

    pub fn end_session(_: NetworkId) {}
  }

  #[pallet::call]
  impl<T: Config> Pallet<T> {
    #[pallet::call_index(0)]
    #[pallet::weight(0)] // TODO
    pub fn set_keys(
      origin: OriginFor<T>,
      network: NetworkId,
      key_pair: KeyPair,
      signature: Signature,
    ) -> DispatchResult {
      ensure_none(origin)?;

      let session = Self::current_session();

      // Confirm a key hasn't been set for this set instance
      let set = ValidatorSet { session, network };
      // TODO: Is this needed? validate_unsigned should be called before this and ensure it's Ok
      Self::verify_signature(set, &key_pair, &signature)?;

      Keys::<T>::set(set, Some(key_pair.clone()));
      Self::deposit_event(Event::KeyGen { set, key_pair });

      Ok(())
    }
  }

  #[pallet::validate_unsigned]
  impl<T: Config> ValidateUnsigned for Pallet<T> {
    type Call = Call<T>;

    fn validate_unsigned(_: TransactionSource, call: &Self::Call) -> TransactionValidity {
      // Match to be exhaustive
      let (network, key_pair, signature) = match call {
        Call::set_keys { network, ref key_pair, ref signature } => (network, key_pair, signature),
        Call::__Ignore(_, _) => unreachable!(),
      };

      let session = Self::current_session();

      let set = ValidatorSet { session, network: *network };
      match Self::verify_signature(set, key_pair, signature) {
        Err(Error::AlreadyGeneratedKeys) => Err(InvalidTransaction::Stale)?,
        Err(Error::NonExistentValidatorSet) |
        Err(Error::BadSignature) |
        Err(Error::NonExistentValidator) |
        Err(Error::InSufficientAllocation) => Err(InvalidTransaction::BadProof)?,
        Err(Error::__Ignore(_, _)) | Err(Error::InSufficientBond) => unreachable!(),
        Ok(()) => (),
      }

      ValidTransaction::with_tag_prefix("validator-sets")
        .and_provides(set)
        // Set a 10 block longevity, though this should be included in the next block
        .longevity(10)
        .propagate(true)
        .build()
    }
  }
}

pub use pallet::*;
