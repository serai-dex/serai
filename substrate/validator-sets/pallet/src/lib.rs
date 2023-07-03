#![cfg_attr(not(feature = "std"), no_std)]

#[allow(deprecated, clippy::let_unit_value)] // TODO
#[frame_support::pallet]
pub mod pallet {
  use scale_info::TypeInfo;

  use sp_core::sr25519::{Public, Signature};
  use sp_std::vec::Vec;
  use sp_application_crypto::RuntimePublic;

  use frame_system::pallet_prelude::*;
  use frame_support::pallet_prelude::*;

  use serai_primitives::*;
  pub use validator_sets_primitives as primitives;
  use primitives::*;

  #[pallet::config]
  pub trait Config: frame_system::Config<AccountId = Public> + TypeInfo {
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

  #[pallet::event]
  #[pallet::generate_deposit(pub(super) fn deposit_event)]
  pub enum Event<T: Config> {
    NewSet { set: ValidatorSet },
    KeyGen { set: ValidatorSet, key_pair: KeyPair },
  }

  #[pallet::genesis_build]
  impl<T: Config> GenesisBuild<T> for GenesisConfig<T> {
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

      let Some(musig_key) = MuSigKeys::<T>::get(set) else {
        Err(Error::NonExistentValidatorSet)?
      };
      if !musig_key.verify(&set_keys_message(&set, key_pair), signature) {
        Err(Error::BadSignature)?;
      }

      Ok(())
    }
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

      // TODO: Get session
      let session: Session = Session(0);

      // Confirm a key hasn't been set for this set instance
      let set = ValidatorSet { session, network };
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

      // TODO: Get the latest session
      let session = Session(0);

      let set = ValidatorSet { session, network: *network };
      match Self::verify_signature(set, key_pair, signature) {
        Err(Error::AlreadyGeneratedKeys) => Err(InvalidTransaction::Stale)?,
        Err(Error::NonExistentValidatorSet) | Err(Error::BadSignature) => {
          Err(InvalidTransaction::BadProof)?
        }
        Err(Error::__Ignore(_, _)) => unreachable!(),
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

  // TODO: Support session rotation
}

pub use pallet::*;
