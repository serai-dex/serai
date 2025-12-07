use super::*;

/// The lookup for a SeraiAddress -> Public.
pub struct Lookup;
impl sp_runtime::traits::StaticLookup for Lookup {
  type Source = SeraiAddress;
  type Target = Public;
  fn lookup(source: SeraiAddress) -> Result<Public, sp_runtime::traits::LookupError> {
    Ok(source.into())
  }
  fn unlookup(source: Public) -> SeraiAddress {
    source.into()
  }
}

/// The runtime version.
pub struct Version;
// TODO: Are we reasonably able to prune `RuntimeVersion` from Substrate?
impl Get<RuntimeVersion> for Version {
  fn get() -> RuntimeVersion {
    #[sp_version::runtime_version]
    pub const VERSION: RuntimeVersion = RuntimeVersion {
      spec_name: Cow::Borrowed("serai"),
      impl_name: Cow::Borrowed("core"),
      authoring_version: 0,
      spec_version: 0,
      impl_version: 0,
      apis: RUNTIME_API_VERSIONS,
      transaction_version: 0,
      system_version: 0,
    };
    VERSION
  }
}

impl frame_system::Config for Runtime {
  type RuntimeOrigin = RuntimeOrigin;
  type RuntimeCall = RuntimeCall;
  type RuntimeEvent = RuntimeEvent;
  type PalletInfo = PalletInfo;

  type Hashing = sp_runtime::traits::BlakeTwo256;
  type Hash = <Self::Block as sp_runtime::traits::Block>::Hash;

  type Block = Block;
  type AccountId = sp_core::sr25519::Public;
  type Lookup = Lookup;
  type Nonce = u32;

  type PreInherents = serai_core_pallet::StartOfBlock<Runtime>;
  type PostInherents = ();
  type PostTransactions = serai_core_pallet::EndOfBlock<Runtime>;

  /*
    We do not globally filter the types of calls which may be performed. Instead, our ABI only
    exposes the calls we want exposed, and each call individually errors if it's called when it
    shouldn't be.
  */
  type BaseCallFilter = frame_support::traits::Everything;

  /*
    We do not have `frame_system` track historical block hashes by their block number. Instead,
    `serai_core_pallet` populates a hash set (map of `[u8; 32] -> ()`) of all historical block's
    hashes within itself.

    The usage of `1` here is solely as `frame_system` requires it be at least `1`.
  */
  type BlockHashCount = ConstU64<1>;

  type Version = Version;
  type BlockLength = serai_core_pallet::Limits;
  type BlockWeights = serai_core_pallet::Limits;
  // We assume `serai-node` will be run using the RocksDB backend
  type DbWeight = frame_support::weights::constants::RocksDbWeight;
  /*
    Serai does not expose `frame_system::Call`. We accordingly have no consequence to using the
    default weights for these accordingly.
  */
  type SystemWeightInfo = ();

  // We also don't use `frame_system`'s account system at all, leaving us to bottom these out.
  type AccountData = ();
  type MaxConsumers = ConstU32<{ u32::MAX }>;
  type OnNewAccount = ();
  type OnKilledAccount = ();

  // Serai does perform any 'on-chain upgrades' to ensure upgrades are opted into by the entity
  // running this node and accordingly consented to
  type OnSetCode = ();

  // We do not have any migrations declared
  type SingleBlockMigrations = ();
  type MultiBlockMigrator = ();
}
