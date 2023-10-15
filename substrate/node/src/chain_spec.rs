use core::marker::PhantomData;

use sp_core::Pair as PairTrait;

use sc_service::ChainType;

use serai_runtime::{
  primitives::*, WASM_BINARY, opaque::SessionKeys, BABE_GENESIS_EPOCH_CONFIG, RuntimeGenesisConfig,
  SystemConfig, ValidatorSetsConfig, SessionConfig, BabeConfig, GrandpaConfig,
  AuthorityDiscoveryConfig, CoinsConfig,
};

pub type ChainSpec = sc_service::GenericChainSpec<RuntimeGenesisConfig>;

fn account_from_name(name: &'static str) -> PublicKey {
  insecure_pair_from_name(name).public()
}

fn testnet_genesis(
  wasm_binary: &[u8],
  validators: &[&'static str],
  endowed_accounts: Vec<PublicKey>,
) -> RuntimeGenesisConfig {
  let session_key = |name| {
    let key = account_from_name(name);
    (
      key,
      key,
      // TODO: Properly diversify these?
      SessionKeys { babe: key.into(), grandpa: key.into(), authority_discovery: key.into() },
    )
  };

  RuntimeGenesisConfig {
    system: SystemConfig { code: wasm_binary.to_vec(), _config: PhantomData },

    transaction_payment: Default::default(),

    coins: CoinsConfig {
      accounts: endowed_accounts.into_iter().map(|a| (a, Coin::Serai, 1 << 60)).collect(),
    },

    validator_sets: ValidatorSetsConfig {
      networks: serai_runtime::primitives::NETWORKS
        .iter()
        .map(|network| match network {
          NetworkId::Serai => (NetworkId::Serai, Amount(50_000 * 10_u64.pow(8))),
          NetworkId::Bitcoin => (NetworkId::Bitcoin, Amount(1_000_000 * 10_u64.pow(8))),
          NetworkId::Ethereum => (NetworkId::Ethereum, Amount(1_000_000 * 10_u64.pow(8))),
          NetworkId::Monero => (NetworkId::Monero, Amount(100_000 * 10_u64.pow(8))),
        })
        .collect(),
      participants: validators.iter().map(|name| account_from_name(name)).collect(),
    },
    session: SessionConfig { keys: validators.iter().map(|name| session_key(*name)).collect() },
    babe: BabeConfig {
      authorities: vec![],
      epoch_config: Some(BABE_GENESIS_EPOCH_CONFIG),
      _config: PhantomData,
    },
    grandpa: GrandpaConfig { authorities: vec![], _config: PhantomData },

    authority_discovery: AuthorityDiscoveryConfig { keys: vec![], _config: PhantomData },
  }
}

pub fn development_config() -> Result<ChainSpec, &'static str> {
  let wasm_binary = WASM_BINARY.ok_or("Development wasm not available")?;

  Ok(ChainSpec::from_genesis(
    // Name
    "Development Network",
    // ID
    "devnet",
    ChainType::Development,
    || {
      testnet_genesis(
        wasm_binary,
        &["Alice"],
        vec![
          account_from_name("Alice"),
          account_from_name("Bob"),
          account_from_name("Charlie"),
          account_from_name("Dave"),
          account_from_name("Eve"),
          account_from_name("Ferdie"),
        ],
      )
    },
    // Bootnodes
    vec![],
    // Telemetry
    None,
    // Protocol ID
    Some("serai"),
    // Fork ID
    None,
    // Properties
    None,
    // Extensions
    None,
  ))
}

pub fn testnet_config() -> Result<ChainSpec, &'static str> {
  let wasm_binary = WASM_BINARY.ok_or("Testnet wasm not available")?;

  Ok(ChainSpec::from_genesis(
    // Name
    "Local Test Network",
    // ID
    "local",
    ChainType::Local,
    || {
      testnet_genesis(
        wasm_binary,
        &["Alice", "Bob", "Charlie", "Dave"],
        vec![
          account_from_name("Alice"),
          account_from_name("Bob"),
          account_from_name("Charlie"),
          account_from_name("Dave"),
          account_from_name("Eve"),
          account_from_name("Ferdie"),
        ],
      )
    },
    // Bootnodes
    vec![],
    // Telemetry
    None,
    // Protocol ID
    Some("serai"),
    // Fork ID
    None,
    // Properties
    None,
    // Extensions
    None,
  ))
}
