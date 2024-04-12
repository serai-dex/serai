use core::marker::PhantomData;
use std::collections::HashSet;

use sp_core::{Decode, Pair as PairTrait, sr25519::Public};

use sc_service::ChainType;

use serai_runtime::{
  primitives::*, WASM_BINARY, BABE_GENESIS_EPOCH_CONFIG, RuntimeGenesisConfig, SystemConfig,
  CoinsConfig, DexConfig, ValidatorSetsConfig, SignalsConfig, BabeConfig, GrandpaConfig,
};

pub type ChainSpec = sc_service::GenericChainSpec<RuntimeGenesisConfig>;

fn account_from_name(name: &'static str) -> PublicKey {
  insecure_pair_from_name(name).public()
}

fn wasm_binary() -> Vec<u8> {
  // TODO: Accept a config of runtime path
  if let Ok(binary) = std::fs::read("/runtime/serai.wasm") {
    return binary;
  }
  WASM_BINARY.ok_or("compiled in wasm not available").unwrap().to_vec()
}

fn devnet_genesis(
  wasm_binary: &[u8],
  validators: &[&'static str],
  endowed_accounts: Vec<PublicKey>,
) -> RuntimeGenesisConfig {
  let validators = validators.iter().map(|name| account_from_name(name)).collect::<Vec<_>>();
  RuntimeGenesisConfig {
    system: SystemConfig { code: wasm_binary.to_vec(), _config: PhantomData },

    transaction_payment: Default::default(),

    coins: CoinsConfig {
      accounts: endowed_accounts
        .into_iter()
        .map(|a| (a, Balance { coin: Coin::Serai, amount: Amount(1 << 60) }))
        .collect(),
      _ignore: Default::default(),
    },

    dex: DexConfig {
      pools: vec![Coin::Bitcoin, Coin::Ether, Coin::Dai, Coin::Monero],
      _ignore: Default::default(),
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
      participants: validators.clone(),
    },
    signals: SignalsConfig::default(),
    babe: BabeConfig {
      authorities: validators.iter().map(|validator| ((*validator).into(), 1)).collect(),
      epoch_config: Some(BABE_GENESIS_EPOCH_CONFIG),
      _config: PhantomData,
    },
    grandpa: GrandpaConfig {
      authorities: validators.into_iter().map(|validator| (validator.into(), 1)).collect(),
      _config: PhantomData,
    },
  }
}

fn testnet_genesis(wasm_binary: &[u8], validators: Vec<&'static str>) -> RuntimeGenesisConfig {
  let validators = validators
    .into_iter()
    .map(|validator| Public::decode(&mut hex::decode(validator).unwrap().as_slice()).unwrap())
    .collect::<Vec<_>>();

  assert_eq!(validators.iter().collect::<HashSet<_>>().len(), validators.len());

  RuntimeGenesisConfig {
    system: SystemConfig { code: wasm_binary.to_vec(), _config: PhantomData },

    transaction_payment: Default::default(),

    coins: CoinsConfig {
      accounts: validators
        .iter()
        .map(|a| (*a, Balance { coin: Coin::Serai, amount: Amount(5_000_000 * 10_u64.pow(8)) }))
        .collect(),
      _ignore: Default::default(),
    },

    dex: DexConfig {
      pools: vec![Coin::Bitcoin, Coin::Ether, Coin::Dai, Coin::Monero],
      _ignore: Default::default(),
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
      participants: validators.clone(),
    },
    signals: SignalsConfig::default(),
    babe: BabeConfig {
      authorities: validators.iter().map(|validator| ((*validator).into(), 1)).collect(),
      epoch_config: Some(BABE_GENESIS_EPOCH_CONFIG),
      _config: PhantomData,
    },
    grandpa: GrandpaConfig {
      authorities: validators.into_iter().map(|validator| (validator.into(), 1)).collect(),
      _config: PhantomData,
    },
  }
}

pub fn development_config() -> ChainSpec {
  let wasm_binary = wasm_binary();

  ChainSpec::from_genesis(
    // Name
    "Development Network",
    // ID
    "devnet",
    ChainType::Development,
    move || {
      devnet_genesis(
        &wasm_binary,
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
    Some("serai-devnet"),
    // Fork ID
    None,
    // Properties
    None,
    // Extensions
    None,
  )
}

pub fn local_config() -> ChainSpec {
  let wasm_binary = wasm_binary();

  ChainSpec::from_genesis(
    // Name
    "Local Test Network",
    // ID
    "local",
    ChainType::Local,
    move || {
      devnet_genesis(
        &wasm_binary,
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
    Some("serai-local"),
    // Fork ID
    None,
    // Properties
    None,
    // Extensions
    None,
  )
}

pub fn testnet_config() -> ChainSpec {
  let wasm_binary = wasm_binary();

  ChainSpec::from_genesis(
    // Name
    "Test Network 2",
    // ID
    "testnet-2",
    ChainType::Live,
    move || { let _ = testnet_genesis(&wasm_binary, vec![]); todo!() },
    // Bootnodes
    vec![],
    // Telemetry
    None,
    // Protocol ID
    Some("serai-testnet-2"),
    // Fork ID
    None,
    // Properties
    None,
    // Extensions
    None,
  )
}

pub fn bootnode_multiaddrs(id: &str) -> Vec<libp2p::Multiaddr> {
  match id {
    "devnet" | "local" => vec![],
    "testnet-2" => todo!(),
    _ => panic!("unrecognized network ID"),
  }
}
