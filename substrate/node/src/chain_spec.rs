use core::marker::PhantomData;
use std::collections::HashSet;

use sp_core::{Decode, Pair as PairTrait, sr25519::Public};

use sc_service::ChainType;

use serai_runtime::{
  primitives::*, WASM_BINARY, BABE_GENESIS_EPOCH_CONFIG, RuntimeGenesisConfig, SystemConfig,
  CoinsConfig, ValidatorSetsConfig, SignalsConfig, BabeConfig, GrandpaConfig, EmissionsConfig,
};

pub type ChainSpec = sc_service::GenericChainSpec;

fn account_from_name(name: &'static str) -> PublicKey {
  insecure_pair_from_name(name).public()
}

fn wasm_binary() -> Vec<u8> {
  // TODO: Accept a config of runtime path
  const WASM_PATH: &str = "/runtime/serai.wasm";
  if let Ok(binary) = std::fs::read(WASM_PATH) {
    log::info!("using {WASM_PATH}");
    return binary;
  }
  log::info!("using built-in wasm");
  WASM_BINARY.ok_or("compiled in wasm not available").unwrap().to_vec()
}

fn devnet_genesis(
  validators: &[&'static str],
  endowed_accounts: Vec<PublicKey>,
) -> RuntimeGenesisConfig {
  let validators = validators.iter().map(|name| account_from_name(name)).collect::<Vec<_>>();
  let key_shares = NETWORKS
    .iter()
    .map(|network| match network {
      NetworkId::Serai => (NetworkId::Serai, Amount(50_000 * 10_u64.pow(8))),
      NetworkId::External(ExternalNetworkId::Bitcoin) => {
        (NetworkId::External(ExternalNetworkId::Bitcoin), Amount(1_000_000 * 10_u64.pow(8)))
      }
      NetworkId::External(ExternalNetworkId::Ethereum) => {
        (NetworkId::External(ExternalNetworkId::Ethereum), Amount(1_000_000 * 10_u64.pow(8)))
      }
      NetworkId::External(ExternalNetworkId::Monero) => {
        (NetworkId::External(ExternalNetworkId::Monero), Amount(100_000 * 10_u64.pow(8)))
      }
    })
    .collect::<Vec<_>>();

  RuntimeGenesisConfig {
    system: SystemConfig { _config: PhantomData },

    transaction_payment: Default::default(),

    coins: CoinsConfig {
      accounts: endowed_accounts
        .into_iter()
        .map(|a| (a, Balance { coin: Coin::Serai, amount: Amount(1 << 60) }))
        .collect(),
      _ignore: Default::default(),
    },

    validator_sets: ValidatorSetsConfig {
      networks: key_shares.clone(),
      participants: validators.clone(),
    },
    emissions: EmissionsConfig { networks: key_shares, participants: validators.clone() },
    signals: SignalsConfig::default(),
    babe: BabeConfig {
      authorities: validators.iter().map(|validator| ((*validator).into(), 1)).collect(),
      epoch_config: BABE_GENESIS_EPOCH_CONFIG,
      _config: PhantomData,
    },
    grandpa: GrandpaConfig {
      authorities: validators.into_iter().map(|validator| (validator.into(), 1)).collect(),
      _config: PhantomData,
    },
  }
}

fn testnet_genesis(validators: Vec<&'static str>) -> RuntimeGenesisConfig {
  let validators = validators
    .into_iter()
    .map(|validator| Public::decode(&mut hex::decode(validator).unwrap().as_slice()).unwrap())
    .collect::<Vec<_>>();
  let key_shares = NETWORKS
    .iter()
    .map(|network| match network {
      NetworkId::Serai => (NetworkId::Serai, Amount(50_000 * 10_u64.pow(8))),
      NetworkId::External(ExternalNetworkId::Bitcoin) => {
        (NetworkId::External(ExternalNetworkId::Bitcoin), Amount(1_000_000 * 10_u64.pow(8)))
      }
      NetworkId::External(ExternalNetworkId::Ethereum) => {
        (NetworkId::External(ExternalNetworkId::Ethereum), Amount(1_000_000 * 10_u64.pow(8)))
      }
      NetworkId::External(ExternalNetworkId::Monero) => {
        (NetworkId::External(ExternalNetworkId::Monero), Amount(100_000 * 10_u64.pow(8)))
      }
    })
    .collect::<Vec<_>>();

  assert_eq!(validators.iter().collect::<HashSet<_>>().len(), validators.len());

  RuntimeGenesisConfig {
    system: SystemConfig { _config: PhantomData },

    transaction_payment: Default::default(),

    coins: CoinsConfig {
      accounts: validators
        .iter()
        .map(|a| (*a, Balance { coin: Coin::Serai, amount: Amount(5_000_000 * 10_u64.pow(8)) }))
        .collect(),
      _ignore: Default::default(),
    },

    validator_sets: ValidatorSetsConfig {
      networks: key_shares.clone(),
      participants: validators.clone(),
    },
    emissions: EmissionsConfig { networks: key_shares, participants: validators.clone() },
    signals: SignalsConfig::default(),
    babe: BabeConfig {
      authorities: validators.iter().map(|validator| ((*validator).into(), 1)).collect(),
      epoch_config: BABE_GENESIS_EPOCH_CONFIG,
      _config: PhantomData,
    },
    grandpa: GrandpaConfig {
      authorities: validators.into_iter().map(|validator| (validator.into(), 1)).collect(),
      _config: PhantomData,
    },
  }
}

fn genesis(
  name: &'static str,
  id: &'static str,
  chain_type: ChainType,
  protocol_id: &'static str,
  config: &RuntimeGenesisConfig,
) -> ChainSpec {
  use sp_core::{
    Encode,
    traits::{RuntimeCode, WrappedRuntimeCode, CodeExecutor},
  };
  use sp_runtime::BuildStorage;

  let bin = wasm_binary();
  let hash = sp_core::blake2_256(&bin).to_vec();

  let chain_spec = sc_chain_spec::ChainSpecBuilder::new(&bin, None)
    .with_name(name)
    .with_id(id)
    .with_chain_type(chain_type)
    .with_protocol_id(protocol_id)
    .build();

  let mut ext = sp_state_machine::BasicExternalities::new_empty();
  let code_fetcher = WrappedRuntimeCode(bin.into());
  sc_executor::WasmExecutor::<sp_io::SubstrateHostFunctions>::builder()
    .with_allow_missing_host_functions(true)
    .build()
    .call(
      &mut ext,
      &RuntimeCode { heap_pages: None, code_fetcher: &code_fetcher, hash },
      "GenesisApi_build",
      &config.encode(),
      sp_core::traits::CallContext::Onchain,
    )
    .0
    .unwrap();
  chain_spec.assimilate_storage(&mut ext.into_storages()).unwrap();

  chain_spec
}

pub fn development_config() -> ChainSpec {
  genesis(
    "Development Network",
    "devnet",
    ChainType::Development,
    "serai-devnet",
    &devnet_genesis(
      &["Alice"],
      vec![
        account_from_name("Alice"),
        account_from_name("Bob"),
        account_from_name("Charlie"),
        account_from_name("Dave"),
        account_from_name("Eve"),
        account_from_name("Ferdie"),
      ],
    ),
  )
}

pub fn local_config() -> ChainSpec {
  genesis(
    "Local Test Network",
    "local",
    ChainType::Local,
    "serai-local",
    &devnet_genesis(
      &["Alice", "Bob", "Charlie", "Dave"],
      vec![
        account_from_name("Alice"),
        account_from_name("Bob"),
        account_from_name("Charlie"),
        account_from_name("Dave"),
        account_from_name("Eve"),
        account_from_name("Ferdie"),
      ],
    ),
  )
}

#[allow(clippy::redundant_closure_call)]
pub fn testnet_config() -> ChainSpec {
  genesis(
    "Test Network 0",
    "testnet-0",
    ChainType::Live,
    "serai-testnet-0",
    &(move || {
      let _ = testnet_genesis(vec![]);
      todo!("TODO")
    })(),
  )
}

pub fn bootnode_multiaddrs(id: &str) -> Vec<libp2p::Multiaddr> {
  match id {
    "devnet" | "local" => vec![],
    "testnet-0" => todo!("TODO"),
    _ => panic!("unrecognized network ID"),
  }
}
