use core::marker::PhantomData;

use sp_core::Pair as PairTrait;

use sc_service::ChainType;

use rand_core::OsRng;
use zeroize::Zeroizing;
use ciphersuite::{
  group::{ff::Field, GroupEncoding},
  WrappedGroup, Ciphersuite,
};
use embedwards25519::Embedwards25519;
use secq256k1::Secq256k1;

use serai_abi::{
  primitives::{
    prelude::*,
    crypto::{Public, SignedEmbeddedEllipticCurveKeys},
  },
  SubstrateBlock as Block,
};
use serai_runtime::*;

pub type ChainSpec = sc_service::GenericChainSpec;

fn insecure_account_from_name(name: &'static str) -> Public {
  sp_core::sr25519::Pair::from_string(&format!("//{name}"), None).unwrap().public().into()
}

fn insecure_embedded_elliptic_curve_keys(
  name: &'static str,
) -> Vec<SignedEmbeddedEllipticCurveKeys> {
  vec![
    SignedEmbeddedEllipticCurveKeys::bitcoin(
      &mut OsRng,
      insecure_account_from_name(name),
      &Zeroizing::new(<Embedwards25519 as WrappedGroup>::F::random(&mut OsRng)),
      &Zeroizing::new(<Secq256k1 as WrappedGroup>::F::random(&mut OsRng)),
    ),
    SignedEmbeddedEllipticCurveKeys::ethereum(
      &mut OsRng,
      insecure_account_from_name(name),
      &Zeroizing::new(<Embedwards25519 as WrappedGroup>::F::random(&mut OsRng)),
      &Zeroizing::new(<Secq256k1 as WrappedGroup>::F::random(&mut OsRng)),
    ),
    SignedEmbeddedEllipticCurveKeys::monero(
      &mut OsRng,
      insecure_account_from_name(name),
      &Zeroizing::new(<Embedwards25519 as WrappedGroup>::F::random(&mut OsRng)),
    ),
  ]
}

fn wasm_binary() -> Vec<u8> {
  // TODO: Accept a config of runtime path
  const DEFAULT_WASM_PATH: &str = "/runtime/serai.wasm";
  let path = serai_env::var("SERAI_WASM").unwrap_or(DEFAULT_WASM_PATH.to_string());
  if let Ok(binary) = std::fs::read(&path) {
    log::info!("using {path} for the WASM");
    return binary;
  }
  log::info!("using built-in wasm");
  WASM_BINARY.ok_or("compiled in wasm not available").unwrap().to_vec()
}

fn devnet_genesis(
  validators: &[&'static str],
  endowed_accounts: Vec<Public>,
) -> RuntimeGenesisConfig {
  let validators = validators
    .iter()
    .map(|name| (insecure_account_from_name(name), insecure_embedded_elliptic_curve_keys(name)))
    .collect::<Vec<_>>();

  RuntimeGenesisConfig {
    system: SystemConfig { _config: PhantomData },

    coins: CoinsConfig {
      accounts: endowed_accounts
        .into_iter()
        .map(|address| (address.into(), Balance { coin: Coin::Serai, amount: Amount(1 << 60) }))
        .collect(),
      _instance: PhantomData,
    },

    liquidity_tokens: LiquidityTokensConfig { accounts: vec![], _instance: PhantomData },

    validator_sets: ValidatorSetsConfig {
      participants: validators
        .iter()
        .map(|validator| (validator.0.into(), validator.1.clone()))
        .collect(),
    },
    signals: SignalsConfig::default(),
    babe: BabeConfig {
      // We leave this empty as `serai-validator-sets-pallet` initializes the authorities
      authorities: vec![],
      epoch_config: BABE_GENESIS_EPOCH_CONFIG,
      _config: PhantomData,
    },
    grandpa: GrandpaConfig { authorities: vec![], _config: PhantomData },
  }
}

/*
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

    coins: CoinsConfig {
      accounts: validators
        .iter()
        .map(|a| (*a, Balance { coin: Coin::Serai, amount: Amount(5_000_000 * 10_u64.pow(8)) }))
        .collect(),
    },

    validator_sets: ValidatorSetsConfig {
      participants: validators.clone(),
    },
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
*/

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
  use sc_service::ChainSpec as _;

  let bin = wasm_binary();
  let hash = sp_core::blake2_256(&bin).to_vec();

  let mut chain_spec = sc_chain_spec::ChainSpecBuilder::new(&bin, None)
    .with_name(name)
    .with_id(id)
    .with_chain_type(chain_type)
    .with_protocol_id(protocol_id)
    .build();

  let mut ext = sp_state_machine::BasicExternalities::new_empty();
  let code_fetcher = WrappedRuntimeCode(bin.clone().into());
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
  let mut storage = ext.into_storages();
  storage.top.insert(sp_core::storage::well_known_keys::CODE.to_vec(), bin);
  chain_spec.set_storage(storage);

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
        insecure_account_from_name("Alice"),
        insecure_account_from_name("Bob"),
        insecure_account_from_name("Charlie"),
        insecure_account_from_name("Dave"),
        insecure_account_from_name("Eve"),
        insecure_account_from_name("Ferdie"),
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
        insecure_account_from_name("Alice"),
        insecure_account_from_name("Bob"),
        insecure_account_from_name("Charlie"),
        insecure_account_from_name("Dave"),
        insecure_account_from_name("Eve"),
        insecure_account_from_name("Ferdie"),
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
      // let _ = testnet_genesis(vec![]);
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
