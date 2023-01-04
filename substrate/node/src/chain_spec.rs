use sp_core::{Pair as PairTrait, sr25519::Pair};
use sc_service::ChainType;

use validator_sets_primitives::{Amount, COIN, Coin};
use pallet_tendermint::crypto::Public;

use serai_runtime::{
  WASM_BINARY, AccountId, opaque::SessionKeys, GenesisConfig, SystemConfig, BalancesConfig,
  ValidatorSetsConfig, SessionConfig,
};

pub type ChainSpec = sc_service::GenericChainSpec<GenesisConfig>;

fn insecure_pair_from_name(name: &'static str) -> Pair {
  Pair::from_string(&format!("//{name}"), None).unwrap()
}

fn account_id_from_name(name: &'static str) -> AccountId {
  insecure_pair_from_name(name).public()
}

fn testnet_genesis(
  wasm_binary: &[u8],
  validators: &[&'static str],
  endowed_accounts: Vec<AccountId>,
) -> GenesisConfig {
  let session_key = |name| {
    let key = account_id_from_name(name);
    (key, key, SessionKeys { tendermint: Public::from(key) })
  };

  GenesisConfig {
    system: SystemConfig { code: wasm_binary.to_vec() },
    balances: BalancesConfig {
      balances: endowed_accounts.iter().cloned().map(|k| (k, 1 << 60)).collect(),
    },
    transaction_payment: Default::default(),

    validator_sets: ValidatorSetsConfig {
      bond: Amount(1_000_000) * COIN,
      coins: Coin(4),
      participants: validators.iter().map(|name| account_id_from_name(name)).collect(),
    },
    session: SessionConfig { keys: validators.iter().map(|name| session_key(*name)).collect() },
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
          account_id_from_name("Alice"),
          account_id_from_name("Bob"),
          account_id_from_name("Charlie"),
          account_id_from_name("Dave"),
          account_id_from_name("Eve"),
          account_id_from_name("Ferdie"),
          account_id_from_name("Alice//stash"),
          account_id_from_name("Bob//stash"),
          account_id_from_name("Charlie//stash"),
          account_id_from_name("Dave//stash"),
          account_id_from_name("Eve//stash"),
          account_id_from_name("Ferdie//stash"),
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
        &["Alice", "Bob", "Charlie"],
        vec![
          account_id_from_name("Alice"),
          account_id_from_name("Bob"),
          account_id_from_name("Charlie"),
          account_id_from_name("Dave"),
          account_id_from_name("Eve"),
          account_id_from_name("Ferdie"),
          account_id_from_name("Alice//stash"),
          account_id_from_name("Bob//stash"),
          account_id_from_name("Charlie//stash"),
          account_id_from_name("Dave//stash"),
          account_id_from_name("Eve//stash"),
          account_id_from_name("Ferdie//stash"),
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
