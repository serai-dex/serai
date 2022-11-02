use sc_service::ChainType;

use sp_core::{Pair as PairTrait, sr25519::Pair};
use pallet_tendermint::crypto::Public;

use serai_runtime::{
  WASM_BINARY, AccountId, opaque::SessionKeys, GenesisConfig, SystemConfig, BalancesConfig,
  SessionConfig,
};

pub type ChainSpec = sc_service::GenericChainSpec<GenesisConfig>;

fn insecure_pair_from_name(name: &'static str) -> Pair {
  Pair::from_string(&format!("//{}", name), None).unwrap()
}

fn account_id_from_name(name: &'static str) -> AccountId {
  insecure_pair_from_name(name).public()
}

fn testnet_genesis(wasm_binary: &[u8], endowed_accounts: Vec<AccountId>) -> GenesisConfig {
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
    session: SessionConfig {
      keys: vec![session_key("Alice"), session_key("Bob"), session_key("Charlie")],
    },
  }
}

pub fn development_config() -> Result<ChainSpec, &'static str> {
  let wasm_binary = WASM_BINARY.ok_or("Development wasm not available")?;

  Ok(ChainSpec::from_genesis(
    // Name
    "Development Network",
    // ID
    "dev",
    ChainType::Development,
    || {
      testnet_genesis(
        wasm_binary,
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
