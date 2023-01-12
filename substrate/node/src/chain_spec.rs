use sp_core::{Decode, Pair as PairTrait, sr25519::Pair};
use sp_runtime::traits::TrailingZeroInput;

use sc_service::ChainType;

use serai_primitives::*;
use pallet_tendermint::crypto::Public;

use serai_runtime::{
  WASM_BINARY, opaque::SessionKeys, GenesisConfig, SystemConfig, BalancesConfig,
  AssetsConfig, ValidatorSetsConfig, SessionConfig,
};

pub type ChainSpec = sc_service::GenericChainSpec<GenesisConfig>;

fn insecure_pair_from_name(name: &'static str) -> Pair {
  Pair::from_string(&format!("//{name}"), None).unwrap()
}

fn address_from_name(name: &'static str) -> NativeAddress {
  insecure_pair_from_name(name).public()
}

fn testnet_genesis(
  wasm_binary: &[u8],
  validators: &[&'static str],
  endowed_accounts: Vec<NativeAddress>,
) -> GenesisConfig {
  let session_key = |name| {
    let key = address_from_name(name);
    (key, key, SessionKeys { tendermint: Public::from(key) })
  };

  // TODO: Replace with a call to the pallet to ask for its account
  let owner = NativeAddress::decode(&mut TrailingZeroInput::new(b"tokens")).unwrap();

  GenesisConfig {
    system: SystemConfig { code: wasm_binary.to_vec() },
    balances: BalancesConfig {
      balances: endowed_accounts.iter().cloned().map(|k| (k, 1 << 60)).collect(),
    },
    assets: AssetsConfig {
      assets: [BITCOIN, ETHER, DAI, MONERO].iter().map(|coin| (*coin, owner, true, 1)).collect(),
      metadata: vec![
        (BITCOIN, b"Bitcoin".to_vec(), b"BTC".to_vec(), 8),
        // Reduce to 8 decimals to feasibly fit within u64 (instead of its native u256)
        (ETHER, b"Ether".to_vec(), b"ETH".to_vec(), 8),
        (DAI, b"Dai Stablecoin".to_vec(), b"DAI".to_vec(), 8),
        (MONERO, b"Monero".to_vec(), b"XMR".to_vec(), 12),
      ],
      accounts: vec![],
    },
    transaction_payment: Default::default(),

    validator_sets: ValidatorSetsConfig {
      bond: Amount(1_000_000) * COIN,
      coins: Coin(4),
      participants: validators.iter().map(|name| address_from_name(name)).collect(),
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
          address_from_name("Alice"),
          address_from_name("Bob"),
          address_from_name("Charlie"),
          address_from_name("Dave"),
          address_from_name("Eve"),
          address_from_name("Ferdie"),
          address_from_name("Alice//stash"),
          address_from_name("Bob//stash"),
          address_from_name("Charlie//stash"),
          address_from_name("Dave//stash"),
          address_from_name("Eve//stash"),
          address_from_name("Ferdie//stash"),
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
          address_from_name("Alice"),
          address_from_name("Bob"),
          address_from_name("Charlie"),
          address_from_name("Dave"),
          address_from_name("Eve"),
          address_from_name("Ferdie"),
          address_from_name("Alice//stash"),
          address_from_name("Bob//stash"),
          address_from_name("Charlie//stash"),
          address_from_name("Dave//stash"),
          address_from_name("Eve//stash"),
          address_from_name("Ferdie//stash"),
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
