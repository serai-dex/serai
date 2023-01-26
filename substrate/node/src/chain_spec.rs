use sp_core::Pair as PairTrait;

use sc_service::ChainType;

use serai_runtime::{
  primitives::*, tokens::primitives::ADDRESS as TOKENS_ADDRESS, tendermint::crypto::Public,
  WASM_BINARY, opaque::SessionKeys, GenesisConfig, SystemConfig, BalancesConfig, AssetsConfig,
  ValidatorSetsConfig, SessionConfig,
};

pub type ChainSpec = sc_service::GenericChainSpec<GenesisConfig>;

fn account_from_name(name: &'static str) -> PublicKey {
  insecure_pair_from_name(name).public()
}

fn testnet_genesis(
  wasm_binary: &[u8],
  validators: &[&'static str],
  endowed_accounts: Vec<PublicKey>,
) -> GenesisConfig {
  let session_key = |name| {
    let key = account_from_name(name);
    (key, key, SessionKeys { tendermint: Public::from(key) })
  };

  GenesisConfig {
    system: SystemConfig { code: wasm_binary.to_vec() },

    balances: BalancesConfig {
      balances: endowed_accounts.iter().cloned().map(|k| (k, 1 << 60)).collect(),
    },
    transaction_payment: Default::default(),

    assets: AssetsConfig {
      assets: [BITCOIN, ETHER, DAI, MONERO]
        .iter()
        .map(|coin| (*coin, TOKENS_ADDRESS.into(), true, 1))
        .collect(),
      metadata: vec![
        (BITCOIN, b"Bitcoin".to_vec(), b"BTC".to_vec(), 8),
        // Reduce to 8 decimals to feasibly fit within u64 (instead of its native u256)
        (ETHER, b"Ether".to_vec(), b"ETH".to_vec(), 8),
        (DAI, b"Dai Stablecoin".to_vec(), b"DAI".to_vec(), 8),
        (MONERO, b"Monero".to_vec(), b"XMR".to_vec(), 12),
      ],
      accounts: vec![],
    },

    session: SessionConfig { keys: validators.iter().map(|name| session_key(*name)).collect() },
    validator_sets: ValidatorSetsConfig {
      bond: Amount(1_000_000 * 10_u64.pow(8)),
      coins: vec![BITCOIN, ETHER, DAI, MONERO],
      participants: validators.iter().map(|name| account_from_name(name)).collect(),
    },
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
          account_from_name("Alice//stash"),
          account_from_name("Bob//stash"),
          account_from_name("Charlie//stash"),
          account_from_name("Dave//stash"),
          account_from_name("Eve//stash"),
          account_from_name("Ferdie//stash"),
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
          account_from_name("Alice"),
          account_from_name("Bob"),
          account_from_name("Charlie"),
          account_from_name("Dave"),
          account_from_name("Eve"),
          account_from_name("Ferdie"),
          account_from_name("Alice//stash"),
          account_from_name("Bob//stash"),
          account_from_name("Charlie//stash"),
          account_from_name("Dave//stash"),
          account_from_name("Eve//stash"),
          account_from_name("Ferdie//stash"),
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
