use core::marker::PhantomData;

use sp_core::Pair as PairTrait;

use sc_service::ChainType;

use serai_runtime::{
  primitives::*, tokens::primitives::ADDRESS as TOKENS_ADDRESS, WASM_BINARY, opaque::SessionKeys,
  BABE_GENESIS_EPOCH_CONFIG, RuntimeGenesisConfig, SystemConfig, BalancesConfig, AssetsConfig,
  ValidatorSetsConfig, SessionConfig, BabeConfig, GrandpaConfig, AuthorityDiscoveryConfig,
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
      SessionKeys { babe: key.into(), grandpa: key.into(), authority_discovery: key.into() },
    )
  };

  RuntimeGenesisConfig {
    system: SystemConfig { code: wasm_binary.to_vec(), _config: PhantomData },

    balances: BalancesConfig {
      balances: endowed_accounts.iter().cloned().map(|k| (k, 1 << 60)).collect(),
    },
    transaction_payment: Default::default(),

    assets: AssetsConfig {
      assets: [Coin::Bitcoin, Coin::Ether, Coin::Dai, Coin::Monero]
        .iter()
        .map(|coin| (*coin, TOKENS_ADDRESS.into(), true, 1))
        .collect(),
      metadata: vec![
        (Coin::Bitcoin, b"Bitcoin".to_vec(), b"BTC".to_vec(), 8),
        // Reduce to 8 decimals to feasibly fit within u64 (instead of its native u256)
        (Coin::Ether, b"Ether".to_vec(), b"ETH".to_vec(), 8),
        (Coin::Dai, b"Dai Stablecoin".to_vec(), b"DAI".to_vec(), 8),
        (Coin::Monero, b"Monero".to_vec(), b"XMR".to_vec(), 12),
      ],
      accounts: vec![],
    },

    validator_sets: ValidatorSetsConfig {
      bond: Amount(1_000_000 * 10_u64.pow(8)),
      networks: vec![
        (NetworkId::Bitcoin, NETWORKS[&NetworkId::Bitcoin].clone()),
        (NetworkId::Ethereum, NETWORKS[&NetworkId::Ethereum].clone()),
        (NetworkId::Monero, NETWORKS[&NetworkId::Monero].clone()),
      ],
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
        &["Alice", "Bob", "Charlie"],
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
