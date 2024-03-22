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

  let bootnode_multiaddrs: Vec<libp2p::Multiaddr> =
    vec!["/ip4/107.161.20.133/tcp/30333".parse().unwrap()];

  // Transforms the above Multiaddrs into MultiaddrWithPeerIds
  // While the PeerIds *should* be known in advance and hardcoded, that data wasn't collected in
  // time and this fine for a testnet
  let bootnodes = || async {
    use libp2p::{Transport as TransportTrait, tcp::tokio::Transport, noise::Config};
    let mut tasks = vec![];
    for multiaddr in bootnode_multiaddrs {
      tasks.push(tokio::time::timeout(
        core::time::Duration::from_secs(10),
        tokio::task::spawn(async move {
          let Ok(noise) = Config::new(&sc_network::Keypair::generate_ed25519()) else { None? };
          let mut transport = Transport::default()
            .upgrade(libp2p::core::upgrade::Version::V1)
            .authenticate(noise)
            .multiplex(libp2p::yamux::Config::default());
          let Ok(transport) = transport.dial(multiaddr.clone()) else { None? };
          let Ok((peer_id, _)) = transport.await else { None? };
          Some(sc_network::config::MultiaddrWithPeerId { multiaddr, peer_id })
        }),
      ));
    }

    let mut res = vec![];
    for task in tasks {
      if let Ok(Ok(Some(bootnode))) = task.await {
        res.push(bootnode);
      }
    }
    res
  };
  let runtime = tokio::runtime::Runtime::new().unwrap();
  let bootnodes = runtime.block_on(bootnodes());
  runtime.shutdown_background();

  ChainSpec::from_genesis(
    // Name
    "Internal Test Network 0",
    // ID
    "testnet-internal-0",
    ChainType::Live,
    move || {
      testnet_genesis(
        &wasm_binary,
        vec![
          // Kayaba
          "4cef4080d00c6ff5ad93d61d1ca631cc10f8c9bd733e8c0c873a85b5fbe5c625",
          // akil
          "1caffa33b0ea1c7ed95c8450c0baf57baf9e1c1f43af3e28a722ef6d3d4db27e",
          // sgp
          "565fe4384ef416f3a29e2d4e9c47fdae0f04c2fc8afb4eb10ad41c519589a04e",
        ],
      )
    },
    // Bootnodes
    bootnodes,
    // Telemetry
    None,
    // Protocol ID
    Some("serai-testnet-internal-0"),
    // Fork ID
    None,
    // Properties
    None,
    // Extensions
    None,
  )
}
