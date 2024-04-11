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
  {
    use std::time::{Duration, SystemTime};
    let secs_since_epoch = SystemTime::now()
      .duration_since(SystemTime::UNIX_EPOCH)
      .expect("current time is before the epoch")
      .as_secs();
    let secs_till_start = 1713283200_u64.saturating_sub(secs_since_epoch);
    std::thread::sleep(Duration::from_secs(secs_till_start));
  }

  let wasm_binary = wasm_binary();

  ChainSpec::from_genesis(
    // Name
    "Test Network 2",
    // ID
    "testnet-2",
    ChainType::Live,
    move || {
      testnet_genesis(
        &wasm_binary,
        vec![
          // Kayaba
          "4cef4080d00c6ff5ad93d61d1ca631cc10f8c9bd733e8c0c873a85b5fbe5c625",
          // CommunityStaking
          "587723d333049d9f4e6f027bbd701d603544a422329ea4e1027d60f7947e1074",
          // SHossain
          "6e30ec71b331d73992307fa7c53719ff238666d7d895487a1b691cc1e4481344",
          // StormyCloud
          "b0ebef6d712b3eb0f01e69a80519e55feff4be8b226fa64d84691e4b3ca2fb38",
          // Yangu
          "c692a906f9c63b7e4d12ad3cde204c6715b9a96b5b8ce565794917b7eaaa5f08",
          // t-900
          "6a9d5a3ca9422baec670e47238decf4a8515f2de0060b0a566a56dfd72686e52",
          // tappokone
          "36acb4be05513bed670ef3b43dc3a0fdfde8dc45339f81c80b53b2289dc3730c",
          // Sleipnir
          "0e87d766c9acec45b39445579cd3f40c8a4b42e9a34049bdbef0da83d000410e",
          "c2f96300a956e949883a5e8952270fb8193154a68533d0dd6b10076224e30167",
          "7a66312c53dfb153e842456f4e9a38dcda7e1788a3366df3e54125e29821f870",
          // jberman
          "b6e23eec7dbdb2bf72a087e335b44464cedfcc11c669033d6e520b3bc8de1650",
          // krytie
          "82815723c498d2aaaead050e63b979bb49a94a00c97b971c22340dffeaa36829",
          // toplel
          "4243da92918333bfc46f4d17ddeda0c3420d920231627dca1b6049f2f13cac6d",
          // clamking
          "941a6efa9e4dee6c3015cc42339fe56f43c2230133787746828befcee957cb1f",
          // Helios
          "56a0e89cffe57337e9e232e41dca0ad7306a17fa0ca63fbac048190fdd45d511",
          // akil
          "1caffa33b0ea1c7ed95c8450c0baf57baf9e1c1f43af3e28a722ef6d3d4db27e",
          // Eumaios
          "9ec7b5edf854f6285205468ed7402e40e5bed8238dc226dd4fd718a40efdce44",
          // pigeons
          "66c71ebf040542ab467def0ad935ec30ea693953d4322b3b168f6f4e9fcacb63",
          // joe_land1
          "94e25d8247b2f0e718bee169213052c693b78743dd91f403398a8837c34e0e6a",
          // rlking1255
          "82592430fe65e353510d3c1018cebc9806290e2d9098a94a1190f120f471c52b",
          // Seth For Privacy
          "f8ebbdb8ff2a77527528577bad6fd3297017f7b35a0613ba31d8af8e7e78cd7b",
          // lemon_respector
          "ce4a4cd996e4601a0226f3c8d9c9cae84519a1a7277b4822e1694b4a8c3ef10b",
          // tuxsudo
          "c6804a561d07d77c2806844a59c24bb9472df16043767721aae0caa20e82391e",
          // Awakeninghumanity.eth
          "5046c9f55a65e08df86c132c142f055db0376563fabc190f47a6851e0ff2af2b",
          // ART3MIS.CLOUD
          "5c1793880b0c06a5ce232288c7789cf4451ab20a8da49b84c88789965bc67356",
          // michnovka
          "98db8174ec40046b1bae39cad69ea0000d67e120524d46bc298d167407410618",
          // kgminer
          "8eca72a4bf684d7c4a20a34048003b504a046bce1289d3ae79a3b4422afaf808",
          // Benny
          "74b4f2d2347a4426c536e6ba48efa14b989b05f03c0ea9b1c67b23696c1a831d",
          // Argo
          "4025bbbe9c9be72769a27e5e6a3749782f4c9b2a47624bdcb0bfbd29f5e2056a",
          // vdo
          "1c87bbcd666099abc1ee2ec3f065abd073c237f95c4d0658b945e9d66d67622d",
          // PotR
          "b29ffbb4a4c0f14eb8c22fabaaacb43f92a62214ff45f0b4f50b7031c3a61a5a",
          // Ghalleb
          "48f903ed592638cee1c7f239a6ac14cbb0224a3153cff0f85eb0873113cf163f",
          // monerobull
          "56a2e3b410cb87bdb8125ae19d76a7be042de49693dc27f03e7a0dcc72b42f6c",
          // Adorid
          "3430222157262d6187c4537b026bcbaeb133695bbb512a7be8f25cc5a082d933",
          // KeepKey
          "a0ce13fb50c3d56548334af703b6ffb9a1b2f66e9dccf4a3688140b77fa58a06",
          // Username
          "b0e62f04f625447673a840d9c5f0e5867b355a67b0dee322334dc00925547b71",
          // R0BC0D3R
          "7e32cebc21b7979c36e477f0a849df1830cc052c879baf13107888654c0be654",
        ],
      )
    },
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
    "serai-local" | "serai-devnet" => vec![],
    "serai-testnet-2" => vec![
      // Kayaba
      "/ip4/107.161.20.133/tcp/30333".parse().unwrap(),
      // lemon_respector
      "/ip4/188.66.62.11/tcp/30333".parse().unwrap(),
      // Ghalleb
      "/ip4/65.21.156.202/tcp/30333".parse().unwrap(),
      // ART3MIS.CLOUD
      "/ip4/51.195.60.217/tcp/30333".parse().unwrap(),
    ],
    _ => panic!("requesting bootnodes for an unrecognized network"),
  }
}
