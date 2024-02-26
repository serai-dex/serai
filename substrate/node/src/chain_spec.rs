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
        .map(|a| (*a, Balance { coin: Coin::Serai, amount: Amount(1 << 60) }))
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

pub fn development_config() -> Result<ChainSpec, &'static str> {
  let wasm_binary = WASM_BINARY.ok_or("Development wasm not available")?;

  Ok(ChainSpec::from_genesis(
    // Name
    "Development Network",
    // ID
    "devnet",
    ChainType::Development,
    || {
      devnet_genesis(
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
    Some("serai-devnet"),
    // Fork ID
    None,
    // Properties
    None,
    // Extensions
    None,
  ))
}

pub fn local_config() -> Result<ChainSpec, &'static str> {
  let wasm_binary = WASM_BINARY.ok_or("Local wasm not available")?;

  Ok(ChainSpec::from_genesis(
    // Name
    "Local Test Network",
    // ID
    "local",
    ChainType::Local,
    || {
      devnet_genesis(
        wasm_binary,
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
  ))
}

pub fn testnet_config() -> Result<ChainSpec, &'static str> {
  let wasm_binary = WASM_BINARY.ok_or("Testnet wasm not available")?;

  let bootnode_multiaddrs: Vec<libp2p::Multiaddr> = vec![
    "/ip6/2604:180:f1::70/tcp/30333".parse().unwrap(),
    "/ip4/103.18.20.202/tcp/30333".parse().unwrap(),
    "/ip4/37.60.255.101/tcp/30333".parse().unwrap(),
    "/ip4/23.227.173.218/tcp/30333".parse().unwrap(),
    "/ip4/65.21.156.202/tcp/30333".parse().unwrap(),
    "/ip4/174.3.203.20/tcp/30333".parse().unwrap(),
    "/ip4/51.195.60.217/tcp/30333".parse().unwrap(),
  ];
  // Transforms the above Multiaddrs into MultiaddrWithPeerIds
  // While the PeerIds *should* be known in advance and hardcoded, that data wasn't collected in
  // time and this fine for a testnet
  let bootnodes = || async {
    #[rustfmt::skip]
    use libp2p::{
      Transport as TransportTrait, OutboundUpgrade, tcp::tokio::Transport, noise::Config
    };
    let mut tasks = vec![];
    for multiaddr in bootnode_multiaddrs {
      tasks.push(tokio::time::timeout(
        core::time::Duration::from_secs(30),
        tokio::task::spawn(async {
          let Ok(transport) = Transport::default().dial(multiaddr.clone()) else { None? };
          let Ok(transport) = transport.await else { None? };
          // Uses a random key pair as we only care about their ID
          let Ok(noise) = Config::new(&sc_network::Keypair::generate_ed25519()) else { None? };
          let Ok(result) = noise.upgrade_outbound(transport, "/ipfs/id/1.0.0").await else { None? };
          let peer_id = result.0;
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

  Ok(ChainSpec::from_genesis(
    // Name
    "Test Network 0",
    // ID
    "testnet-0",
    ChainType::Live,
    || {
      testnet_genesis(
        wasm_binary,
        vec![
          // Kayaba
          "4cef4080d00c6ff5ad93d61d1ca631cc10f8c9bd733e8c0c873a85b5fbe5c625",
          // CommunityStaking
          "587723d333049d9f4e6f027bbd701d603544a422329ea4e1027d60f7947e1074",
          // Adorid
          "28800b36a7e92d8c210668ccff4a759d0b179f09178818dc7d7037a057ca8e61",
          // SHossain
          "6e30ec71b331d73992307fa7c53719ff238666d7d895487a1b691cc1e4481344",
          // Yangu
          "c692a906f9c63b7e4d12ad3cde204c6715b9a96b5b8ce565794917b7eaaa5f08",
          // StormyCloud
          "b0ebef6d712b3eb0f01e69a80519e55feff4be8b226fa64d84691e4b3ca2fb38",
          // rlking1255
          "82592430fe65e353510d3c1018cebc9806290e2d9098a94a1190f120f471c52b",
          // Ghalleb
          "48f903ed592638cee1c7f239a6ac14cbb0224a3153cff0f85eb0873113cf163f",
          // monerobull
          "56a2e3b410cb87bdb8125ae19d76a7be042de49693dc27f03e7a0dcc72b42f6c",
          "322a0a63102e4b4ed727a968a6bdcfd1a71af6ed03664d3db8a8ba285e199019",
          // vdo
          "1c87bbcd666099abc1ee2ec3f065abd073c237f95c4d0658b945e9d66d67622d",
          // t-900
          "6a9d5a3ca9422baec670e47238decf4a8515f2de0060b0a566a56dfd72686e52",
          // tappokone
          "36acb4be05513bed670ef3b43dc3a0fdfde8dc45339f81c80b53b2289dc3730c",
          // untraceable
          "46894302ff717b73def8eaa180e5f162e845ef3d0d8aef44fefc8df4c342271f",
          // kim0
          "3e6ed40b3fecd2adf0ba70d1d59b5e07813ee997a0d8400bd2f3bd4444b1ba13",
          // Helios
          "56a0e89cffe57337e9e232e41dca0ad7306a17fa0ca63fbac048190fdd45d511",
          // hbs
          "805a64c49a50adaf2281b54a90cc2ab96410bc4a5faed93b5d5d97c448fba457",
          // ElectricityMachine
          "3e1d8fcfd4887f4c2eb28fda3c8a857c870e6a70ed60ea92ebe11049c3905002",
          // FlyR9
          "2e114afcb26055e7cd337c2d0145e52365142bb850370777a24f83dfa6442c0e",
          // boog900
          "aad4faf130e4d8fc2279ffbd1c166994b581f29148a4331d204f314b7d4c2001",
          // KeepKey
          "a8ba046fa30cd9b734560a89e96315bb15e072596c5929d9e81db1c470c28830",
          // ripplemcgee1
          "02e076222b59189f3e4c24f7cbf66c7c24d33e6b38153022fc61075c619e7b65",
          // krytie
          "82815723c498d2aaaead050e63b979bb49a94a00c97b971c22340dffeaa36829",
          // akil
          "1caffa33b0ea1c7ed95c8450c0baf57baf9e1c1f43af3e28a722ef6d3d4db27e",
          // JimmyT
          "4ee69d489677f915c08328ece5138705d67a40ea598da47b724c10ec89a0253e",
          // Sleipnir
          "0e87d766c9acec45b39445579cd3f40c8a4b42e9a34049bdbef0da83d000410e",
          "c2f96300a956e949883a5e8952270fb8193154a68533d0dd6b10076224e30167",
          "7a66312c53dfb153e842456f4e9a38dcda7e1788a3366df3e54125e29821f870",
          // username12345678901
          "76434119e3c38885e6cda1167571ad2cec46e129a9156fe79cbac66b314e8762",
          // sgp
          "565fe4384ef416f3a29e2d4e9c47fdae0f04c2fc8afb4eb10ad41c519589a04e",
          // jberman
          "b6e23eec7dbdb2bf72a087e335b44464cedfcc11c669033d6e520b3bc8de1650",
          // Eumaios
          "9ec7b5edf854f6285205468ed7402e40e5bed8238dc226dd4fd718a40efdce44",
          // pigeons
          "66c71ebf040542ab467def0ad935ec30ea693953d4322b3b168f6f4e9fcacb63",
          // joe_land1
          "94e25d8247b2f0e718bee169213052c693b78743dd91f403398a8837c34e0e6a",
          // detherminal
          "0852729a8653454e176b8f7a372eb51abccc2b91f548ddaea3e4bc8e35c89452",
          // 0x221f
          "5aa02a2ff0ca8b22b68cb5e6de1c6790db0b8d2eba80e267aae8ab44eb9cc834",
          // Seth For Privacy
          "f8ebbdb8ff2a77527528577bad6fd3297017f7b35a0613ba31d8af8e7e78cd7b",
          // ludo
          "40352580f976f4b69a924034f8a63cf025f64894ff65796750fdccf4646f980f",
          // lemon_respector
          "ce4a4cd996e4601a0226f3c8d9c9cae84519a1a7277b4822e1694b4a8c3ef10b",
          // tuxsudo
          "c6804a561d07d77c2806844a59c24bb9472df16043767721aae0caa20e82391e",
          // Awakeninghumanity.eth
          "5046c9f55a65e08df86c132c142f055db0376563fabc190f47a6851e0ff2af2b",
          // freQniK
          "42cc47732664ffefe8cca0e675015924c0f778840e3c58e39c5db48913b1727a",
          // ART3MIS.CLOUD
          "5c1793880b0c06a5ce232288c7789cf4451ab20a8da49b84c88789965bc67356",
          // Rucknium
          "8cd62eedcda504b3204b5593120863b4316cf84205f6d1cd4652877d724b2151",
          // PotR
          "b29ffbb4a4c0f14eb8c22fabaaacb43f92a62214ff45f0b4f50b7031c3a61a5a",
          // michnovka
          "98db8174ec40046b1bae39cad69ea0000d67e120524d46bc298d167407410618",
          // helpinghand
          "fe563aa039c3499ca379765e63f708cc3bce82145cdc2abb7dbcc94d52eec539",
          // toplel
          "4243da92918333bfc46f4d17ddeda0c3420d920231627dca1b6049f2f13cac6d",
          // clamking
          "941a6efa9e4dee6c3015cc42339fe56f43c2230133787746828befcee957cb1f",
          // worksmarter
          "c4f2f6ffead84fcaa2e3c894d57c342a24c461eab5d1d17cae3d1a9e61d73e46",
          // kgminer
          "8eca72a4bf684d7c4a20a34048003b504a046bce1289d3ae79a3b4422afaf808",
          // Benny
          "74b4f2d2347a4426c536e6ba48efa14b989b05f03c0ea9b1c67b23696c1a831d",
          // Argo
          "4025bbbe9c9be72769a27e5e6a3749782f4c9b2a47624bdcb0bfbd29f5e2056a",
        ],
      )
    },
    // Bootnodes
    tokio::runtime::Handle::current().block_on(bootnodes()),
    // Telemetry
    None,
    // Protocol ID
    Some("serai-testnet-0"),
    // Fork ID
    None,
    // Properties
    None,
    // Extensions
    None,
  ))
}
