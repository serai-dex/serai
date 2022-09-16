use sc_service::ChainType;

use sp_runtime::traits::Verify;
use sp_core::{sr25519, Pair, Public};

use sp_runtime::traits::IdentifyAccount;

use serai_runtime::{WASM_BINARY, AccountId, Signature, GenesisConfig, SystemConfig, BalancesConfig};

pub type ChainSpec = sc_service::GenericChainSpec<GenesisConfig>;
type AccountPublic = <Signature as Verify>::Signer;

fn get_from_seed<TPublic: Public>(seed: &'static str) -> <TPublic::Pair as Pair>::Public {
  TPublic::Pair::from_string(&format!("//{}", seed), None).unwrap().public()
}

fn get_account_id_from_seed<TPublic: Public>(seed: &'static str) -> AccountId
where
  AccountPublic: From<<TPublic::Pair as Pair>::Public>,
{
  AccountPublic::from(get_from_seed::<TPublic>(seed)).into_account()
}

fn testnet_genesis(wasm_binary: &[u8], endowed_accounts: Vec<AccountId>) -> GenesisConfig {
  GenesisConfig {
    system: SystemConfig { code: wasm_binary.to_vec() },
    balances: BalancesConfig {
      balances: endowed_accounts.iter().cloned().map(|k| (k, 1 << 60)).collect(),
    },
    transaction_payment: Default::default(),
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
          get_account_id_from_seed::<sr25519::Public>("Alice"),
          get_account_id_from_seed::<sr25519::Public>("Bob"),
          get_account_id_from_seed::<sr25519::Public>("Charlie"),
          get_account_id_from_seed::<sr25519::Public>("Dave"),
          get_account_id_from_seed::<sr25519::Public>("Eve"),
          get_account_id_from_seed::<sr25519::Public>("Ferdie"),
          get_account_id_from_seed::<sr25519::Public>("Alice//stash"),
          get_account_id_from_seed::<sr25519::Public>("Bob//stash"),
          get_account_id_from_seed::<sr25519::Public>("Charlie//stash"),
          get_account_id_from_seed::<sr25519::Public>("Dave//stash"),
          get_account_id_from_seed::<sr25519::Public>("Eve//stash"),
          get_account_id_from_seed::<sr25519::Public>("Ferdie//stash"),
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
