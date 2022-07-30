use frame_system::Config as SysConfig;
use subxt::{Config, ClientBuilder, extrinsic::BaseExtrinsicParams};

use serai_runtime::{Address, Signature, UncheckedExtrinsic, Runtime};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct SeraiConfig;
impl Config for SeraiConfig {
  type BlockNumber = <Runtime as SysConfig>::BlockNumber;

  type Hash = <Runtime as SysConfig>::Hash;
  type Hashing = <Runtime as SysConfig>::Hashing;

  type Index = <Runtime as SysConfig>::Index;
  type AccountId = <Runtime as SysConfig>::AccountId;
  // TODO: Bech32m
  type Address = Address;

  type Header = <Runtime as SysConfig>::Header;
  type Signature = Signature;

  type Extrinsic = UncheckedExtrinsic;
}

// TODO: https://github.com/paritytech/subxt/issues/602
// const METADATA: &str = concat!(env!("OUT_DIR"), "serai.scale");

#[subxt::subxt(runtime_metadata_path = "serai.scale")]
mod runtime {}
type Serai = runtime::RuntimeApi<SeraiConfig, BaseExtrinsicParams<SeraiConfig, ()>>;

pub(crate) async fn new() -> Serai {
  ClientBuilder::new().build().await.unwrap().to_runtime_api::<Serai>()
}
