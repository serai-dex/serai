use std::{boxed::Box, sync::Arc, error::Error};

use sp_runtime::traits::Block as BlockTrait;
use sp_inherents::CreateInherentDataProviders;
use sp_consensus::DisableProofRecording;
use sp_api::ProvideRuntimeApi;

use sc_executor::{NativeVersion, NativeExecutionDispatch, NativeElseWasmExecutor};
use sc_transaction_pool::FullPool;
use sc_network::NetworkService;
use sc_service::TFullClient;

use serai_runtime::{self, opaque::Block, RuntimeApi};

mod types;
use types::{TendermintClientMinimal, TendermintValidator};

mod validators;

pub(crate) mod tendermint;
pub use tendermint::TendermintImport;
mod block_import;

mod import_queue;
pub use import_queue::{TendermintImportQueue, import_queue};

pub(crate) mod gossip;
pub(crate) mod authority;
pub use authority::TendermintAuthority;

mod select_chain;
pub use select_chain::TendermintSelectChain;

const CONSENSUS_ID: [u8; 4] = *b"tend";

pub struct ExecutorDispatch;
impl NativeExecutionDispatch for ExecutorDispatch {
  #[cfg(feature = "runtime-benchmarks")]
  type ExtendHostFunctions = frame_benchmarking::benchmarking::HostFunctions;
  #[cfg(not(feature = "runtime-benchmarks"))]
  type ExtendHostFunctions = ();

  fn dispatch(method: &str, data: &[u8]) -> Option<Vec<u8>> {
    serai_runtime::api::dispatch(method, data)
  }

  fn native_version() -> NativeVersion {
    serai_runtime::native_version()
  }
}

pub type FullClient = TFullClient<Block, RuntimeApi, NativeElseWasmExecutor<ExecutorDispatch>>;

pub struct Cidp;
#[async_trait::async_trait]
impl CreateInherentDataProviders<Block, ()> for Cidp {
  type InherentDataProviders = (sp_timestamp::InherentDataProvider,);
  async fn create_inherent_data_providers(
    &self,
    _: <Block as BlockTrait>::Hash,
    _: (),
  ) -> Result<Self::InherentDataProviders, Box<dyn Send + Sync + Error>> {
    Ok((sp_timestamp::InherentDataProvider::from_system_time(),))
  }
}

pub struct TendermintValidatorFirm;
impl TendermintClientMinimal for TendermintValidatorFirm {
  const BLOCK_TIME_IN_SECONDS: u32 = { (serai_runtime::MILLISECS_PER_BLOCK / 1000) as u32 };

  type Block = Block;
  type Backend = sc_client_db::Backend<Block>;
  type Api = <FullClient as ProvideRuntimeApi<Block>>::Api;
  type Client = FullClient;
}

impl TendermintValidator for TendermintValidatorFirm {
  type CIDP = Cidp;
  type Environment = sc_basic_authorship::ProposerFactory<
    FullPool<Block, FullClient>,
    Self::Backend,
    Self::Client,
    DisableProofRecording,
  >;

  type Network = Arc<NetworkService<Block, <Block as BlockTrait>::Hash>>;
}
