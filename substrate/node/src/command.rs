use sc_service::PartialComponents;
use frame_benchmarking_cli::{ExtrinsicFactory, BenchmarkCmd, SUBSTRATE_REFERENCE_HARDWARE};
use sc_cli::{ChainSpec, RuntimeVersion, SubstrateCli};

use serai_runtime::Block;

use crate::{
  chain_spec,
  cli::{Cli, Subcommand},
  command_helper::{RemarkBuilder, inherent_benchmark_data},
  service,
};

impl SubstrateCli for Cli {
  fn impl_name() -> String {
    "Serai Node".into()
  }

  fn impl_version() -> String {
    env!("SUBSTRATE_CLI_IMPL_VERSION").to_string()
  }

  fn description() -> String {
    env!("CARGO_PKG_DESCRIPTION").to_string()
  }

  fn author() -> String {
    env!("CARGO_PKG_AUTHORS").to_string()
  }

  fn support_url() -> String {
    "serai.exchange".to_string()
  }

  fn copyright_start_year() -> i32 {
    2022
  }

  fn load_spec(&self, id: &str) -> Result<Box<dyn sc_service::ChainSpec>, String> {
    match id {
      "dev" => Ok(Box::new(chain_spec::development_config()?)),
      _ => panic!("Unknown network ID"),
    }
  }

  fn native_runtime_version(_: &Box<dyn ChainSpec>) -> &'static RuntimeVersion {
    &serai_runtime::VERSION
  }
}

pub fn run() -> sc_cli::Result<()> {
  let cli = Cli::from_args();

  match &cli.subcommand {
    Some(Subcommand::Key(cmd)) => cmd.run(&cli),

    Some(Subcommand::BuildSpec(cmd)) => {
      cli.create_runner(cmd)?.sync_run(|config| cmd.run(config.chain_spec, config.network))
    }

    Some(Subcommand::CheckBlock(cmd)) => cli.create_runner(cmd)?.async_run(|config| {
      let PartialComponents { client, task_manager, import_queue, .. } =
        service::new_partial(&config)?;
      Ok((cmd.run(client, import_queue), task_manager))
    }),

    Some(Subcommand::ExportBlocks(cmd)) => cli.create_runner(cmd)?.async_run(|config| {
      let PartialComponents { client, task_manager, .. } = service::new_partial(&config)?;
      Ok((cmd.run(client, config.database), task_manager))
    }),

    Some(Subcommand::ExportState(cmd)) => cli.create_runner(cmd)?.async_run(|config| {
      let PartialComponents { client, task_manager, .. } = service::new_partial(&config)?;
      Ok((cmd.run(client, config.chain_spec), task_manager))
    }),

    Some(Subcommand::ImportBlocks(cmd)) => cli.create_runner(cmd)?.async_run(|config| {
      let PartialComponents { client, task_manager, import_queue, .. } =
        service::new_partial(&config)?;
      Ok((cmd.run(client, import_queue), task_manager))
    }),

    Some(Subcommand::PurgeChain(cmd)) => {
      cli.create_runner(cmd)?.sync_run(|config| cmd.run(config.database))
    }

    Some(Subcommand::Revert(cmd)) => cli.create_runner(cmd)?.async_run(|config| {
      let PartialComponents { client, task_manager, backend, .. } = service::new_partial(&config)?;
      Ok((cmd.run(client, backend, None), task_manager))
    }),

    Some(Subcommand::Benchmark(cmd)) => cli.create_runner(cmd)?.sync_run(|config| match cmd {
      BenchmarkCmd::Pallet(cmd) => cmd.run::<Block, service::ExecutorDispatch>(config),

      BenchmarkCmd::Block(cmd) => cmd.run(service::new_partial(&config)?.client),

      #[cfg(not(feature = "runtime-benchmarks"))]
      BenchmarkCmd::Storage(_) => {
        Err("Storage benchmarking can be enabled with `--features runtime-benchmarks`.".into())
      }

      #[cfg(feature = "runtime-benchmarks")]
      BenchmarkCmd::Storage(cmd) => {
        let PartialComponents { client, backend, .. } = service::new_partial(&config)?;
        cmd.run(config, client, backend.expose_db(), backend.expose_storage())
      }

      BenchmarkCmd::Overhead(cmd) => {
        let client = service::new_partial(&config)?.client;
        cmd.run(
          config,
          client.clone(),
          inherent_benchmark_data()?,
          vec![],
          &RemarkBuilder::new(client),
        )
      }

      BenchmarkCmd::Extrinsic(cmd) => {
        let PartialComponents { client, .. } = service::new_partial(&config)?;
        cmd.run(
          client.clone(),
          inherent_benchmark_data()?,
          vec![],
          &ExtrinsicFactory(vec![Box::new(RemarkBuilder::new(client))]),
        )
      }

      BenchmarkCmd::Machine(cmd) => cmd.run(&config, SUBSTRATE_REFERENCE_HARDWARE.clone()),
    }),

    Some(Subcommand::ChainInfo(cmd)) => {
      cli.create_runner(cmd)?.sync_run(|config| cmd.run::<Block>(&config))
    }

    None => cli.create_runner(&cli.run)?.run_node_until_exit(|config| async {
      service::new_full(config).map_err(sc_cli::Error::Service)
    }),
  }
}
