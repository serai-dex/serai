use std::sync::Arc;

use serai_runtime::Block;

use sc_service::{PruningMode, PartialComponents};

use sc_cli::SubstrateCli;
use frame_benchmarking_cli::{ExtrinsicFactory, BenchmarkCmd, SUBSTRATE_REFERENCE_HARDWARE};

use crate::{
  chain_spec,
  cli::{Cli, Subcommand},
  command_helper::{RemarkBuilder, inherent_benchmark_data},
  service::{self, FullClient},
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
    "https://github.com/serai-dex/serai/issues/new".to_string()
  }

  fn copyright_start_year() -> i32 {
    2022
  }

  fn load_spec(&self, id: &str) -> Result<Box<dyn sc_service::ChainSpec>, String> {
    match id {
<<<<<<< HEAD
      "dev" | "devnet" => Ok(Box::new(chain_spec::development_config()?)),
=======
      "dev" => Ok(Box::new(chain_spec::development_config()?)),
>>>>>>> 083198ec (Make the dev profile a local testnet profile)
      "local" => Ok(Box::new(chain_spec::testnet_config()?)),
      _ => panic!("Unknown network ID"),
    }
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
        service::new_partial(&config)?.1;
      Ok((cmd.run(client, import_queue), task_manager))
    }),

    Some(Subcommand::ExportBlocks(cmd)) => cli.create_runner(cmd)?.async_run(|config| {
      let PartialComponents { client, task_manager, .. } = service::new_partial(&config)?.1;
      Ok((cmd.run(client, config.database), task_manager))
    }),

    Some(Subcommand::ExportState(cmd)) => cli.create_runner(cmd)?.async_run(|config| {
      let PartialComponents { client, task_manager, .. } = service::new_partial(&config)?.1;
      Ok((cmd.run(client, config.chain_spec), task_manager))
    }),

    Some(Subcommand::ImportBlocks(cmd)) => cli.create_runner(cmd)?.async_run(|config| {
      let PartialComponents { client, task_manager, import_queue, .. } =
        service::new_partial(&config)?.1;
      Ok((cmd.run(client, import_queue), task_manager))
    }),

    Some(Subcommand::PurgeChain(cmd)) => {
      cli.create_runner(cmd)?.sync_run(|config| cmd.run(config.database))
    }

    Some(Subcommand::Revert(cmd)) => cli.create_runner(cmd)?.async_run(|config| {
<<<<<<< HEAD
      let PartialComponents { client, task_manager, backend, .. } = service::new_partial(&config)?;
      let aux_revert = Box::new(|client: Arc<FullClient>, backend, blocks| {
        sc_consensus_babe::revert(client.clone(), backend, blocks)?;
        sc_consensus_grandpa::revert(client, blocks)?;
        Ok(())
      });
      Ok((cmd.run(client, backend, Some(aux_revert)), task_manager))
=======
      let PartialComponents { client, task_manager, backend, .. } =
        service::new_partial(&config)?.1;
      Ok((cmd.run(client, backend, None), task_manager))
>>>>>>> 9b0dca06 (Provide a way to create the machine)
    }),

    Some(Subcommand::Benchmark(cmd)) => cli.create_runner(cmd)?.sync_run(|config| match cmd {
      BenchmarkCmd::Pallet(cmd) => cmd.run::<Block, ()>(config),

      BenchmarkCmd::Block(cmd) => cmd.run(service::new_partial(&config)?.1.client),

      #[cfg(not(feature = "runtime-benchmarks"))]
      BenchmarkCmd::Storage(_) => {
        Err("Storage benchmarking can be enabled with `--features runtime-benchmarks`.".into())
      }

      #[cfg(feature = "runtime-benchmarks")]
      BenchmarkCmd::Storage(cmd) => {
        let PartialComponents { client, backend, .. } = service::new_partial(&config)?.1;
        cmd.run(config, client, backend.expose_db(), backend.expose_storage())
      }

      BenchmarkCmd::Overhead(cmd) => {
        let client = service::new_partial(&config)?.1.client;
        cmd.run(
          config,
          client.clone(),
          inherent_benchmark_data()?,
          vec![],
          &RemarkBuilder::new(client),
        )
      }

      BenchmarkCmd::Extrinsic(cmd) => {
        let client = service::new_partial(&config)?.1.client;
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

<<<<<<< HEAD
    None => cli.create_runner(&cli.run)?.run_node_until_exit(|mut config| async {
      if config.role.is_authority() {
        config.state_pruning = Some(PruningMode::ArchiveAll);
      }
=======
    None => cli.create_runner(&cli.run)?.run_node_until_exit(|config| async {
>>>>>>> 9b0dca06 (Provide a way to create the machine)
      service::new_full(config).await.map_err(sc_cli::Error::Service)
    }),
  }
}
