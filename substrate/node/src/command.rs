use std::sync::Arc;

use serai_abi::SubstrateBlock as Block;

use sc_service::{PruningMode, PartialComponents};

use sc_cli::SubstrateCli;

use crate::{
  chain_spec,
  cli::{Cli, Subcommand},
  service::{self, FullClient},
};

impl SubstrateCli for Cli {
  fn impl_name() -> String {
    "Serai Node".into()
  }

  fn impl_version() -> String {
    String::new()
  }

  fn description() -> String {
    String::new()
  }

  fn author() -> String {
    String::new()
  }

  fn support_url() -> String {
    "https://github.com/serai-dex/serai/issues/new".to_string()
  }

  fn copyright_start_year() -> i32 {
    2022
  }

  fn load_spec(&self, id: &str) -> Result<Box<dyn sc_service::ChainSpec>, String> {
    match id {
      "dev" | "devnet" => Ok(Box::new(chain_spec::development_config())),
      "local" => Ok(Box::new(chain_spec::local_config())),
      "testnet" => Ok(Box::new(chain_spec::testnet_config())),
      _ => panic!("Unknown network ID"),
    }
  }
}

pub fn run() -> sc_cli::Result<()> {
  let mut cli = Cli::from_args();

  match &cli.subcommand {
    Some(Subcommand::Key(cmd)) => cmd.run(&cli),

    Some(Subcommand::BuildSpec(cmd)) => {
      cli.create_runner(cmd)?.sync_run(|config| cmd.run(config.chain_spec, config.network))
    }

    Some(Subcommand::CheckBlock(cmd)) => cli.create_runner(cmd)?.async_run(|mut config| {
      let PartialComponents { client, task_manager, import_queue, .. } =
        service::new_partial(&mut config)?.0;
      Ok((cmd.run(client, import_queue), task_manager))
    }),

    Some(Subcommand::ExportBlocks(cmd)) => cli.create_runner(cmd)?.async_run(|mut config| {
      let PartialComponents { client, task_manager, .. } = service::new_partial(&mut config)?.0;
      Ok((cmd.run(client, config.database), task_manager))
    }),

    Some(Subcommand::ExportState(cmd)) => cli.create_runner(cmd)?.async_run(|mut config| {
      let PartialComponents { client, task_manager, .. } = service::new_partial(&mut config)?.0;
      Ok((cmd.run(client, config.chain_spec), task_manager))
    }),

    Some(Subcommand::ImportBlocks(cmd)) => cli.create_runner(cmd)?.async_run(|mut config| {
      let PartialComponents { client, task_manager, import_queue, .. } =
        service::new_partial(&mut config)?.0;
      Ok((cmd.run(client, import_queue), task_manager))
    }),

    Some(Subcommand::PurgeChain(cmd)) => {
      cli.create_runner(cmd)?.sync_run(|config| cmd.run(config.database))
    }

    Some(Subcommand::Revert(cmd)) => cli.create_runner(cmd)?.async_run(|mut config| {
      let PartialComponents { client, task_manager, backend, .. } =
        service::new_partial(&mut config)?.0;
      let aux_revert = Box::new(|client: Arc<FullClient>, backend, blocks| {
        sc_consensus_babe::revert(client.clone(), backend, blocks)?;
        sc_consensus_grandpa::revert(client, blocks)?;
        Ok(())
      });
      Ok((cmd.run(client, backend, Some(aux_revert)), task_manager))
    }),

    Some(Subcommand::ChainInfo(cmd)) => {
      cli.create_runner(cmd)?.sync_run(|config| cmd.run::<Block>(&config))
    }

    None => {
      cli.run.network_params.node_key_params = sc_cli::NodeKeyParams {
        node_key: None,
        node_key_file: None,
        node_key_type: sc_cli::arg_enums::NodeKeyType::Ed25519,
        unsafe_force_node_key_generation: true,
      };

      cli.create_runner(&cli.run)?.run_node_until_exit(|mut config| async {
        if config.role.is_authority() {
          config.state_pruning = Some(PruningMode::ArchiveAll);
        }
        service::new_full(config).map_err(sc_cli::Error::Service)
      })
    }
  }
}
