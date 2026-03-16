#![allow(clippy::std_instead_of_alloc, clippy::std_instead_of_core)]
#![expect(clippy::result_large_err)]

use std::sync::Arc;

use zeroize::Zeroizing;

use sp_core::{Pair as _, sr25519::Pair};

use serai_abi::{primitives::address::SeraiAddress, SubstrateBlock as Block};

use sc_service::{ChainSpec, BlocksPruning, PruningMode};
use sc_cli::{RunCmd, SubstrateCli};

mod keystore;

mod chain_spec;
mod service;
use service::{Partial, FullClient};

mod rpc;

/*
  The following propagates a subset of `sc-cli` into the Serai node's CLI. At this time, the Serai
  node does not plan to forever be premised on `sc-cli`, which has a non-trivial amount of
  dependencies and handles a decent amount of orchestration in an opaque fashion. This opacity
  makes it more to difficult to provide Serai's desired tooling regarding the keystore and
  development configurations. It is used for now however, but various methods may be stubbed due to
  simply not caring to fulfill the entire `sc-cli` API.
*/

#[derive(Debug, clap::Subcommand)]
enum Subcommand {
  PurgeChain(sc_cli::PurgeChainCmd),
  Revert(sc_cli::RevertCmd),
  ChainInfo(sc_cli::ChainInfoCmd),
}

#[derive(Debug, clap::Parser)]
struct Cli {
  #[clap(subcommand)]
  subcommand: Option<Subcommand>,

  #[clap(flatten)]
  run: RunCmd,
}

impl SubstrateCli for Cli {
  fn impl_name() -> String {
    "serai".to_owned()
  }

  fn impl_version() -> String {
    "0.1.0".to_owned()
  }

  fn description() -> String {
    String::new()
  }

  fn author() -> String {
    String::new()
  }

  fn support_url() -> String {
    "https://github.com/serai-dex/serai/issues/new".to_owned()
  }

  fn copyright_start_year() -> i32 {
    2022
  }

  fn load_spec(&self, id: &str) -> Result<Box<dyn ChainSpec>, String> {
    match id {
      "dev" | "devnet" => Ok(Box::new(chain_spec::development_config())),
      "local" => Ok(Box::new(chain_spec::local_config())),
      _ => panic!("Unknown network ID"),
    }
  }
}

fn main() -> sc_cli::Result<()> {
  let cli = Cli::from_args();

  match &cli.subcommand {
    Some(Subcommand::PurgeChain(cmd)) => {
      cli.create_runner(cmd)?.sync_run(|config| cmd.run(config.database))
    }

    Some(Subcommand::Revert(cmd)) => cli.create_runner(cmd)?.async_run(|mut config| {
      let Partial { backend, client, task_manager, .. } = service::new_partial(None, &mut config)?;
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
      cli.create_runner(&cli.run)?.run_node_until_exit(async |mut config| {
        // Load our bespoke definition of a keystore
        let validator_identity_and_keystore: Option<(SeraiAddress, keystore::Keystore)> =
          if let Some((validator_identity, keystore)) = keystore::Keystore::from_env() {
            Some((validator_identity, keystore))
          } else if let Some(seed) = config.dev_key_seed.as_ref() {
            let pair = Pair::from_string(seed, None).expect("dev key had invalid seed");
            let validator_identity = chain_spec::validator_identity_for_dev_seed(seed);
            Some((validator_identity, keystore::Keystore::from(pair)))
          } else {
            None
          };
        assert_eq!(
          validator_identity_and_keystore.is_some(),
          config.role.is_authority(),
          "unrecognized keystore to operate a validator with"
        );

        /*
          If we are a validator, set our `node_key` to be deterministic to our auxiliary key. This
          avoids having to actively manage multiple key materials for the validator's operation.
          This also does silently override any explicitly specified node key configuration, yet we
          do not care to try and respect those.

          Because the auxiliary key is defined over Ristretto, yet the P2P network uses Ed25519, we
          are unable to use the existing derivation scheme (though one can technically define a
          mapping between the two groups). As we do not require _public_ derivation of node keys,
          though that is a requirement for subkeys, we simply use a domain-separated hash of a
          derived private key to generate the necessary key material.
        */
        if let Some((_validator_identity, keystore)) = &validator_identity_and_keystore {
          let node_key_entropy = keystore.pair(sp_core::crypto::KeyTypeId(*b"p2ed"));
          let node_key_entropy = Zeroizing::new(node_key_entropy.to_raw_vec());
          /*
            This effects a hardened derivation, which may or may not be necessary. Specifically,
            the sr25519 VRF is premised on the computation of Diffie-Hellmans, and transports
            frequently derive a symmetric encryption key from a Diffie-Hellman. If the P2P protocol
            grants the adversary a DH oracle (they can provide an arbitrary point and receive the
            DH for a validator's key and that point, such as if they open a transport, claim an
            arbitrary point is in fact their own key (causing the validator to perform the DH), and
            then somehow learn the symmetric key from there), then usage of a P2P key with a known
            relation to the key used with BABE may break the security of BABE (due to granting the
            adversary the ability to learn random numbers before everyone else).

            Similar concerns exist any time we wish to provide keys of known relation for usage in
            arbitrary protocols. The usage within the runtime itself is only safe as all the keys
            are solely used for signing (as fine to compose) except for the singular usage for the
            BABE VRF (which is fine to compose with signing). This has to be kept in mind when we
            now start using keys, derived in any manner, with other protocols such as the P2P layer
            however.
          */
          let mut node_key = Zeroizing::new(sp_core::blake2_256(&node_key_entropy));
          // Perform a rejection sample such that this will keep sampling keys until it finds one
          loop {
            use sc_network::config::{Secret, ed25519::SecretKey};
            let Ok(node_key) = SecretKey::try_from_bytes(node_key.clone()) else {
              *node_key = sp_core::blake2_256(node_key.as_slice());
              continue;
            };
            config.network.node_key =
              sc_service::config::NodeKeyConfig::Ed25519(Secret::Input(node_key));
            break;
          }
        }

        if config.role.is_authority() {
          // TODO: https://github.com/serai-dex/serai/issues/696
          config.state_pruning = Some(PruningMode::ArchiveCanonical);
          config.blocks_pruning = BlocksPruning::KeepFinalized;
        }

        // TODO: Decide, and define a constant for, our port number
        config.network.listen_addresses =
          vec!["/ip4/0.0.0.0/tcp/30333".parse().unwrap(), "/ip6/::/tcp/30333".parse().unwrap()];

        service::new_full(validator_identity_and_keystore, config).map_err(sc_cli::Error::Service)
      })
    }
  }
}
