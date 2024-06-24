use ciphersuite::{Ciphersuite, Ristretto};

use serai_client::primitives::NetworkId;

use dockertest::DockerTest;

use crate::*;

mod key_gen;
pub(crate) use key_gen::key_gen;

mod batch;
pub(crate) use batch::{recv_batch_preprocesses, sign_batch, substrate_block};

mod send;

pub(crate) const COORDINATORS: usize = 4;
pub(crate) const THRESHOLD: usize = ((COORDINATORS * 2) / 3) + 1;

fn new_test(network: NetworkId) -> (Vec<(Handles, <Ristretto as Ciphersuite>::F)>, DockerTest) {
  let mut coordinators = vec![];
  let mut test = DockerTest::new().with_network(dockertest::Network::Isolated);
  let mut eth_handle = None;
  for _ in 0 .. COORDINATORS {
    let (handles, coord_key, compositions) = processor_stack(network, eth_handle.clone());
    // TODO: Remove this once https://github.com/foundry-rs/foundry/issues/7955
    // This has all processors share an Ethereum node until we can sync controlled nodes
    if network == NetworkId::Ethereum {
      eth_handle = eth_handle.or_else(|| Some(handles.0.clone()));
    }
    coordinators.push((handles, coord_key));
    for composition in compositions {
      test.provide_container(composition);
    }
  }
  (coordinators, test)
}
