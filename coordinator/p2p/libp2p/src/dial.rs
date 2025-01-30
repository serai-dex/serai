use core::future::Future;
use std::{sync::Arc, collections::HashSet};

use rand_core::{RngCore, OsRng};

use tokio::sync::mpsc;

use serai_client::{SeraiError, Serai};

use libp2p::{
  core::multiaddr::{Protocol, Multiaddr},
  swarm::dial_opts::DialOpts,
};

use serai_task::ContinuallyRan;

use crate::{PORT, Peers, validators::Validators};

const TARGET_PEERS_PER_NETWORK: usize = 5;
/*
  If we only tracked the target amount of peers per network, we'd risk being eclipsed by an
  adversary who immediately connects to us with their array of validators upon our boot. Their
  array would satisfy our target amount of peers, so we'd never seek more, enabling the adversary
  to be the only entity we peered with.

  We solve this by additionally requiring an explicit amount of peers we dialed. That means we
  randomly chose to connect to these peers.
*/
// TODO const TARGET_DIALED_PEERS_PER_NETWORK: usize = 3;

pub(crate) struct DialTask {
  serai: Arc<Serai>,
  validators: Validators,
  peers: Peers,
  to_dial: mpsc::UnboundedSender<DialOpts>,
}

impl DialTask {
  pub(crate) fn new(
    serai: Arc<Serai>,
    peers: Peers,
    to_dial: mpsc::UnboundedSender<DialOpts>,
  ) -> Self {
    DialTask { serai: serai.clone(), validators: Validators::new(serai).0, peers, to_dial }
  }
}

impl ContinuallyRan for DialTask {
  // Only run every five minutes, not the default of every five seconds
  const DELAY_BETWEEN_ITERATIONS: u64 = 5 * 60;
  const MAX_DELAY_BETWEEN_ITERATIONS: u64 = 10 * 60;

  type Error = SeraiError;

  fn run_iteration(&mut self) -> impl Send + Future<Output = Result<bool, Self::Error>> {
    async move {
      self.validators.update().await?;

      // If any of our peers is lacking, try to connect to more
      let mut dialed = false;
      let peer_counts = self
        .peers
        .peers
        .read()
        .await
        .iter()
        .map(|(network, peers)| (*network, peers.len()))
        .collect::<Vec<_>>();
      for (network, peer_count) in peer_counts {
        /*
          If we don't have the target amount of peers, and we don't have all the validators in the
          set but one, attempt to connect to more validators within this set.

          The latter clause is so if there's a set with only 3 validators, we don't infinitely try
          to connect to the target amount of peers for this network as we never will. Instead, we
          only try to connect to most of the validators actually present.
        */
        if (peer_count < TARGET_PEERS_PER_NETWORK) &&
          (peer_count <
            self
              .validators
              .by_network()
              .get(&network)
              .map(HashSet::len)
              .unwrap_or(0)
              .saturating_sub(1))
        {
          let mut potential_peers = self.serai.p2p_validators(network).await?;
          for _ in 0 .. (TARGET_PEERS_PER_NETWORK - peer_count) {
            if potential_peers.is_empty() {
              break;
            }
            let index_to_dial =
              usize::try_from(OsRng.next_u64() % u64::try_from(potential_peers.len()).unwrap())
                .unwrap();
            let randomly_selected_peer = potential_peers.swap_remove(index_to_dial);

            log::info!("found peer from substrate: {randomly_selected_peer}");

            // Map the peer from a Substrate P2P network peer to a Coordinator P2P network peer
            let mapped_peer = randomly_selected_peer
              .into_iter()
              .filter_map(|protocol| match protocol {
                // Drop PeerIds from the Substrate P2p network
                Protocol::P2p(_) => None,
                // Use our own TCP port
                Protocol::Tcp(_) => Some(Protocol::Tcp(PORT)),
                // Pass-through any other specifications (IPv4, IPv6, etc)
                other => Some(other),
              })
              .collect::<Multiaddr>();

            log::debug!("mapped found peer: {mapped_peer}");

            self
              .to_dial
              .send(DialOpts::unknown_peer_id().address(mapped_peer).build())
              .expect("dial receiver closed?");
            dialed = true;
          }
        }
      }

      Ok(dialed)
    }
  }
}
