#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![allow(clippy::std_instead_of_alloc, clippy::std_instead_of_core)]

use core::{
  pin::Pin,
  task::{Poll, Context},
  time::Duration,
};
extern crate alloc;
use alloc::sync::Arc;
use std::{
  sync::RwLock,
  collections::{HashSet, HashMap},
};

use rand_core::{RngCore as _, OsRng};

use zeroize::Zeroizing;
use schnorrkel::Keypair;

use serai_client_serai::{
  abi::primitives::{
    crypto::{Public, key_types, subkey},
    network_id::ExternalNetworkId,
  },
  Serai,
};

use tokio::sync::oneshot;

use serai_task::{Task, ContinuallyRan as _};

use serai_cosign::SignedCosign;

use tributary_framework::{ReadWriteAsBorsh, Transaction, Block};

use libp2p::{
  multihash::Multihash,
  identity::{self, PeerId},
  tcp::Config as TcpConfig,
  yamux, allow_block_list,
  connection_limits::{self, ConnectionLimits},
  swarm::NetworkBehaviour,
  SwarmBuilder,
};

use serai_coordinator_p2p::{SyncRequest, CommittedTributaryBlock, P2pSend, P2pRecv};

/// A struct to sync the validators from the Serai node in order to keep track of them.
mod validators;
use validators::UpdateValidatorsTask;

/// The authentication protocol upgrade to limit the P2P network to active validators.
mod authenticate;
use authenticate::OnlyValidators;

/// The ping behavior, used to ensure connection latency is below the limit
mod ping;

/// The request-response messages and behavior
mod reqres;
use reqres::{Request, Response};

/// The gossip messages and behavior
mod gossip;
use gossip::Message;

/// The swarm task, running it and dispatching to/from it
mod swarm;
use swarm::{MAX_OUTBOUND_REQUESTS, OutboundRequest, SwarmTask};

/// The dial task, to find new peers to connect to
mod dial;
use dial::DialTask;

const PORT: u16 = 30563; // 5132 ^ (('c' << 8) | 'o')

fn peer_id_from_public(public: Public) -> PeerId {
  // 0 represents the identity Multihash, that no hash was performed
  // It's an internal constant so we can't refer to the constant inside libp2p
  PeerId::from_multihash(Multihash::wrap(0, &public.0).unwrap()).unwrap()
}

// TODO: Use our own Libp2p identity?
fn identity_keypair(serai_key: &Keypair) -> Zeroizing<Keypair> {
  Zeroizing::new(
    subkey::<sp_core::sr25519::Pair>(&serai_key.clone().into(), key_types::AUTHORITY_DISCOVERY)
      .into(),
  )
}

/// The representation of a peer.
pub struct Peer<'p2p, Tx: 'static + Send + Transaction> {
  outbound_requests: &'p2p async_channel::Sender<OutboundRequest<Tx>>,
  id: PeerId,
}
impl<Tx: 'static + Send + Transaction> serai_coordinator_p2p::Peer<'_, Tx> for Peer<'_, Tx> {
  fn send_sync_request(
    &self,
    sync_request: SyncRequest,
  ) -> impl Send + Future<Output = Option<Vec<CommittedTributaryBlock<Tx>>>> {
    async move {
      const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(5);

      let request = Request::SyncRequest(sync_request);
      let (sender, receiver) = oneshot::channel();
      let _ = self.outbound_requests.send((self.id, request, Some(sender))).await;
      if let Ok(Ok(Response::Blocks(blocks))) =
        tokio::time::timeout(HEARTBEAT_TIMEOUT, receiver).await
      {
        Some(blocks)
      } else {
        None
      }
    }
  }
}

#[derive(Clone)]
struct Peers {
  peers: Arc<RwLock<HashMap<ExternalNetworkId, HashSet<PeerId>>>>,
}

// Consider adding identify/kad/autonat/rendevous/(relay + dcutr). While we currently use the Serai
// network for peers, we could use it solely for bootstrapping/as a fallback.
#[allow(unreachable_code)] // TODO: This only fires on nightly
mod behavior {
  use super::*;

  #[derive(NetworkBehaviour)]
  pub(super) struct Behavior<Tx: 'static + Send + Transaction> {
    // Used to only allow Serai validators as peers
    pub(super) allow_list: allow_block_list::Behaviour<allow_block_list::AllowedPeers>,
    // Used to limit each peer to a single connection
    pub(super) connection_limits: connection_limits::Behaviour,
    // Used to ensure connection latency is within tolerances
    pub(super) ping: ping::Behavior,
    // Used to request data from specific peers
    pub(super) reqres: reqres::Behavior<Tx>,
    // Used to broadcast messages to all other peers subscribed to a topic
    pub(super) gossip: gossip::Behavior,
  }
}
use behavior::*;

struct Libp2pSendInner<Tx: Transaction> {
  peers: Peers,

  gossip: async_channel::Sender<Message<Tx>>,
  outbound_requests: async_channel::Sender<OutboundRequest<Tx>>,
}

/// The send half of the [`libp2p`]-backed P2P implementation.
#[derive(Clone)]
pub struct Libp2pSend<Tx: Transaction>(Arc<Libp2pSendInner<Tx>>);

trait StaticSendTransaction: 'static + Send + Transaction {}
impl<T: 'static + Send + Transaction> StaticSendTransaction for T {}

pin_project_lite::pin_project! {
  /// The receive half of the [`libp2p`]-backed P2P implementation.
  pub struct Libp2pRecv<Tx: StaticSendTransaction> {
    #[pin]
    task: SwarmTask<Tx>
  }
}

impl<Tx: 'static + Send + Transaction> P2pRecv<Tx> for Libp2pRecv<Tx> {
  type Response = libp2p::request_response::ResponseChannel<Response<Tx>>;

  fn poll(
    self: Pin<&mut Self>,
    cx: &mut Context<'_>,
  ) -> Poll<serai_coordinator_p2p::Recv<Tx, Self::Response>> {
    self.project().task.poll(cx)
  }

  fn notable_cosigns(
    self: Pin<&mut Self>,
    response: Self::Response,
    notable_cosigns: Vec<SignedCosign>,
  ) {
    self.project().task.notable_cosigns(response, notable_cosigns);
  }

  fn sync(
    self: Pin<&mut Self>,
    response: Self::Response,
    blocks: Vec<CommittedTributaryBlock<Tx>>,
  ) {
    self.project().task.sync(response, blocks);
  }
}

impl<Tx: 'static + Send + Transaction> Libp2pSend<Tx> {
  /// Create a new libp2p-backed P2P instance.
  ///
  /// This will spawn all of the internal tasks necessary for functioning.
  pub fn new(serai_key: &Zeroizing<Keypair>, serai: Arc<Serai>) -> (Self, Libp2pRecv<Tx>) {
    // Define the object we track peers with
    let peers = Peers { peers: Arc::new(RwLock::new(HashMap::new())) };

    // Define the dial task
    let (dial_task_def, dial_task) = Task::new();
    let (to_dial_send, to_dial_recv) = async_channel::bounded(32);
    tokio::spawn(
      DialTask::new(serai.clone(), peers.clone(), to_dial_send)
        .continually_run(dial_task_def, vec![]),
    );

    let swarm = {
      let serai_key = identity_keypair(serai_key);
      let new_only_validators = |noise_keypair: &identity::Keypair| -> Result<_, ()> {
        Ok(OnlyValidators { serai_key: serai_key.clone(), noise_keypair: noise_keypair.clone() })
      };

      let mut swarm = SwarmBuilder::with_existing_identity(identity::Keypair::generate_ed25519())
        .with_tokio()
        .with_tcp(TcpConfig::default().nodelay(true), new_only_validators, yamux::Config::default)
        .unwrap()
        .with_behaviour(|_| Behavior {
          allow_list: allow_block_list::Behaviour::default(),
          // Limit each per to a single connection
          connection_limits: connection_limits::Behaviour::new(
            ConnectionLimits::default().with_max_established_per_peer(Some(1)),
          ),
          ping: ping::new_behavior(),
          reqres: reqres::new_behavior::<Tx>(),
          gossip: gossip::new_behavior::<Tx>(),
        })
        .unwrap()
        .with_swarm_config(|config| {
          config
            .with_idle_connection_timeout(ping::INTERVAL + ping::TIMEOUT + Duration::from_secs(5))
        })
        .build();
      swarm.listen_on(format!("/ip4/0.0.0.0/tcp/{PORT}").parse().unwrap()).unwrap();
      swarm.listen_on(format!("/ip6/::/tcp/{PORT}").parse().unwrap()).unwrap();
      swarm
    };

    let (swarm_validators, validator_changes) = UpdateValidatorsTask::spawn(serai);
    let (gossip_send, gossip_recv) = async_channel::bounded(512);
    let (outbound_requests_send, outbound_requests_recv) =
      async_channel::bounded(MAX_OUTBOUND_REQUESTS);

    // Create the swarm task
    let task = SwarmTask::<Tx>::new(
      dial_task,
      to_dial_recv,
      swarm_validators,
      validator_changes,
      peers.clone(),
      swarm,
      gossip_recv,
      outbound_requests_recv,
    );

    (
      Libp2pSend(Arc::new(Libp2pSendInner {
        peers,

        gossip: gossip_send,
        outbound_requests: outbound_requests_send,
      })),
      Libp2pRecv { task },
    )
  }
}

const LATENCY_TIME: Duration = Duration::from_millis(1_500);
const BLOCK_DOWNLOADING_TIME: Duration = Duration::from_millis(2_000);
const BLOCK_PROCESSING_TIME: Duration = Duration::from_millis(500);

impl<Tx: Send + Transaction>
  tendermint::Network<
    [u8; 32],
    [u8; 64],
    tributary_framework::AggregateSignature,
    ReadWriteAsBorsh<Block<Tx>>,
  > for Libp2pSend<Tx>
{
  const LATENCY_TIME: Duration = LATENCY_TIME;
  const BLOCK_DOWNLOADING_TIME: Duration = BLOCK_DOWNLOADING_TIME;
  const BLOCK_PROCESSING_TIME: Duration = BLOCK_PROCESSING_TIME;

  type Sleep = tokio::time::Sleep;
  fn sleep(duration: Duration) -> tokio::time::Sleep {
    tokio::time::sleep(duration)
  }

  fn broadcast(
    &mut self,
    genesis: impl AsRef<[u8]>,
    message: tributary_framework::Message<Tx>,
  ) -> impl Send + Future<Output = ()> {
    let tributary = genesis.as_ref().try_into().unwrap();
    async move {
      let _ = self.0.gossip.send(Message::TributaryMessage { tributary, message }).await;
    }
  }
}

impl<Tx: Transaction> tributary_framework::mempool::MempoolNetwork<Tx> for Libp2pSend<Tx> {
  fn gossip(&mut self, genesis: [u8; 32], transaction: Tx) {
    let _ = self.0.gossip.try_send(Message::TributaryTransaction {
      tributary: genesis,
      transaction: ReadWriteAsBorsh(transaction),
    });
  }
}

impl<Tx: 'static + Send + Transaction> serai_cosign::RequestNotableCosigns for Libp2pSend<Tx> {
  type Error = ();

  fn request_notable_cosigns(
    &self,
    global_session: [u8; 32],
  ) -> impl Send + Future<Output = Result<(), Self::Error>> {
    async move {
      const MINIMUM_AMOUNT_OF_PEERS_TO_REQUEST_FROM: usize = 3;

      let request = Request::NotableCosigns { global_session };

      let peers = self.0.peers.peers.read().unwrap().clone();
      // HashSet of all peers
      let peers = peers.into_values().flat_map(<_>::into_iter).collect::<HashSet<_>>();
      // Vec of all peers
      let mut peers = peers.into_iter().collect::<Vec<_>>();
      let request_from = peers.len().isqrt().isqrt().max(MINIMUM_AMOUNT_OF_PEERS_TO_REQUEST_FROM);

      for _ in 0 .. request_from {
        #[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
        let i = OsRng.next_u64() as usize;
        let Some(i) = i.checked_rem(peers.len()) else { break };
        let peer = peers.swap_remove(i);

        let _ = self.0.outbound_requests.send((peer, request, None)).await;
      }

      Ok(())
    }
  }
}

impl<Tx: 'static + Send + Transaction> P2pSend<Tx> for Libp2pSend<Tx> {
  type Peer<'p2p> = Peer<'p2p, Tx>;

  fn peers(&self, network: ExternalNetworkId) -> impl Send + Future<Output = Vec<Self::Peer<'_>>> {
    async move {
      let Some(peer_ids) = self.0.peers.peers.read().unwrap().get(&network).cloned() else {
        return vec![];
      };
      let mut res = vec![];
      for id in peer_ids {
        res.push(Peer { outbound_requests: &self.0.outbound_requests, id });
      }
      res
    }
  }

  async fn publish_cosign(&self, cosign: SignedCosign) {
    let _ = self.0.gossip.send(Message::Cosign(cosign)).await;
  }
}
