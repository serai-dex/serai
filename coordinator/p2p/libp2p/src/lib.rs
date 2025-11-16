#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use core::{future::Future, time::Duration};
use std::{
  sync::Arc,
  collections::{HashSet, HashMap},
};

use rand_core::{RngCore, OsRng};

use zeroize::Zeroizing;
use schnorrkel::Keypair;

use serai_client_serai::{
  abi::primitives::{
    crypto::Public, network_id::ExternalNetworkId, validator_sets::ExternalValidatorSet,
  },
  Serai,
};

use tokio::sync::{mpsc, oneshot, Mutex, RwLock};

use serai_task::{Task, ContinuallyRan};

use serai_cosign::SignedCosign;

use libp2p::{
  multihash::Multihash,
  identity::{self, PeerId},
  tcp::Config as TcpConfig,
  yamux, allow_block_list,
  connection_limits::{self, ConnectionLimits},
  swarm::NetworkBehaviour,
  SwarmBuilder,
};

use serai_coordinator_p2p::{Heartbeat, TributaryBlockWithCommit};

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
use reqres::{InboundRequestId, Request, Response};

/// The gossip messages and behavior
mod gossip;
use gossip::Message;

/// The swarm task, running it and dispatching to/from it
mod swarm;
use swarm::SwarmTask;

/// The dial task, to find new peers to connect to
mod dial;
use dial::DialTask;

const PORT: u16 = 30563; // 5132 ^ (('c' << 8) | 'o')

fn peer_id_from_public(public: Public) -> PeerId {
  // 0 represents the identity Multihash, that no hash was performed
  // It's an internal constant so we can't refer to the constant inside libp2p
  PeerId::from_multihash(Multihash::wrap(0, &public.0).unwrap()).unwrap()
}

/// The representation of a peer.
pub struct Peer<'a> {
  outbound_requests: &'a mpsc::UnboundedSender<(PeerId, Request, oneshot::Sender<Response>)>,
  id: PeerId,
}
impl serai_coordinator_p2p::Peer<'_> for Peer<'_> {
  fn send_heartbeat(
    &self,
    heartbeat: Heartbeat,
  ) -> impl Send + Future<Output = Option<Vec<TributaryBlockWithCommit>>> {
    async move {
      const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(5);

      let request = Request::Heartbeat(heartbeat);
      let (sender, receiver) = oneshot::channel();
      self
        .outbound_requests
        .send((self.id, request, sender))
        .expect("outbound requests recv channel was dropped?");
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
#[derive(NetworkBehaviour)]
struct Behavior {
  // Used to only allow Serai validators as peers
  allow_list: allow_block_list::Behaviour<allow_block_list::AllowedPeers>,
  // Used to limit each peer to a single connection
  connection_limits: connection_limits::Behaviour,
  // Used to ensure connection latency is within tolerances
  ping: ping::Behavior,
  // Used to request data from specific peers
  reqres: reqres::Behavior,
  // Used to broadcast messages to all other peers subscribed to a topic
  gossip: gossip::Behavior,
}

#[allow(clippy::type_complexity)]
struct Libp2pInner {
  peers: Peers,

  gossip: mpsc::UnboundedSender<Message>,
  outbound_requests: mpsc::UnboundedSender<(PeerId, Request, oneshot::Sender<Response>)>,

  tributary_gossip: Mutex<mpsc::UnboundedReceiver<([u8; 32], Vec<u8>)>>,

  signed_cosigns: Mutex<mpsc::UnboundedReceiver<SignedCosign>>,
  signed_cosigns_send: mpsc::UnboundedSender<SignedCosign>,

  heartbeat_requests:
    Mutex<mpsc::UnboundedReceiver<(InboundRequestId, ExternalValidatorSet, [u8; 32])>>,
  notable_cosign_requests: Mutex<mpsc::UnboundedReceiver<(InboundRequestId, [u8; 32])>>,
  inbound_request_responses: mpsc::UnboundedSender<(InboundRequestId, Response)>,
}

/// The libp2p-backed P2P implementation.
///
/// The P2p trait implementation does not support backpressure and is expected to be fully
/// utilized. Failure to poll the entire API will cause unbounded memory growth.
#[derive(Clone)]
pub struct Libp2p(Arc<Libp2pInner>);

impl Libp2p {
  /// Create a new libp2p-backed P2P instance.
  ///
  /// This will spawn all of the internal tasks necessary for functioning.
  pub fn new(serai_key: &Zeroizing<Keypair>, serai: Arc<Serai>) -> Libp2p {
    // Define the object we track peers with
    let peers = Peers { peers: Arc::new(RwLock::new(HashMap::new())) };

    // Define the dial task
    let (dial_task_def, dial_task) = Task::new();
    let (to_dial_send, to_dial_recv) = mpsc::unbounded_channel();
    tokio::spawn(
      DialTask::new(serai.clone(), peers.clone(), to_dial_send)
        .continually_run(dial_task_def, vec![]),
    );

    let swarm = {
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
          reqres: reqres::new_behavior(),
          gossip: gossip::new_behavior(),
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

    let (gossip_send, gossip_recv) = mpsc::unbounded_channel();
    let (signed_cosigns_send, signed_cosigns_recv) = mpsc::unbounded_channel();
    let (tributary_gossip_send, tributary_gossip_recv) = mpsc::unbounded_channel();

    let (outbound_requests_send, outbound_requests_recv) = mpsc::unbounded_channel();

    let (heartbeat_requests_send, heartbeat_requests_recv) = mpsc::unbounded_channel();
    let (notable_cosign_requests_send, notable_cosign_requests_recv) = mpsc::unbounded_channel();
    let (inbound_request_responses_send, inbound_request_responses_recv) =
      mpsc::unbounded_channel();

    // Create the swarm task
    SwarmTask::spawn(
      dial_task,
      to_dial_recv,
      swarm_validators,
      validator_changes,
      peers.clone(),
      swarm,
      gossip_recv,
      signed_cosigns_send.clone(),
      tributary_gossip_send,
      outbound_requests_recv,
      heartbeat_requests_send,
      notable_cosign_requests_send,
      inbound_request_responses_recv,
    );

    Libp2p(Arc::new(Libp2pInner {
      peers,

      gossip: gossip_send,
      outbound_requests: outbound_requests_send,

      tributary_gossip: Mutex::new(tributary_gossip_recv),

      signed_cosigns: Mutex::new(signed_cosigns_recv),
      signed_cosigns_send,

      heartbeat_requests: Mutex::new(heartbeat_requests_recv),
      notable_cosign_requests: Mutex::new(notable_cosign_requests_recv),
      inbound_request_responses: inbound_request_responses_send,
    }))
  }
}

impl tributary_sdk::P2p for Libp2p {
  fn broadcast(&self, tributary: [u8; 32], message: Vec<u8>) -> impl Send + Future<Output = ()> {
    async move {
      self
        .0
        .gossip
        .send(Message::Tributary { tributary, message })
        .expect("gossip recv channel was dropped?");
    }
  }
}

impl serai_cosign::RequestNotableCosigns for Libp2p {
  type Error = ();

  fn request_notable_cosigns(
    &self,
    global_session: [u8; 32],
  ) -> impl Send + Future<Output = Result<(), Self::Error>> {
    async move {
      const AMOUNT_OF_PEERS_TO_REQUEST_FROM: usize = 3;
      const NOTABLE_COSIGNS_TIMEOUT: Duration = Duration::from_secs(5);

      let request = Request::NotableCosigns { global_session };

      let peers = self.0.peers.peers.read().await.clone();
      // HashSet of all peers
      let peers = peers.into_values().flat_map(<_>::into_iter).collect::<HashSet<_>>();
      // Vec of all peers
      let mut peers = peers.into_iter().collect::<Vec<_>>();

      let mut channels = Vec::with_capacity(AMOUNT_OF_PEERS_TO_REQUEST_FROM);
      for _ in 0 .. AMOUNT_OF_PEERS_TO_REQUEST_FROM {
        if peers.is_empty() {
          break;
        }
        let i = usize::try_from(OsRng.next_u64() % u64::try_from(peers.len()).unwrap()).unwrap();
        let peer = peers.swap_remove(i);

        let (sender, receiver) = oneshot::channel();
        self
          .0
          .outbound_requests
          .send((peer, request, sender))
          .expect("outbound requests recv channel was dropped?");
        channels.push(receiver);
      }

      // We could reduce our latency by using FuturesUnordered here but the latency isn't a concern
      for channel in channels {
        if let Ok(Ok(Response::NotableCosigns(cosigns))) =
          tokio::time::timeout(NOTABLE_COSIGNS_TIMEOUT, channel).await
        {
          for cosign in cosigns {
            self
              .0
              .signed_cosigns_send
              .send(cosign)
              .expect("signed_cosigns recv in this object was dropped?");
          }
        }
      }

      Ok(())
    }
  }
}

impl serai_coordinator_p2p::P2p for Libp2p {
  type Peer<'a> = Peer<'a>;

  fn peers(&self, network: ExternalNetworkId) -> impl Send + Future<Output = Vec<Self::Peer<'_>>> {
    async move {
      let Some(peer_ids) = self.0.peers.peers.read().await.get(&network).cloned() else {
        return vec![];
      };
      let mut res = vec![];
      for id in peer_ids {
        res.push(Peer { outbound_requests: &self.0.outbound_requests, id });
      }
      res
    }
  }

  fn publish_cosign(&self, cosign: SignedCosign) -> impl Send + Future<Output = ()> {
    async move {
      self.0.gossip.send(Message::Cosign(cosign)).expect("gossip recv channel was dropped?");
    }
  }

  fn heartbeat(
    &self,
  ) -> impl Send + Future<Output = (Heartbeat, oneshot::Sender<Vec<TributaryBlockWithCommit>>)> {
    async move {
      let (request_id, set, latest_block_hash) = self
        .0
        .heartbeat_requests
        .lock()
        .await
        .recv()
        .await
        .expect("heartbeat_requests_send was dropped?");
      let (sender, receiver) = oneshot::channel();
      tokio::spawn({
        let respond = self.0.inbound_request_responses.clone();
        async move {
          // The swarm task expects us to respond to every request. If the caller drops this
          // channel, we'll receive `Err` and respond with `vec![]`, safely satisfying that bound
          // without requiring the caller send a value down this channel
          let response = if let Ok(blocks) = receiver.await {
            Response::Blocks(blocks)
          } else {
            Response::Blocks(vec![])
          };
          respond
            .send((request_id, response))
            .expect("inbound_request_responses_recv was dropped?");
        }
      });
      (Heartbeat { set, latest_block_hash }, sender)
    }
  }

  fn notable_cosigns_request(
    &self,
  ) -> impl Send + Future<Output = ([u8; 32], oneshot::Sender<Vec<SignedCosign>>)> {
    async move {
      let (request_id, global_session) = self
        .0
        .notable_cosign_requests
        .lock()
        .await
        .recv()
        .await
        .expect("notable_cosign_requests_send was dropped?");
      let (sender, receiver) = oneshot::channel();
      tokio::spawn({
        let respond = self.0.inbound_request_responses.clone();
        async move {
          let response = if let Ok(notable_cosigns) = receiver.await {
            Response::NotableCosigns(notable_cosigns)
          } else {
            Response::NotableCosigns(vec![])
          };
          respond
            .send((request_id, response))
            .expect("inbound_request_responses_recv was dropped?");
        }
      });
      (global_session, sender)
    }
  }

  fn tributary_message(&self) -> impl Send + Future<Output = ([u8; 32], Vec<u8>)> {
    async move {
      self.0.tributary_gossip.lock().await.recv().await.expect("tributary_gossip send was dropped?")
    }
  }

  fn cosign(&self) -> impl Send + Future<Output = SignedCosign> {
    async move {
      self
        .0
        .signed_cosigns
        .lock()
        .await
        .recv()
        .await
        .expect("signed_cosigns couldn't recv despite send in same object?")
    }
  }
}
