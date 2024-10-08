use core::{time::Duration, fmt};
use std::{
  sync::Arc,
  io::{self, Read},
  collections::{HashSet, HashMap},
  time::{SystemTime, Instant},
};

use async_trait::async_trait;
use rand_core::{RngCore, OsRng};

use scale::{Decode, Encode};
use borsh::{BorshSerialize, BorshDeserialize};
use serai_client::{
  primitives::ExternalNetworkId, validator_sets::primitives::ExternalValidatorSet, Serai,
};

use serai_db::Db;

use futures_util::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, StreamExt};
use tokio::{
  sync::{Mutex, RwLock, mpsc, broadcast},
  time::sleep,
};

use libp2p::{
  core::multiaddr::{Protocol, Multiaddr},
  identity::Keypair,
  PeerId,
  tcp::Config as TcpConfig,
  noise, yamux,
  request_response::{
    Codec as RrCodecTrait, Message as RrMessage, Event as RrEvent, Config as RrConfig,
    Behaviour as RrBehavior, ProtocolSupport,
  },
  gossipsub::{
    IdentTopic, FastMessageId, MessageId, MessageAuthenticity, ValidationMode, ConfigBuilder,
    IdentityTransform, AllowAllSubscriptionFilter, Event as GsEvent, PublishError,
    Behaviour as GsBehavior,
  },
  swarm::{NetworkBehaviour, SwarmEvent},
  SwarmBuilder,
};

pub(crate) use tributary::{ReadWrite, P2p as TributaryP2p};

use crate::{Transaction, Block, Tributary, ActiveTributary, TributaryEvent};

// Block size limit + 1 KB of space for signatures/metadata
const MAX_LIBP2P_GOSSIP_MESSAGE_SIZE: usize = tributary::BLOCK_SIZE_LIMIT + 1024;

const MAX_LIBP2P_REQRES_MESSAGE_SIZE: usize =
  (tributary::BLOCK_SIZE_LIMIT * BLOCKS_PER_BATCH) + 1024;

const MAX_LIBP2P_MESSAGE_SIZE: usize = {
  // Manual `max` since `max` isn't a const fn
  if MAX_LIBP2P_GOSSIP_MESSAGE_SIZE > MAX_LIBP2P_REQRES_MESSAGE_SIZE {
    MAX_LIBP2P_GOSSIP_MESSAGE_SIZE
  } else {
    MAX_LIBP2P_REQRES_MESSAGE_SIZE
  }
};

const LIBP2P_TOPIC: &str = "serai-coordinator";

// Amount of blocks in a minute
const BLOCKS_PER_MINUTE: usize = (60 / (tributary::tendermint::TARGET_BLOCK_TIME / 1000)) as usize;

// Maximum amount of blocks to send in a batch
const BLOCKS_PER_BATCH: usize = BLOCKS_PER_MINUTE + 1;

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, BorshSerialize, BorshDeserialize)]
pub struct CosignedBlock {
  pub network: ExternalNetworkId,
  pub block_number: u64,
  pub block: [u8; 32],
  pub signature: [u8; 64],
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum ReqResMessageKind {
  KeepAlive,
  Heartbeat([u8; 32]),
  Block([u8; 32]),
}

impl ReqResMessageKind {
  pub fn read<R: Read>(reader: &mut R) -> Option<ReqResMessageKind> {
    let mut kind = [0; 1];
    reader.read_exact(&mut kind).ok()?;
    match kind[0] {
      0 => Some(ReqResMessageKind::KeepAlive),
      1 => Some({
        let mut genesis = [0; 32];
        reader.read_exact(&mut genesis).ok()?;
        ReqResMessageKind::Heartbeat(genesis)
      }),
      2 => Some({
        let mut genesis = [0; 32];
        reader.read_exact(&mut genesis).ok()?;
        ReqResMessageKind::Block(genesis)
      }),
      _ => None,
    }
  }

  pub fn serialize(&self) -> Vec<u8> {
    match self {
      ReqResMessageKind::KeepAlive => vec![0],
      ReqResMessageKind::Heartbeat(genesis) => {
        let mut res = vec![1];
        res.extend(genesis);
        res
      }
      ReqResMessageKind::Block(genesis) => {
        let mut res = vec![2];
        res.extend(genesis);
        res
      }
    }
  }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum GossipMessageKind {
  Tributary([u8; 32]),
  CosignedBlock,
}

impl GossipMessageKind {
  pub fn read<R: Read>(reader: &mut R) -> Option<GossipMessageKind> {
    let mut kind = [0; 1];
    reader.read_exact(&mut kind).ok()?;
    match kind[0] {
      0 => Some({
        let mut genesis = [0; 32];
        reader.read_exact(&mut genesis).ok()?;
        GossipMessageKind::Tributary(genesis)
      }),
      1 => Some(GossipMessageKind::CosignedBlock),
      _ => None,
    }
  }

  pub fn serialize(&self) -> Vec<u8> {
    match self {
      GossipMessageKind::Tributary(genesis) => {
        let mut res = vec![0];
        res.extend(genesis);
        res
      }
      GossipMessageKind::CosignedBlock => {
        vec![1]
      }
    }
  }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum P2pMessageKind {
  ReqRes(ReqResMessageKind),
  Gossip(GossipMessageKind),
}

impl P2pMessageKind {
  fn genesis(&self) -> Option<[u8; 32]> {
    match self {
      P2pMessageKind::ReqRes(ReqResMessageKind::KeepAlive) |
      P2pMessageKind::Gossip(GossipMessageKind::CosignedBlock) => None,
      P2pMessageKind::ReqRes(
        ReqResMessageKind::Heartbeat(genesis) | ReqResMessageKind::Block(genesis),
      ) |
      P2pMessageKind::Gossip(GossipMessageKind::Tributary(genesis)) => Some(*genesis),
    }
  }
}

impl From<ReqResMessageKind> for P2pMessageKind {
  fn from(kind: ReqResMessageKind) -> P2pMessageKind {
    P2pMessageKind::ReqRes(kind)
  }
}

impl From<GossipMessageKind> for P2pMessageKind {
  fn from(kind: GossipMessageKind) -> P2pMessageKind {
    P2pMessageKind::Gossip(kind)
  }
}

#[derive(Clone, Debug)]
pub struct Message<P: P2p> {
  pub sender: P::Id,
  pub kind: P2pMessageKind,
  pub msg: Vec<u8>,
}

#[derive(Clone, Debug, Encode, Decode)]
pub struct BlockCommit {
  pub block: Vec<u8>,
  pub commit: Vec<u8>,
}

#[derive(Clone, Debug, Encode, Decode)]
pub struct HeartbeatBatch {
  pub blocks: Vec<BlockCommit>,
  pub timestamp: u64,
}

#[async_trait]
pub trait P2p: Send + Sync + Clone + fmt::Debug + TributaryP2p {
  type Id: Send + Sync + Clone + Copy + fmt::Debug;

  async fn subscribe(&self, set: ExternalValidatorSet, genesis: [u8; 32]);
  async fn unsubscribe(&self, set: ExternalValidatorSet, genesis: [u8; 32]);

  async fn send_raw(&self, to: Self::Id, msg: Vec<u8>);
  async fn broadcast_raw(&self, kind: P2pMessageKind, msg: Vec<u8>);
  async fn receive(&self) -> Message<Self>;

  async fn send(&self, to: Self::Id, kind: ReqResMessageKind, msg: Vec<u8>) {
    let mut actual_msg = kind.serialize();
    actual_msg.extend(msg);
    self.send_raw(to, actual_msg).await;
  }
  async fn broadcast(&self, kind: impl Send + Into<P2pMessageKind>, msg: Vec<u8>) {
    let kind = kind.into();
    let mut actual_msg = match kind {
      P2pMessageKind::ReqRes(kind) => kind.serialize(),
      P2pMessageKind::Gossip(kind) => kind.serialize(),
    };
    actual_msg.extend(msg);
    /*
    log::trace!(
      "broadcasting p2p message (kind {})",
      match kind {
        P2pMessageKind::KeepAlive => "KeepAlive".to_string(),
        P2pMessageKind::Tributary(genesis) => format!("Tributary({})", hex::encode(genesis)),
        P2pMessageKind::Heartbeat(genesis) => format!("Heartbeat({})", hex::encode(genesis)),
        P2pMessageKind::Block(genesis) => format!("Block({})", hex::encode(genesis)),
        P2pMessageKind::CosignedBlock => "CosignedBlock".to_string(),
      }
    );
    */
    self.broadcast_raw(kind, actual_msg).await;
  }
}

#[derive(Default, Clone, Copy, PartialEq, Eq, Debug)]
struct RrCodec;
#[async_trait]
impl RrCodecTrait for RrCodec {
  type Protocol = &'static str;
  type Request = Vec<u8>;
  type Response = Vec<u8>;

  async fn read_request<R: Send + Unpin + AsyncRead>(
    &mut self,
    _: &Self::Protocol,
    io: &mut R,
  ) -> io::Result<Vec<u8>> {
    let mut len = [0; 4];
    io.read_exact(&mut len).await?;
    let len = usize::try_from(u32::from_le_bytes(len)).expect("not at least a 32-bit platform?");
    if len > MAX_LIBP2P_REQRES_MESSAGE_SIZE {
      Err(io::Error::other("request length exceeded MAX_LIBP2P_REQRES_MESSAGE_SIZE"))?;
    }
    // This may be a non-trivial allocation easily causable
    // While we could chunk the read, meaning we only perform the allocation as bandwidth is used,
    // the max message size should be sufficiently sane
    let mut buf = vec![0; len];
    io.read_exact(&mut buf).await?;
    Ok(buf)
  }
  async fn read_response<R: Send + Unpin + AsyncRead>(
    &mut self,
    proto: &Self::Protocol,
    io: &mut R,
  ) -> io::Result<Vec<u8>> {
    self.read_request(proto, io).await
  }
  async fn write_request<W: Send + Unpin + AsyncWrite>(
    &mut self,
    _: &Self::Protocol,
    io: &mut W,
    req: Vec<u8>,
  ) -> io::Result<()> {
    io.write_all(
      &u32::try_from(req.len())
        .map_err(|_| io::Error::other("request length exceeded 2**32"))?
        .to_le_bytes(),
    )
    .await?;
    io.write_all(&req).await
  }
  async fn write_response<W: Send + Unpin + AsyncWrite>(
    &mut self,
    proto: &Self::Protocol,
    io: &mut W,
    res: Vec<u8>,
  ) -> io::Result<()> {
    self.write_request(proto, io, res).await
  }
}

#[derive(NetworkBehaviour)]
struct Behavior {
  reqres: RrBehavior<RrCodec>,
  gossipsub: GsBehavior,
}

#[allow(clippy::type_complexity)]
#[derive(Clone)]
pub struct LibP2p {
  subscribe: Arc<Mutex<mpsc::UnboundedSender<(bool, ExternalValidatorSet, [u8; 32])>>>,
  send: Arc<Mutex<mpsc::UnboundedSender<(PeerId, Vec<u8>)>>>,
  broadcast: Arc<Mutex<mpsc::UnboundedSender<(P2pMessageKind, Vec<u8>)>>>,
  receive: Arc<Mutex<mpsc::UnboundedReceiver<Message<Self>>>>,
}
impl fmt::Debug for LibP2p {
  fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
    fmt.debug_struct("LibP2p").finish_non_exhaustive()
  }
}

impl LibP2p {
  #[allow(clippy::new_without_default)]
  pub fn new(serai: Arc<Serai>) -> Self {
    log::info!("creating a libp2p instance");

    let throwaway_key_pair = Keypair::generate_ed25519();

    let behavior = Behavior {
      reqres: { RrBehavior::new([("/coordinator", ProtocolSupport::Full)], RrConfig::default()) },
      gossipsub: {
        let heartbeat_interval = tributary::tendermint::LATENCY_TIME / 2;
        let heartbeats_per_block =
          usize::try_from(tributary::tendermint::TARGET_BLOCK_TIME / heartbeat_interval).unwrap();

        use blake2::{Digest, Blake2s256};
        let config = ConfigBuilder::default()
          .heartbeat_interval(Duration::from_millis(heartbeat_interval.into()))
          .history_length(heartbeats_per_block * 2)
          .history_gossip(heartbeats_per_block)
          .max_transmit_size(MAX_LIBP2P_GOSSIP_MESSAGE_SIZE)
          // We send KeepAlive after 80s
          .idle_timeout(Duration::from_secs(85))
          .validation_mode(ValidationMode::Strict)
          // Uses a content based message ID to avoid duplicates as much as possible
          .message_id_fn(|msg| {
            MessageId::new(&Blake2s256::digest([msg.topic.as_str().as_bytes(), &msg.data].concat()))
          })
          // Re-defines for fast ID to prevent needing to convert into a Message to run
          // message_id_fn
          // This function is valid for both
          .fast_message_id_fn(|msg| {
            FastMessageId::new(&Blake2s256::digest(
              [msg.topic.as_str().as_bytes(), &msg.data].concat(),
            ))
          })
          .build();
        let mut gossipsub = GsBehavior::<IdentityTransform, AllowAllSubscriptionFilter>::new(
          MessageAuthenticity::Signed(throwaway_key_pair.clone()),
          config.unwrap(),
        )
        .unwrap();

        // Subscribe to the base topic
        let topic = IdentTopic::new(LIBP2P_TOPIC);
        gossipsub.subscribe(&topic).unwrap();

        gossipsub
      },
    };

    // Uses noise for authentication, yamux for multiplexing
    // TODO: Do we want to add a custom authentication protocol to only accept connections from
    // fellow validators? Doing so would reduce the potential for spam
    // TODO: Relay client?
    let mut swarm = SwarmBuilder::with_existing_identity(throwaway_key_pair)
      .with_tokio()
      .with_tcp(TcpConfig::default().nodelay(true), noise::Config::new, || {
        let mut config = yamux::Config::default();
        // 1 MiB default + max message size
        config.set_max_buffer_size((1024 * 1024) + MAX_LIBP2P_MESSAGE_SIZE);
        // 256 KiB default + max message size
        config
          .set_receive_window_size(((256 * 1024) + MAX_LIBP2P_MESSAGE_SIZE).try_into().unwrap());
        config
      })
      .unwrap()
      .with_behaviour(|_| behavior)
      .unwrap()
      .build();
    const PORT: u16 = 30563; // 5132 ^ (('c' << 8) | 'o')
    swarm.listen_on(format!("/ip4/0.0.0.0/tcp/{PORT}").parse().unwrap()).unwrap();

    let (send_send, mut send_recv) = mpsc::unbounded_channel();
    let (broadcast_send, mut broadcast_recv) = mpsc::unbounded_channel();
    let (receive_send, receive_recv) = mpsc::unbounded_channel();
    let (subscribe_send, mut subscribe_recv) = mpsc::unbounded_channel();

    fn topic_for_set(set: ExternalValidatorSet) -> IdentTopic {
      IdentTopic::new(format!("{LIBP2P_TOPIC}-{}", hex::encode(set.encode())))
    }

    // TODO: If a network has less than TARGET_PEERS, this will cause retries ad infinitum
    const TARGET_PEERS: usize = 5;

    // The addrs we're currently dialing, and the networks associated with them
    let dialing_peers = Arc::new(RwLock::new(HashMap::new()));
    // The peers we're currently connected to, and the networks associated with them
    let connected_peers =
      Arc::new(RwLock::new(HashMap::<Multiaddr, HashSet<ExternalNetworkId>>::new()));

    // Find and connect to peers
    let (connect_to_network_send, mut connect_to_network_recv) =
      tokio::sync::mpsc::unbounded_channel();
    let (to_dial_send, mut to_dial_recv) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn({
      let dialing_peers = dialing_peers.clone();
      let connected_peers = connected_peers.clone();

      let connect_to_network_send = connect_to_network_send.clone();
      async move {
        loop {
          let connect = |network: ExternalNetworkId, addr: Multiaddr| {
            let dialing_peers = dialing_peers.clone();
            let connected_peers = connected_peers.clone();
            let to_dial_send = to_dial_send.clone();
            let connect_to_network_send = connect_to_network_send.clone();
            async move {
              log::info!("found peer from substrate: {addr}");

              let protocols = addr.iter().filter_map(|piece| match piece {
                // Drop PeerIds from the Substrate P2p network
                Protocol::P2p(_) => None,
                // Use our own TCP port
                Protocol::Tcp(_) => Some(Protocol::Tcp(PORT)),
                other => Some(other),
              });

              let mut new_addr = Multiaddr::empty();
              for protocol in protocols {
                new_addr.push(protocol);
              }
              let addr = new_addr;
              log::debug!("transformed found peer: {addr}");

              let (is_fresh_dial, nets) = {
                let mut dialing_peers = dialing_peers.write().await;
                let is_fresh_dial = !dialing_peers.contains_key(&addr);
                if is_fresh_dial {
                  dialing_peers.insert(addr.clone(), HashSet::new());
                }
                // Associate this network with this peer
                dialing_peers.get_mut(&addr).unwrap().insert(network);

                let nets = dialing_peers.get(&addr).unwrap().clone();
                (is_fresh_dial, nets)
              };

              // Spawn a task to remove this peer from 'dialing' in sixty seconds, in case dialing
              // fails
              // This performs cleanup and bounds the size of the map to whatever growth occurs
              // within a temporal window
              tokio::spawn({
                let dialing_peers = dialing_peers.clone();
                let connected_peers = connected_peers.clone();
                let connect_to_network_send = connect_to_network_send.clone();
                let addr = addr.clone();
                async move {
                  tokio::time::sleep(core::time::Duration::from_secs(60)).await;
                  let mut dialing_peers = dialing_peers.write().await;
                  if let Some(expected_nets) = dialing_peers.remove(&addr) {
                    log::debug!("removed addr from dialing upon timeout: {addr}");

                    // TODO: De-duplicate this below instance
                    // If we failed to dial and haven't gotten enough actual connections, retry
                    let connected_peers = connected_peers.read().await;
                    for net in expected_nets {
                      let mut remaining_peers = 0;
                      for nets in connected_peers.values() {
                        if nets.contains(&net) {
                          remaining_peers += 1;
                        }
                      }
                      // If we do not, start connecting to this network again
                      if remaining_peers < TARGET_PEERS {
                        connect_to_network_send.send(net).expect(
                          "couldn't send net to connect to due to disconnects (receiver dropped?)",
                        );
                      }
                    }
                  }
                }
              });

              if is_fresh_dial {
                to_dial_send.send((addr, nets)).unwrap();
              }
            }
          };

          // TODO: We should also connect to random peers from random nets as needed for
          // cosigning

          // Drain the chainnel, de-duplicating any networks in it
          let mut connect_to_network_networks = HashSet::new();
          while let Ok(network) = connect_to_network_recv.try_recv() {
            connect_to_network_networks.insert(network);
          }
          for network in connect_to_network_networks {
            if let Ok(mut nodes) = serai.p2p_validators(network.into()).await {
              // If there's an insufficient amount of nodes known, connect to all yet add it
              // back and break
              if nodes.len() < TARGET_PEERS {
                log::warn!(
                  "insufficient amount of P2P nodes known for {:?}: {}",
                  network,
                  nodes.len()
                );
                // Retry this later
                connect_to_network_send.send(network).unwrap();
                for node in nodes {
                  connect(network, node).await;
                }
                continue;
              }

              // Randomly select up to 150% of the TARGET_PEERS
              for _ in 0 .. ((3 * TARGET_PEERS) / 2) {
                if !nodes.is_empty() {
                  let to_connect = nodes.swap_remove(
                    usize::try_from(OsRng.next_u64() % u64::try_from(nodes.len()).unwrap())
                      .unwrap(),
                  );
                  connect(network, to_connect).await;
                }
              }
            }
          }
          // Sleep 60 seconds before moving to the next iteration
          tokio::time::sleep(core::time::Duration::from_secs(60)).await;
        }
      }
    });

    // Manage the actual swarm
    tokio::spawn({
      let mut time_of_last_p2p_message = Instant::now();

      async move {
        let connected_peers = connected_peers.clone();

        let mut set_for_genesis = HashMap::new();
        loop {
          let time_since_last = Instant::now().duration_since(time_of_last_p2p_message);
          tokio::select! {
            biased;

            // Subscribe to any new topics
            set = subscribe_recv.recv() => {
              let (subscribe, set, genesis): (_, ExternalValidatorSet, [u8; 32]) =
                set.expect("subscribe_recv closed. are we shutting down?");
              let topic = topic_for_set(set);
              if subscribe {
                log::info!("subscribing to p2p messages for {set:?}");
                connect_to_network_send.send(set.network).unwrap();
                set_for_genesis.insert(genesis, set);
                swarm.behaviour_mut().gossipsub.subscribe(&topic).unwrap();
              } else {
                log::info!("unsubscribing to p2p messages for {set:?}");
                set_for_genesis.remove(&genesis);
                swarm.behaviour_mut().gossipsub.unsubscribe(&topic).unwrap();
              }
            }

            msg = send_recv.recv() => {
              let (peer, msg): (PeerId, Vec<u8>) =
                msg.expect("send_recv closed. are we shutting down?");
              swarm.behaviour_mut().reqres.send_request(&peer, msg);
            },

            // Handle any queued outbound messages
            msg = broadcast_recv.recv() => {
              // Update the time of last message
              time_of_last_p2p_message = Instant::now();

              let (kind, msg): (P2pMessageKind, Vec<u8>) =
                msg.expect("broadcast_recv closed. are we shutting down?");

              if matches!(kind, P2pMessageKind::ReqRes(_)) {
                // Use request/response, yet send to all connected peers
                for peer_id in swarm.connected_peers().copied().collect::<Vec<_>>() {
                  swarm.behaviour_mut().reqres.send_request(&peer_id, msg.clone());
                }
              } else {
                // Use gossipsub

                let set =
                  kind.genesis().and_then(|genesis| set_for_genesis.get(&genesis).copied());
                let topic = if let Some(set) = set {
                  topic_for_set(set)
                } else {
                  IdentTopic::new(LIBP2P_TOPIC)
                };

                match swarm.behaviour_mut().gossipsub.publish(topic, msg.clone()) {
                  Err(PublishError::SigningError(e)) => {
                    panic!("signing error when broadcasting: {e}")
                  },
                  Err(PublishError::InsufficientPeers) => {
                    log::warn!("failed to send p2p message due to insufficient peers")
                  }
                  Err(PublishError::MessageTooLarge) => {
                    panic!("tried to send a too large message: {}", hex::encode(msg))
                  }
                  Err(PublishError::TransformFailed(e)) => panic!("IdentityTransform failed: {e}"),
                  Err(PublishError::Duplicate) | Ok(_) => {}
                }
              }
            }

            // Handle new incoming messages
            event = swarm.next() => {
              match event {
                Some(SwarmEvent::Dialing { connection_id, .. }) => {
                  log::debug!("dialing to peer in connection ID {}", &connection_id);
                }
                Some(SwarmEvent::ConnectionEstablished {
                  peer_id,
                  connection_id,
                  endpoint,
                  ..
                }) => {
                  if &peer_id == swarm.local_peer_id() {
                    log::warn!("established a libp2p connection to ourselves");
                    swarm.close_connection(connection_id);
                    continue;
                  }

                  let addr = endpoint.get_remote_address();
                  let nets = {
                    let mut dialing_peers = dialing_peers.write().await;
                    if let Some(nets) = dialing_peers.remove(addr) {
                      nets
                    } else {
                      log::debug!("connected to a peer who we didn't have within dialing");
                      HashSet::new()
                    }
                  };
                  {
                    let mut connected_peers = connected_peers.write().await;
                    connected_peers.insert(addr.clone(), nets);

                    log::debug!(
                      "connection established to peer {} in connection ID {}, connected peers: {}",
                      &peer_id,
                      &connection_id,
                      connected_peers.len(),
                    );
                  }
                }
                Some(SwarmEvent::ConnectionClosed { peer_id, endpoint, .. }) => {
                  let mut connected_peers = connected_peers.write().await;
                  let Some(nets) = connected_peers.remove(endpoint.get_remote_address()) else {
                    log::debug!("closed connection to peer which wasn't in connected_peers");
                    continue;
                  };
                  // Downgrade to a read lock
                  let connected_peers = connected_peers.downgrade();

                  // For each net we lost a peer for, check if we still have sufficient peers
                  // overall
                  for net in nets {
                    let mut remaining_peers = 0;
                    for nets in connected_peers.values() {
                      if nets.contains(&net) {
                        remaining_peers += 1;
                      }
                    }
                    // If we do not, start connecting to this network again
                    if remaining_peers < TARGET_PEERS {
                      connect_to_network_send
                        .send(net)
                        .expect(
                          "couldn't send net to connect to due to disconnects (receiver dropped?)"
                        );
                    }
                  }

                  log::debug!(
                    "connection with peer {peer_id} closed, connected peers: {}",
                    connected_peers.len(),
                  );
                }
                Some(SwarmEvent::Behaviour(BehaviorEvent::Reqres(
                  RrEvent::Message { peer, message },
                ))) => {
                  let message = match message {
                    RrMessage::Request { request, .. } => request,
                    RrMessage::Response { response, .. } => response,
                  };

                  let mut msg_ref = message.as_slice();
                  let Some(kind) = ReqResMessageKind::read(&mut msg_ref) else { continue };
                  let message = Message {
                    sender: peer,
                    kind: P2pMessageKind::ReqRes(kind),
                    msg: msg_ref.to_vec(),
                  };
                  receive_send.send(message).expect("receive_send closed. are we shutting down?");
                }
                Some(SwarmEvent::Behaviour(BehaviorEvent::Gossipsub(
                  GsEvent::Message { propagation_source, message, .. },
                ))) => {
                  let mut msg_ref = message.data.as_slice();
                  let Some(kind) = GossipMessageKind::read(&mut msg_ref) else { continue };
                  let message = Message {
                    sender: propagation_source,
                    kind: P2pMessageKind::Gossip(kind),
                    msg: msg_ref.to_vec(),
                  };
                  receive_send.send(message).expect("receive_send closed. are we shutting down?");
                }
                _ => {}
              }
            }

            // Handle peers to dial
            addr_and_nets = to_dial_recv.recv() => {
              let (addr, nets) =
                addr_and_nets.expect("received address was None (sender dropped?)");
              // If we've already dialed and connected to this address, don't further dial them
              // Just associate these networks with them
              if let Some(existing_nets) = connected_peers.write().await.get_mut(&addr) {
                for net in nets {
                  existing_nets.insert(net);
                }
                continue;
              }

              if let Err(e) = swarm.dial(addr) {
                log::warn!("dialing peer failed: {e:?}");
              }
            }

            // If it's been >80s since we've published a message, publish a KeepAlive since we're
            // still an active service
            // This is useful when we have no active tributaries and accordingly aren't sending
            // heartbeats
            // If we are sending heartbeats, we should've sent one after 60s of no finalized blocks
            // (where a finalized block only occurs due to network activity), meaning this won't be
            // run
            () = tokio::time::sleep(Duration::from_secs(80).saturating_sub(time_since_last)) => {
              time_of_last_p2p_message = Instant::now();
              for peer_id in swarm.connected_peers().copied().collect::<Vec<_>>() {
                swarm
                  .behaviour_mut()
                  .reqres
                  .send_request(&peer_id, ReqResMessageKind::KeepAlive.serialize());
              }
            }
          }
        }
      }
    });

    LibP2p {
      subscribe: Arc::new(Mutex::new(subscribe_send)),
      send: Arc::new(Mutex::new(send_send)),
      broadcast: Arc::new(Mutex::new(broadcast_send)),
      receive: Arc::new(Mutex::new(receive_recv)),
    }
  }
}

#[async_trait]
impl P2p for LibP2p {
  type Id = PeerId;

  async fn subscribe(&self, set: ExternalValidatorSet, genesis: [u8; 32]) {
    self
      .subscribe
      .lock()
      .await
      .send((true, set, genesis))
      .expect("subscribe_send closed. are we shutting down?");
  }

  async fn unsubscribe(&self, set: ExternalValidatorSet, genesis: [u8; 32]) {
    self
      .subscribe
      .lock()
      .await
      .send((false, set, genesis))
      .expect("subscribe_send closed. are we shutting down?");
  }

  async fn send_raw(&self, peer: Self::Id, msg: Vec<u8>) {
    self.send.lock().await.send((peer, msg)).expect("send_send closed. are we shutting down?");
  }

  async fn broadcast_raw(&self, kind: P2pMessageKind, msg: Vec<u8>) {
    self
      .broadcast
      .lock()
      .await
      .send((kind, msg))
      .expect("broadcast_send closed. are we shutting down?");
  }

  // TODO: We only have a single handle call this. Differentiate Send/Recv to remove this constant
  // lock acquisition?
  async fn receive(&self) -> Message<Self> {
    self.receive.lock().await.recv().await.expect("receive_recv closed. are we shutting down?")
  }
}

#[async_trait]
impl TributaryP2p for LibP2p {
  async fn broadcast(&self, genesis: [u8; 32], msg: Vec<u8>) {
    <Self as P2p>::broadcast(self, GossipMessageKind::Tributary(genesis), msg).await
  }
}

pub async fn heartbeat_tributaries_task<D: Db, P: P2p>(
  p2p: P,
  mut tributary_event: broadcast::Receiver<TributaryEvent<D, P>>,
) {
  let ten_blocks_of_time =
    Duration::from_secs((10 * Tributary::<D, Transaction, P>::block_time()).into());

  let mut readers = HashMap::new();
  loop {
    loop {
      match tributary_event.try_recv() {
        Ok(TributaryEvent::NewTributary(ActiveTributary { spec, tributary })) => {
          readers.insert(spec.set(), tributary.reader());
        }
        Ok(TributaryEvent::TributaryRetired(set)) => {
          readers.remove(&set);
        }
        Err(broadcast::error::TryRecvError::Empty) => break,
        Err(broadcast::error::TryRecvError::Lagged(_)) => {
          panic!("heartbeat_tributaries lagged to handle tributary_event")
        }
        Err(broadcast::error::TryRecvError::Closed) => panic!("tributary_event sender closed"),
      }
    }

    for tributary in readers.values() {
      let tip = tributary.tip();
      let block_time =
        SystemTime::UNIX_EPOCH + Duration::from_secs(tributary.time_of_block(&tip).unwrap_or(0));

      // Only trigger syncing if the block is more than a minute behind
      if SystemTime::now() > (block_time + Duration::from_secs(60)) {
        log::warn!("last known tributary block was over a minute ago");
        let mut msg = tip.to_vec();
        let time: u64 = SystemTime::now()
          .duration_since(SystemTime::UNIX_EPOCH)
          .expect("system clock is wrong")
          .as_secs();
        msg.extend(time.to_le_bytes());
        P2p::broadcast(&p2p, ReqResMessageKind::Heartbeat(tributary.genesis()), msg).await;
      }
    }

    // Only check once every 10 blocks of time
    sleep(ten_blocks_of_time).await;
  }
}

pub async fn handle_p2p_task<D: Db, P: P2p>(
  p2p: P,
  cosign_channel: mpsc::UnboundedSender<CosignedBlock>,
  mut tributary_event: broadcast::Receiver<TributaryEvent<D, P>>,
) {
  let channels = Arc::new(RwLock::new(HashMap::<_, mpsc::UnboundedSender<Message<P>>>::new()));
  tokio::spawn({
    let p2p = p2p.clone();
    let channels = channels.clone();
    let mut set_to_genesis = HashMap::new();
    async move {
      loop {
        match tributary_event.recv().await.unwrap() {
          TributaryEvent::NewTributary(tributary) => {
            let genesis = tributary.spec.genesis();
            set_to_genesis.insert(tributary.spec.set(), genesis);

            let (send, mut recv) = mpsc::unbounded_channel();
            channels.write().await.insert(genesis, send);

            // Subscribe to the topic for this tributary
            p2p.subscribe(tributary.spec.set(), genesis).await;

            let spec_set = tributary.spec.set();

            // Per-Tributary P2P message handler
            tokio::spawn({
              let p2p = p2p.clone();
              async move {
                loop {
                  let Some(msg) = recv.recv().await else {
                    // Channel closure happens when the tributary retires
                    break;
                  };
                  match msg.kind {
                    P2pMessageKind::ReqRes(ReqResMessageKind::KeepAlive) => {}

                    // TODO: Slash on Heartbeat which justifies a response, since the node
                    // obviously was offline and we must now use our bandwidth to compensate for
                    // them?
                    P2pMessageKind::ReqRes(ReqResMessageKind::Heartbeat(msg_genesis)) => {
                      assert_eq!(msg_genesis, genesis);
                      if msg.msg.len() != 40 {
                        log::error!("validator sent invalid heartbeat");
                        continue;
                      }
                      // Only respond to recent heartbeats
                      let msg_time = u64::from_le_bytes(msg.msg[32 .. 40].try_into().expect(
                        "length-checked heartbeat message didn't have 8 bytes for the u64",
                      ));
                      if SystemTime::now()
                        .duration_since(SystemTime::UNIX_EPOCH)
                        .expect("system clock is wrong")
                        .as_secs()
                        .saturating_sub(msg_time) >
                        10
                      {
                        continue;
                      }

                      log::debug!("received heartbeat with a recent timestamp");

                      let reader = tributary.tributary.reader();

                      let p2p = p2p.clone();
                      // Spawn a dedicated task as this may require loading large amounts of data
                      // from disk and take a notable amount of time
                      tokio::spawn(async move {
                        let mut latest = msg.msg[.. 32].try_into().unwrap();
                        let mut to_send = vec![];
                        while let Some(next) = reader.block_after(&latest) {
                          to_send.push(next);
                          latest = next;
                        }
                        if to_send.len() > 3 {
                          // prepare the batch to sends
                          let mut blocks = vec![];
                          for (i, next) in to_send.iter().enumerate() {
                            if i >= BLOCKS_PER_BATCH {
                              break;
                            }

                            blocks.push(BlockCommit {
                              block: reader.block(next).unwrap().serialize(),
                              commit: reader.commit(next).unwrap(),
                            });
                          }
                          let batch = HeartbeatBatch { blocks, timestamp: msg_time };

                          p2p
                            .send(msg.sender, ReqResMessageKind::Block(genesis), batch.encode())
                            .await;
                        }
                      });
                    }

                    P2pMessageKind::ReqRes(ReqResMessageKind::Block(msg_genesis)) => {
                      assert_eq!(msg_genesis, genesis);
                      // decode the batch
                      let Ok(batch) = HeartbeatBatch::decode(&mut msg.msg.as_ref()) else {
                        log::error!(
                          "received HeartBeatBatch message with an invalidly serialized batch"
                        );
                        continue;
                      };

                      // sync blocks
                      for bc in batch.blocks {
                        // TODO: why do we use ReadWrite instead of Encode/Decode for blocks?
                        // Should we use the same for batches so we can read both at the same time?
                        let Ok(block) = Block::<Transaction>::read(&mut bc.block.as_slice()) else {
                          log::error!("received block message with an invalidly serialized block");
                          continue;
                        };

                        let res = tributary.tributary.sync_block(block, bc.commit).await;
                        log::debug!(
                          "received block from {:?}, sync_block returned {}",
                          msg.sender,
                          res
                        );
                      }
                    }

                    P2pMessageKind::Gossip(GossipMessageKind::Tributary(msg_genesis)) => {
                      assert_eq!(msg_genesis, genesis);
                      log::trace!("handling message for tributary {:?}", spec_set);
                      if tributary.tributary.handle_message(&msg.msg).await {
                        P2p::broadcast(&p2p, msg.kind, msg.msg).await;
                      }
                    }

                    P2pMessageKind::Gossip(GossipMessageKind::CosignedBlock) => unreachable!(),
                  }
                }
              }
            });
          }
          TributaryEvent::TributaryRetired(set) => {
            if let Some(genesis) = set_to_genesis.remove(&set) {
              p2p.unsubscribe(set, genesis).await;
              channels.write().await.remove(&genesis);
            }
          }
        }
      }
    }
  });

  loop {
    let msg = p2p.receive().await;
    match msg.kind {
      P2pMessageKind::ReqRes(ReqResMessageKind::KeepAlive) => {}
      P2pMessageKind::Gossip(GossipMessageKind::Tributary(genesis)) |
      P2pMessageKind::ReqRes(
        ReqResMessageKind::Heartbeat(genesis) | ReqResMessageKind::Block(genesis),
      ) => {
        if let Some(channel) = channels.read().await.get(&genesis) {
          channel.send(msg).unwrap();
        }
      }
      P2pMessageKind::Gossip(GossipMessageKind::CosignedBlock) => {
        let Ok(msg) = CosignedBlock::deserialize_reader(&mut msg.msg.as_slice()) else {
          log::error!("received CosignedBlock message with invalidly serialized contents");
          continue;
        };
        cosign_channel.send(msg).unwrap();
      }
    }
  }
}
