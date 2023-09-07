use core::{time::Duration, fmt};
use std::{sync::Arc, time::Instant, io::Read};

use async_trait::async_trait;

use tokio::sync::{mpsc, Mutex};

use libp2p::{
  futures::StreamExt,
  identity::Keypair,
  PeerId, Transport,
  core::upgrade,
  tcp::{Config, tokio as libp2p_tokio},
  noise, yamux,
  gossipsub::{
    IdentTopic, FastMessageId, MessageId, MessageAuthenticity, ValidationMode, ConfigBuilder,
    IdentityTransform, AllowAllSubscriptionFilter, Event as GsEvent, PublishError,
    Behaviour as GsBehavior,
  },
  swarm::{NetworkBehaviour, SwarmBuilder, SwarmEvent, Swarm},
};

pub use tributary::P2p as TributaryP2p;

// TODO: Use distinct topics
const LIBP2P_TOPIC: &str = "serai-coordinator";

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum P2pMessageKind {
  KeepAlive,
  Tributary([u8; 32]),
  Heartbeat([u8; 32]),
  Block([u8; 32]),
}

impl P2pMessageKind {
  fn serialize(&self) -> Vec<u8> {
    match self {
      P2pMessageKind::KeepAlive => vec![0],
      P2pMessageKind::Tributary(genesis) => {
        let mut res = vec![1];
        res.extend(genesis);
        res
      }
      P2pMessageKind::Heartbeat(genesis) => {
        let mut res = vec![2];
        res.extend(genesis);
        res
      }
      P2pMessageKind::Block(genesis) => {
        let mut res = vec![3];
        res.extend(genesis);
        res
      }
    }
  }

  fn read<R: Read>(reader: &mut R) -> Option<P2pMessageKind> {
    let mut kind = [0; 1];
    reader.read_exact(&mut kind).ok()?;
    match kind[0] {
      0 => Some(P2pMessageKind::KeepAlive),
      1 => Some({
        let mut genesis = [0; 32];
        reader.read_exact(&mut genesis).ok()?;
        P2pMessageKind::Tributary(genesis)
      }),
      2 => Some({
        let mut genesis = [0; 32];
        reader.read_exact(&mut genesis).ok()?;
        P2pMessageKind::Heartbeat(genesis)
      }),
      3 => Some({
        let mut genesis = [0; 32];
        reader.read_exact(&mut genesis).ok()?;
        P2pMessageKind::Block(genesis)
      }),
      _ => None,
    }
  }
}

#[derive(Clone, Debug)]
pub struct Message<P: P2p> {
  pub sender: P::Id,
  pub kind: P2pMessageKind,
  pub msg: Vec<u8>,
}

#[async_trait]
pub trait P2p: Send + Sync + Clone + fmt::Debug + TributaryP2p {
  type Id: Send + Sync + Clone + Copy + fmt::Debug;

  async fn send_raw(&self, to: Self::Id, msg: Vec<u8>);
  async fn broadcast_raw(&self, msg: Vec<u8>);
  async fn receive_raw(&self) -> (Self::Id, Vec<u8>);

  async fn send(&self, to: Self::Id, kind: P2pMessageKind, msg: Vec<u8>) {
    let mut actual_msg = kind.serialize();
    actual_msg.extend(msg);
    self.send_raw(to, actual_msg).await;
  }
  async fn broadcast(&self, kind: P2pMessageKind, msg: Vec<u8>) {
    let mut actual_msg = kind.serialize();
    actual_msg.extend(msg);
    log::trace!(
      "broadcasting p2p message (kind {})",
      match kind {
        P2pMessageKind::KeepAlive => "KeepAlive".to_string(),
        P2pMessageKind::Tributary(genesis) => format!("Tributary({})", hex::encode(genesis)),
        P2pMessageKind::Heartbeat(genesis) => format!("Heartbeat({})", hex::encode(genesis)),
        P2pMessageKind::Block(genesis) => format!("Block({})", hex::encode(genesis)),
      }
    );
    self.broadcast_raw(actual_msg).await;
  }
  async fn receive(&self) -> Message<Self> {
    let (sender, kind, msg) = loop {
      let (sender, msg) = self.receive_raw().await;
      if msg.is_empty() {
        log::error!("empty p2p message from {sender:?}");
        continue;
      }

      let mut msg_ref = msg.as_ref();
      let Some(kind) = P2pMessageKind::read::<&[u8]>(&mut msg_ref) else {
        log::error!("invalid p2p message kind from {sender:?}");
        continue;
      };
      break (sender, kind, msg_ref.to_vec());
    };
    log::trace!(
      "received p2p message (kind {})",
      match kind {
        P2pMessageKind::KeepAlive => "KeepAlive".to_string(),
        P2pMessageKind::Tributary(genesis) => format!("Tributary({})", hex::encode(genesis)),
        P2pMessageKind::Heartbeat(genesis) => format!("Heartbeat({})", hex::encode(genesis)),
        P2pMessageKind::Block(genesis) => format!("Block({})", hex::encode(genesis)),
      }
    );
    Message { sender, kind, msg }
  }
}

#[derive(NetworkBehaviour)]
struct Behavior {
  gossipsub: GsBehavior,
  //#[cfg(debug_assertions)]
  mdns: libp2p::mdns::tokio::Behaviour,
}

lazy_static::lazy_static! {
  static ref TIME_OF_LAST_P2P_MESSAGE: Mutex<Instant> = Mutex::new(Instant::now());
}

#[allow(clippy::type_complexity)]
#[derive(Clone)]
pub struct LibP2p(
  Arc<Mutex<mpsc::UnboundedSender<Vec<u8>>>>,
  Arc<Mutex<mpsc::UnboundedReceiver<(PeerId, Vec<u8>)>>>,
);
impl fmt::Debug for LibP2p {
  fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
    fmt.debug_struct("LibP2p").finish_non_exhaustive()
  }
}

impl LibP2p {
  #[allow(clippy::new_without_default)]
  pub fn new() -> Self {
    log::info!("creating a libp2p instance");

    let throwaway_key_pair = Keypair::generate_ed25519();
    let throwaway_peer_id = PeerId::from(throwaway_key_pair.public());

    // Uses noise for authentication, yamux for multiplexing
    // TODO: Do we want to add a custom authentication protocol to only accept connections from
    // fellow validators? Doing so would reduce the potential for spam
    let transport = libp2p_tokio::Transport::new(Config::default().nodelay(true))
      .upgrade(upgrade::Version::V1)
      .authenticate(noise::Config::new(&throwaway_key_pair).unwrap())
      .multiplex(yamux::Config::default())
      .boxed();

    let behavior = Behavior {
      gossipsub: {
        // Block size limit + 1 KB of space for signatures/metadata
        const MAX_LIBP2P_MESSAGE_SIZE: usize = tributary::BLOCK_SIZE_LIMIT + 1024;

        let heartbeat_interval = tributary::tendermint::LATENCY_TIME / 2;
        let heartbeats_per_block =
          usize::try_from(tributary::tendermint::TARGET_BLOCK_TIME / heartbeat_interval).unwrap();

        use blake2::{Digest, Blake2s256};
        let config = ConfigBuilder::default()
          .heartbeat_interval(Duration::from_millis(heartbeat_interval.into()))
          .history_length(heartbeats_per_block * 2)
          .history_gossip(heartbeats_per_block)
          .max_transmit_size(MAX_LIBP2P_MESSAGE_SIZE)
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
          MessageAuthenticity::Signed(throwaway_key_pair),
          config.unwrap(),
        )
        .unwrap();

        // Uses a single topic to prevent being a BTC validator only connected to ETH validators,
        // unable to communicate with other BTC validators
        let topic = IdentTopic::new(LIBP2P_TOPIC);
        gossipsub.subscribe(&topic).unwrap();

        gossipsub
      },

      // Only use MDNS in debug environments, as it should have no value in a release build
      // TODO: We do tests on release binaries as of right now...
      //#[cfg(debug_assertions)]
      mdns: {
        log::info!("creating mdns service");
        libp2p::mdns::tokio::Behaviour::new(libp2p::mdns::Config::default(), throwaway_peer_id)
          .unwrap()
      },
    };

    let mut swarm =
      SwarmBuilder::with_tokio_executor(transport, behavior, throwaway_peer_id).build();
    const PORT: u16 = 30563; // 5132 ^ (('c' << 8) | 'o')
    swarm.listen_on(format!("/ip4/0.0.0.0/tcp/{PORT}").parse().unwrap()).unwrap();

    let (broadcast_send, mut broadcast_recv) = mpsc::unbounded_channel();
    let (receive_send, receive_recv) = mpsc::unbounded_channel();

    tokio::spawn({
      #[allow(clippy::needless_pass_by_ref_mut)] // False positive
      async fn broadcast_raw(p2p: &mut Swarm<Behavior>, msg: Vec<u8>) {
        // Update the time of last message
        *TIME_OF_LAST_P2P_MESSAGE.lock().await = Instant::now();

        match p2p.behaviour_mut().gossipsub.publish(IdentTopic::new(LIBP2P_TOPIC), msg.clone()) {
          Err(PublishError::SigningError(e)) => panic!("signing error when broadcasting: {e}"),
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

      async move {
        // Run this task ad-infinitum
        loop {
          let time_since_last =
            Instant::now().duration_since(*TIME_OF_LAST_P2P_MESSAGE.lock().await);
          tokio::select! {
            biased;

            // Handle any queued outbound messages
            msg = broadcast_recv.recv() => {
              broadcast_raw(
                &mut swarm,
                msg.expect("broadcast_recv closed. are we shutting down?")
              ).await;
            }

            // Handle new incoming messages
            event = swarm.next() => {
              match event {
                //#[cfg(debug_assertions)]
                Some(SwarmEvent::Behaviour(BehaviorEvent::Mdns(
                  libp2p::mdns::Event::Discovered(list),
                ))) => {
                  for (peer, mut addr) in list {
                    // Check the port is as expected to prevent trying to peer with Substrate nodes
                    if addr.pop() == Some(libp2p::multiaddr::Protocol::Tcp(PORT)) {
                      log::info!("found peer via mdns");
                      swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer);
                    }
                  }
                }
                //#[cfg(debug_assertions)]
                Some(SwarmEvent::Behaviour(BehaviorEvent::Mdns(
                  libp2p::mdns::Event::Expired(list),
                ))) => {
                  for (peer, _) in list {
                    log::info!("disconnecting peer due to mdns");
                    swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer);
                  }
                }

                Some(SwarmEvent::Behaviour(BehaviorEvent::Gossipsub(
                  GsEvent::Message { propagation_source, message, .. },
                ))) => {
                  receive_send
                    .send((propagation_source, message.data))
                    .expect("receive_send closed. are we shutting down?");
                }
                _ => {}
              }
            }

            // If it's been >80s since we've published a message, publish a KeepAlive since we're
            // still an active service
            // This is useful when we have no active tributaries and accordingly aren't sending
            // heartbeats
            // If we are sending heartbeats, we should've sent one after 60s of no finalized blocks
            // (where a finalized block only occurs due to network activity), meaning this won't be
            // run
            _ = tokio::time::sleep(Duration::from_secs(80).saturating_sub(time_since_last)) => {
              broadcast_raw(&mut swarm, P2pMessageKind::KeepAlive.serialize()).await;
            }
          }
        }
      }
    });

    LibP2p(Arc::new(Mutex::new(broadcast_send)), Arc::new(Mutex::new(receive_recv)))
  }
}

#[async_trait]
impl P2p for LibP2p {
  type Id = PeerId;

  async fn send_raw(&self, _: Self::Id, msg: Vec<u8>) {
    self.broadcast_raw(msg).await;
  }

  async fn broadcast_raw(&self, msg: Vec<u8>) {
    self.0.lock().await.send(msg).expect("broadcast_send closed. are we shutting down?");
  }

  // TODO: We only have a single handle call this. Differentiate Send/Recv to remove this constant
  // lock acquisition?
  async fn receive_raw(&self) -> (Self::Id, Vec<u8>) {
    self.1.lock().await.recv().await.expect("receive_recv closed. are we shutting down?")
  }
}

#[async_trait]
impl TributaryP2p for LibP2p {
  async fn broadcast(&self, genesis: [u8; 32], msg: Vec<u8>) {
    <Self as P2p>::broadcast(self, P2pMessageKind::Tributary(genesis), msg).await
  }
}
