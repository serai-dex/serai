use core::{time::Duration, fmt, task::Poll};
use std::{sync::Arc, collections::VecDeque, io::Read};

use async_trait::async_trait;

use tokio::{sync::Mutex, time::sleep};

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
  Tributary([u8; 32]),
  Heartbeat([u8; 32]),
  Block([u8; 32]),
}

impl P2pMessageKind {
  fn serialize(&self) -> Vec<u8> {
    match self {
      P2pMessageKind::Tributary(genesis) => {
        let mut res = vec![0];
        res.extend(genesis);
        res
      }
      P2pMessageKind::Heartbeat(genesis) => {
        let mut res = vec![1];
        res.extend(genesis);
        res
      }
      P2pMessageKind::Block(genesis) => {
        let mut res = vec![2];
        res.extend(genesis);
        res
      }
    }
  }

  fn read<R: Read>(reader: &mut R) -> Option<P2pMessageKind> {
    let mut kind = [0; 1];
    reader.read_exact(&mut kind).ok()?;
    match kind[0] {
      0 => Some({
        let mut genesis = [0; 32];
        reader.read_exact(&mut genesis).ok()?;
        P2pMessageKind::Tributary(genesis)
      }),
      1 => Some({
        let mut genesis = [0; 32];
        reader.read_exact(&mut genesis).ok()?;
        P2pMessageKind::Heartbeat(genesis)
      }),
      2 => Some({
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

#[allow(clippy::type_complexity)]
#[derive(Clone)]
pub struct LibP2p(Arc<Mutex<Swarm<Behavior>>>, Arc<Mutex<VecDeque<(PeerId, Vec<u8>)>>>);
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
    let transport = libp2p_tokio::Transport::new(Config::default())
      .upgrade(upgrade::Version::V1)
      .authenticate(noise::Config::new(&throwaway_key_pair).unwrap())
      .multiplex(yamux::Config::default())
      .boxed();

    let behavior = Behavior {
      gossipsub: {
        // Block size limit + 1 KB of space for signatures/metadata
        const MAX_LIBP2P_MESSAGE_SIZE: usize = tributary::BLOCK_SIZE_LIMIT + 1024;

        use blake2::{Digest, Blake2s256};
        let config = ConfigBuilder::default()
          .max_transmit_size(MAX_LIBP2P_MESSAGE_SIZE)
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
        log::info!("spawning mdns");
        libp2p::mdns::tokio::Behaviour::new(libp2p::mdns::Config::default(), throwaway_peer_id)
          .unwrap()
      },
    };

    let mut swarm =
      SwarmBuilder::with_tokio_executor(transport, behavior, throwaway_peer_id).build();
    const PORT: u16 = 30563; // 5132 ^ (('c' << 8) | 'o')
    swarm.listen_on(format!("/ip4/0.0.0.0/tcp/{PORT}").parse().unwrap()).unwrap();

    let res = LibP2p(Arc::new(Mutex::new(swarm)), Arc::new(Mutex::new(VecDeque::new())));
    tokio::spawn({
      let p2p = res.clone();
      async move {
        // Run this task ad-infinitum
        loop {
          // Maintain this lock until it's out of events
          let mut p2p_lock = p2p.0.lock().await;
          loop {
            match futures::poll!(p2p_lock.next()) {
              //#[cfg(debug_assertions)]
              Poll::Ready(Some(SwarmEvent::Behaviour(BehaviorEvent::Mdns(
                libp2p::mdns::Event::Discovered(list),
              )))) => {
                for (peer, mut addr) in list {
                  if addr.pop() == Some(libp2p::multiaddr::Protocol::Tcp(PORT)) {
                    log::info!("found peer via mdns");
                    p2p_lock.behaviour_mut().gossipsub.add_explicit_peer(&peer);
                  }
                }
              }
              //#[cfg(debug_assertions)]
              Poll::Ready(Some(SwarmEvent::Behaviour(BehaviorEvent::Mdns(
                libp2p::mdns::Event::Expired(list),
              )))) => {
                for (peer, _) in list {
                  log::info!("disconnecting peer due to mdns");
                  p2p_lock.behaviour_mut().gossipsub.remove_explicit_peer(&peer);
                }
              }

              Poll::Ready(Some(SwarmEvent::Behaviour(BehaviorEvent::Gossipsub(
                GsEvent::Message { propagation_source, message, .. },
              )))) => {
                p2p.1.lock().await.push_back((propagation_source, message.data));
              }
              Poll::Ready(Some(_)) => {}
              _ => {
                drop(p2p_lock);
                sleep(Duration::from_millis(100)).await;
                break;
              }
            }
          }
        }
      }
    });
    res
  }
}

#[async_trait]
impl P2p for LibP2p {
  type Id = PeerId;

  async fn send_raw(&self, _: Self::Id, msg: Vec<u8>) {
    self.broadcast_raw(msg).await;
  }

  async fn broadcast_raw(&self, msg: Vec<u8>) {
    match self
      .0
      .lock()
      .await
      .behaviour_mut()
      .gossipsub
      .publish(IdentTopic::new(LIBP2P_TOPIC), msg.clone())
    {
      Err(PublishError::SigningError(e)) => panic!("signing error when broadcasting: {e}"),
      Err(PublishError::InsufficientPeers) => {
        log::warn!("failed to send p2p message due to insufficient peers")
      }
      Err(PublishError::MessageTooLarge) => {
        panic!("tried to send a too large message: {}", hex::encode(msg))
      }
      Err(PublishError::TransformFailed(e)) => panic!("IdentityTransform failed: {e}"),
      Err(PublishError::Duplicate) | Ok(_) => {}
    };
  }

  async fn receive_raw(&self) -> (Self::Id, Vec<u8>) {
    loop {
      if let Some(res) = self.1.lock().await.pop_front() {
        return res;
      }
      sleep(Duration::from_millis(100)).await;
    }
  }
}

#[async_trait]
impl TributaryP2p for LibP2p {
  async fn broadcast(&self, genesis: [u8; 32], msg: Vec<u8>) {
    <Self as P2p>::broadcast(self, P2pMessageKind::Tributary(genesis), msg).await
  }
}
