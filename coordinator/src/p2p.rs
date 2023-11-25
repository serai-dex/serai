use core::{time::Duration, fmt};
use std::{
  sync::Arc,
  io::Read,
  collections::HashMap,
  time::{SystemTime, Instant},
};

use async_trait::async_trait;

use scale::{Encode, Decode};
use serai_client::primitives::NetworkId;

use serai_db::Db;

use tokio::{
  sync::{Mutex, RwLock, mpsc, broadcast},
  time::sleep,
};

use libp2p::{
  futures::StreamExt,
  identity::Keypair,
  PeerId,
  gossipsub::{
    IdentTopic, FastMessageId, MessageId, MessageAuthenticity, ValidationMode, ConfigBuilder,
    IdentityTransform, AllowAllSubscriptionFilter, Event as GsEvent, PublishError,
    Behaviour as GsBehavior,
  },
  swarm::{NetworkBehaviour, SwarmEvent, Swarm},
  SwarmBuilder,
};

pub(crate) use tributary::{ReadWrite, P2p as TributaryP2p};

use crate::{Transaction, Block, Tributary, ActiveTributary, TributaryEvent};

const LIBP2P_TOPIC: &str = "serai-coordinator";

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Encode, Decode)]
pub struct CosignedBlock {
  pub network: NetworkId,
  pub block_number: u64,
  pub block: [u8; 32],
  pub signature: [u8; 64],
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum P2pMessageKind {
  KeepAlive,
  Tributary([u8; 32]),
  Heartbeat([u8; 32]),
  Block([u8; 32]),
  CosignedBlock,
}

impl P2pMessageKind {
  fn genesis(&self) -> Option<[u8; 32]> {
    match self {
      P2pMessageKind::KeepAlive => None,
      P2pMessageKind::Tributary(genesis) => Some(*genesis),
      P2pMessageKind::Heartbeat(genesis) => Some(*genesis),
      P2pMessageKind::Block(genesis) => Some(*genesis),
      P2pMessageKind::CosignedBlock => None,
    }
  }

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
      P2pMessageKind::CosignedBlock => {
        vec![4]
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
      4 => Some(P2pMessageKind::CosignedBlock),
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

  async fn subscribe(&self, genesis: [u8; 32]);
  async fn unsubscribe(&self, genesis: [u8; 32]);

  async fn send_raw(&self, to: Self::Id, genesis: Option<[u8; 32]>, msg: Vec<u8>);
  async fn broadcast_raw(&self, genesis: Option<[u8; 32]>, msg: Vec<u8>);
  async fn receive_raw(&self) -> (Self::Id, Vec<u8>);

  async fn send(&self, to: Self::Id, kind: P2pMessageKind, msg: Vec<u8>) {
    let mut actual_msg = kind.serialize();
    actual_msg.extend(msg);
    self.send_raw(to, kind.genesis(), actual_msg).await;
  }
  async fn broadcast(&self, kind: P2pMessageKind, msg: Vec<u8>) {
    let mut actual_msg = kind.serialize();
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
    self.broadcast_raw(kind.genesis(), actual_msg).await;
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
    /*
    log::trace!(
      "received p2p message (kind {})",
      match kind {
        P2pMessageKind::KeepAlive => "KeepAlive".to_string(),
        P2pMessageKind::Tributary(genesis) => format!("Tributary({})", hex::encode(genesis)),
        P2pMessageKind::Heartbeat(genesis) => format!("Heartbeat({})", hex::encode(genesis)),
        P2pMessageKind::Block(genesis) => format!("Block({})", hex::encode(genesis)),
        P2pMessageKind::CosignedBlock => "CosignedBlock".to_string(),
      }
    );
    */
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
pub struct LibP2p {
  subscribe: Arc<Mutex<mpsc::UnboundedSender<(bool, [u8; 32])>>>,
  broadcast: Arc<Mutex<mpsc::UnboundedSender<(Option<[u8; 32]>, Vec<u8>)>>>,
  receive: Arc<Mutex<mpsc::UnboundedReceiver<(PeerId, Vec<u8>)>>>,
}
impl fmt::Debug for LibP2p {
  fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
    fmt.debug_struct("LibP2p").finish_non_exhaustive()
  }
}

impl LibP2p {
  #[allow(clippy::new_without_default)]
  pub fn new() -> Self {
    // Block size limit + 1 KB of space for signatures/metadata
    const MAX_LIBP2P_MESSAGE_SIZE: usize = tributary::BLOCK_SIZE_LIMIT + 1024;

    log::info!("creating a libp2p instance");

    let throwaway_key_pair = Keypair::generate_ed25519();
    let throwaway_peer_id = PeerId::from(throwaway_key_pair.public());

    let behavior = Behavior {
      gossipsub: {
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
          MessageAuthenticity::Signed(throwaway_key_pair.clone()),
          config.unwrap(),
        )
        .unwrap();

        // Subscribe to the base topic
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

    // Uses noise for authentication, yamux for multiplexing
    // TODO: Do we want to add a custom authentication protocol to only accept connections from
    // fellow validators? Doing so would reduce the potential for spam
    // TODO: Relay client?
    let mut swarm = SwarmBuilder::with_existing_identity(throwaway_key_pair)
      .with_tokio()
      .with_quic()
      .with_behaviour(|_| behavior)
      .unwrap()
      .build();
    const PORT: u16 = 30563; // 5132 ^ (('c' << 8) | 'o')
    swarm.listen_on(format!("/ip4/0.0.0.0/udp/{PORT}").parse().unwrap()).unwrap();

    let (broadcast_send, mut broadcast_recv) = mpsc::unbounded_channel();
    let (receive_send, receive_recv) = mpsc::unbounded_channel();
    let (subscribe_send, mut subscribe_recv) = mpsc::unbounded_channel();

    fn topic_for_genesis(genesis: [u8; 32]) -> IdentTopic {
      IdentTopic::new(format!("{LIBP2P_TOPIC}-{}", hex::encode(genesis)))
    }

    tokio::spawn({
      let mut time_of_last_p2p_message = Instant::now();

      #[allow(clippy::needless_pass_by_ref_mut)] // False positive
      async fn broadcast_raw(
        p2p: &mut Swarm<Behavior>,
        time_of_last_p2p_message: &mut Instant,
        genesis: Option<[u8; 32]>,
        msg: Vec<u8>,
      ) {
        // Update the time of last message
        *time_of_last_p2p_message = Instant::now();

        let topic = if let Some(genesis) = genesis {
          topic_for_genesis(genesis)
        } else {
          IdentTopic::new(LIBP2P_TOPIC)
        };

        match p2p.behaviour_mut().gossipsub.publish(topic, msg.clone()) {
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
          let time_since_last = Instant::now().duration_since(time_of_last_p2p_message);
          tokio::select! {
            biased;

            // Subscribe to any new topics
            topic = subscribe_recv.recv() => {
              let (subscribe, topic) = topic.expect("subscribe_recv closed. are we shutting down?");
              if subscribe {
                swarm
                  .behaviour_mut()
                  .gossipsub
                  .subscribe(&topic_for_genesis(topic))
                  .unwrap();
              } else {
                swarm
                  .behaviour_mut()
                  .gossipsub
                  .unsubscribe(&topic_for_genesis(topic))
                  .unwrap();
              }
            }

            // Handle any queued outbound messages
            msg = broadcast_recv.recv() => {
              let (genesis, msg) = msg.expect("broadcast_recv closed. are we shutting down?");
              broadcast_raw(
                &mut swarm,
                &mut time_of_last_p2p_message,
                genesis,
                msg,
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
                    if addr.pop() == Some(libp2p::multiaddr::Protocol::Udp(PORT)) {
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
              broadcast_raw(
                &mut swarm,
                &mut time_of_last_p2p_message,
                None,
                P2pMessageKind::KeepAlive.serialize()
              ).await;
            }
          }
        }
      }
    });

    LibP2p {
      subscribe: Arc::new(Mutex::new(subscribe_send)),
      broadcast: Arc::new(Mutex::new(broadcast_send)),
      receive: Arc::new(Mutex::new(receive_recv)),
    }
  }
}

#[async_trait]
impl P2p for LibP2p {
  type Id = PeerId;

  async fn subscribe(&self, genesis: [u8; 32]) {
    self
      .subscribe
      .lock()
      .await
      .send((true, genesis))
      .expect("subscribe_send closed. are we shutting down?");
  }

  async fn unsubscribe(&self, genesis: [u8; 32]) {
    self
      .subscribe
      .lock()
      .await
      .send((false, genesis))
      .expect("subscribe_send closed. are we shutting down?");
  }

  async fn send_raw(&self, _: Self::Id, genesis: Option<[u8; 32]>, msg: Vec<u8>) {
    self.broadcast_raw(genesis, msg).await;
  }

  async fn broadcast_raw(&self, genesis: Option<[u8; 32]>, msg: Vec<u8>) {
    self
      .broadcast
      .lock()
      .await
      .send((genesis, msg))
      .expect("broadcast_send closed. are we shutting down?");
  }

  // TODO: We only have a single handle call this. Differentiate Send/Recv to remove this constant
  // lock acquisition?
  async fn receive_raw(&self) -> (Self::Id, Vec<u8>) {
    self.receive.lock().await.recv().await.expect("receive_recv closed. are we shutting down?")
  }
}

#[async_trait]
impl TributaryP2p for LibP2p {
  async fn broadcast(&self, genesis: [u8; 32], msg: Vec<u8>) {
    <Self as P2p>::broadcast(self, P2pMessageKind::Tributary(genesis), msg).await
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
        // Also include the timestamp so LibP2p doesn't flag this as an old message re-circulating
        let timestamp = SystemTime::now()
          .duration_since(SystemTime::UNIX_EPOCH)
          .expect("system clock is wrong")
          .as_secs();
        // Divide by the block time so if multiple parties send a Heartbeat, they're more likely to
        // overlap
        let time_unit = timestamp / u64::from(Tributary::<D, Transaction, P>::block_time());
        msg.extend(time_unit.to_le_bytes());
        P2p::broadcast(&p2p, P2pMessageKind::Heartbeat(tributary.genesis()), msg).await;
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
            p2p.subscribe(genesis).await;

            // Per-Tributary P2P message handler
            tokio::spawn({
              let p2p = p2p.clone();
              async move {
                loop {
                  let Some(mut msg) = recv.recv().await else {
                    // Channel closure happens when the tributary retires
                    break;
                  };
                  match msg.kind {
                    P2pMessageKind::KeepAlive => {}

                    P2pMessageKind::Tributary(msg_genesis) => {
                      assert_eq!(msg_genesis, genesis);
                      log::trace!("handling message for tributary {:?}", tributary.spec.set());
                      if tributary.tributary.handle_message(&msg.msg).await {
                        P2p::broadcast(&p2p, msg.kind, msg.msg).await;
                      }
                    }

                    // TODO2: Rate limit this per timestamp
                    // And/or slash on Heartbeat which justifies a response, since the node
                    // obviously was offline and we must now use our bandwidth to compensate for
                    // them?
                    P2pMessageKind::Heartbeat(msg_genesis) => {
                      assert_eq!(msg_genesis, genesis);
                      if msg.msg.len() != 40 {
                        log::error!("validator sent invalid heartbeat");
                        continue;
                      }

                      let p2p = p2p.clone();
                      let spec = tributary.spec.clone();
                      let reader = tributary.tributary.reader();
                      // Spawn a dedicated task as this may require loading large amounts of data
                      // from disk and take a notable amount of time
                      tokio::spawn(async move {
                        /*
                        // Have sqrt(n) nodes reply with the blocks
                        let mut responders = (tributary.spec.n() as f32).sqrt().floor() as u64;
                        // Try to have at least 3 responders
                        if responders < 3 {
                          responders = tributary.spec.n().min(3).into();
                        }
                        */

                        /*
                        // Have up to three nodes respond
                        let responders = u64::from(spec.n().min(3));

                        // Decide which nodes will respond by using the latest block's hash as a
                        // mutually agreed upon entropy source
                        // This isn't a secure source of entropy, yet it's fine for this
                        let entropy = u64::from_le_bytes(reader.tip()[.. 8].try_into().unwrap());
                        // If n = 10, responders = 3, we want `start` to be 0 ..= 7
                        // (so the highest is 7, 8, 9)
                        // entropy % (10 + 1) - 3 = entropy % 8 = 0 ..= 7
                        let start =
                          usize::try_from(entropy % (u64::from(spec.n() + 1) - responders))
                            .unwrap();
                        let mut selected = false;
                        for validator in &spec.validators()
                          [start .. (start + usize::try_from(responders).unwrap())]
                        {
                          if our_key == validator.0 {
                            selected = true;
                            break;
                          }
                        }
                        if !selected {
                          log::debug!("received heartbeat and not selected to respond");
                          return;
                        }

                        log::debug!("received heartbeat and selected to respond");
                        */

                        // Have every node respond
                        // While we could only have a subset respond, LibP2P will sync all messages
                        // it isn't aware of
                        // It's cheaper to be aware from our disk than from over the network
                        // TODO: Spawn a dedicated topic for this heartbeat response?
                        let mut latest = msg.msg[.. 32].try_into().unwrap();
                        while let Some(next) = reader.block_after(&latest) {
                          let mut res = reader.block(&next).unwrap().serialize();
                          res.extend(reader.commit(&next).unwrap());
                          // Also include the timestamp used within the Heartbeat
                          res.extend(&msg.msg[32 .. 40]);
                          p2p.send(msg.sender, P2pMessageKind::Block(spec.genesis()), res).await;
                          latest = next;
                        }
                      });
                    }

                    P2pMessageKind::Block(msg_genesis) => {
                      assert_eq!(msg_genesis, genesis);
                      let mut msg_ref: &[u8] = msg.msg.as_ref();
                      let Ok(block) = Block::<Transaction>::read(&mut msg_ref) else {
                        log::error!("received block message with an invalidly serialized block");
                        continue;
                      };
                      // Get just the commit
                      msg.msg.drain(.. (msg.msg.len() - msg_ref.len()));
                      msg.msg.drain((msg.msg.len() - 8) ..);

                      let res = tributary.tributary.sync_block(block, msg.msg).await;
                      log::debug!(
                        "received block from {:?}, sync_block returned {}",
                        msg.sender,
                        res
                      );
                    }

                    P2pMessageKind::CosignedBlock => unreachable!(),
                  }
                }
              }
            });
          }
          TributaryEvent::TributaryRetired(set) => {
            if let Some(genesis) = set_to_genesis.remove(&set) {
              channels.write().await.remove(&genesis);
              p2p.unsubscribe(genesis).await;
            }
          }
        }
      }
    }
  });

  loop {
    let msg = p2p.receive().await;
    match msg.kind {
      P2pMessageKind::KeepAlive => {}
      P2pMessageKind::Tributary(genesis) => {
        if let Some(channel) = channels.read().await.get(&genesis) {
          channel.send(msg).unwrap();
        }
      }
      P2pMessageKind::Heartbeat(genesis) => {
        if let Some(channel) = channels.read().await.get(&genesis) {
          channel.send(msg).unwrap();
        }
      }
      P2pMessageKind::Block(genesis) => {
        if let Some(channel) = channels.read().await.get(&genesis) {
          channel.send(msg).unwrap();
        }
      }
      P2pMessageKind::CosignedBlock => {
        let mut msg_ref: &[u8] = msg.msg.as_ref();
        let Ok(msg) = CosignedBlock::decode(&mut scale::IoReader(&mut msg_ref)) else {
          log::error!("received CosignedBlock message with invalidly serialized contents");
          continue;
        };
        cosign_channel.send(msg).unwrap();
      }
    }
  }
}
