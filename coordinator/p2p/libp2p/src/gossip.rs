use core::time::Duration;

use blake2::{Digest as _, Blake2s256};

use borsh::{BorshSerialize, BorshDeserialize};

use libp2p::gossipsub::{
  IdentTopic, MessageId, MessageAuthenticity, ValidationMode, ConfigBuilder, IdentityTransform,
  AllowAllSubscriptionFilter, Behaviour,
};
pub use libp2p::gossipsub::Event;

use serai_cosign::SignedCosign;

// Block size limit + 16 KB of space for signatures/metadata
pub(crate) const MAX_LIBP2P_GOSSIP_MESSAGE_SIZE: usize = tributary_sdk::BLOCK_SIZE_LIMIT + 16384;

const LIBP2P_PROTOCOL: &str = "/serai/coordinator/gossip/1.0.0";
const BASE_TOPIC: &str = "/";

fn topic_for_tributary(tributary: [u8; 32]) -> IdentTopic {
  IdentTopic::new(format!("/tributary/{}", hex::encode(tributary)))
}

#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub(crate) enum Message {
  Tributary { tributary: [u8; 32], message: Vec<u8> },
  Cosign(SignedCosign),
}

impl Message {
  pub(crate) fn topic(&self) -> IdentTopic {
    match self {
      Message::Tributary { tributary, .. } => topic_for_tributary(*tributary),
      Message::Cosign(_) => IdentTopic::new(BASE_TOPIC),
    }
  }
}

pub(crate) type Behavior = Behaviour<IdentityTransform, AllowAllSubscriptionFilter>;

pub(crate) fn new_behavior() -> Behavior {
  // The latency used by the Tendermint protocol, used here as the gossip epoch duration
  // libp2p-rs defaults to 1 second, whereas ours will be ~2
  const HEARTBEAT_INTERVAL: Duration = tributary_sdk::tendermint::LATENCY_TIME;
  // The amount of heartbeats which will occur within a single Tributary block
  #[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
  const HEARTBEATS_PER_BLOCK: u32 = tributary_sdk::tendermint::TARGET_BLOCK_TIME
    .as_millis()
    .div_ceil(HEARTBEAT_INTERVAL.as_millis()) as u32;
  // libp2p-rs defaults to 5, whereas ours will be ~8
  const HEARTBEATS_TO_KEEP_U32: u32 = 2 * HEARTBEATS_PER_BLOCK;
  #[expect(clippy::as_conversions)]
  const HEARTBEATS_TO_KEEP: usize = HEARTBEATS_TO_KEEP_U32 as usize;
  // libp2p-rs defaults to 3 whereas ours will be ~4
  #[expect(clippy::as_conversions)]
  const HEARTBEATS_TO_GOSSIP: usize = HEARTBEATS_PER_BLOCK as usize;
  // Track duplicates in the cache for the lifetime of the heartbeats
  const DUPLICATE_CACHE_TIME: Duration =
    HEARTBEAT_INTERVAL.checked_mul(HEARTBEATS_TO_KEEP_U32).unwrap();

  let config = ConfigBuilder::default()
    .protocol_id_prefix(LIBP2P_PROTOCOL)
    .history_length(HEARTBEATS_TO_KEEP)
    .history_gossip(HEARTBEATS_TO_GOSSIP)
    .heartbeat_interval(HEARTBEAT_INTERVAL)
    .max_transmit_size(MAX_LIBP2P_GOSSIP_MESSAGE_SIZE)
    .duplicate_cache_time(DUPLICATE_CACHE_TIME)
    .validation_mode(ValidationMode::Anonymous)
    // Uses a content based message ID to avoid duplicates as much as possible
    .message_id_fn(|msg| {
      MessageId::new(&Blake2s256::digest([msg.topic.as_str().as_bytes(), &msg.data].concat()))
    })
    .build();

  let mut gossip = Behavior::new(MessageAuthenticity::Anonymous, config.unwrap()).unwrap();

  // Subscribe to the base topic
  let topic = IdentTopic::new(BASE_TOPIC);
  let _ = gossip.subscribe(&topic);

  gossip
}
