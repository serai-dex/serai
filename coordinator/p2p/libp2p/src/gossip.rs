use core::time::Duration;

use blake2::{Digest, Blake2s256};

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
  let heartbeat_interval = tributary_sdk::tendermint::LATENCY_TIME;
  // The amount of heartbeats which will occur within a single Tributary block
  let heartbeats_per_block =
    tributary_sdk::tendermint::TARGET_BLOCK_TIME.div_ceil(heartbeat_interval);
  // libp2p-rs defaults to 5, whereas ours will be ~8
  let heartbeats_to_keep = 2 * heartbeats_per_block;
  // libp2p-rs defaults to 3 whereas ours will be ~4
  let heartbeats_to_gossip = heartbeats_per_block;

  let config = ConfigBuilder::default()
    .protocol_id_prefix(LIBP2P_PROTOCOL)
    .history_length(usize::try_from(heartbeats_to_keep).unwrap())
    .history_gossip(usize::try_from(heartbeats_to_gossip).unwrap())
    .heartbeat_interval(Duration::from_millis(heartbeat_interval.into()))
    .max_transmit_size(MAX_LIBP2P_GOSSIP_MESSAGE_SIZE)
    .duplicate_cache_time(Duration::from_millis((heartbeats_to_keep * heartbeat_interval).into()))
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
