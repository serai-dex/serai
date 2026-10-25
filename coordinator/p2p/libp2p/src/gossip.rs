use core::time::Duration;

use blake2::{Digest as _, Blake2b256};

use borsh::{BorshSerialize, BorshDeserialize};

use tributary_sdk::{ReadWriteAsBorsh, Transaction};

use libp2p::gossipsub::{
  IdentTopic, MessageId, MessageAuthenticity, ValidationMode, ConfigBuilder, IdentityTransform,
  AllowAllSubscriptionFilter, Behaviour,
};
pub use libp2p::gossipsub::Event;

use serai_cosign::SignedCosign;

const LIBP2P_PROTOCOL: &str = "/serai/coordinator/gossip/1.0.0";
const BASE_TOPIC: &str = "/";

fn topic_for_tributary(tributary: [u8; 32]) -> IdentTopic {
  IdentTopic::new(format!("/tributary/{}", hex::encode(tributary)))
}

#[expect(clippy::enum_variant_names)]
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub(crate) enum Message<Tx: 'static + Send + Sync + Transaction> {
  TributaryMessage {
    tributary: [u8; 32],
    #[borsh(bound(serialize = "", deserialize = ""))]
    message: tributary_sdk::Message<Tx>,
  },
  TributaryTransaction {
    tributary: [u8; 32],
    #[borsh(bound(serialize = "", deserialize = ""))]
    transaction: ReadWriteAsBorsh<Tx>,
  },
  Cosign(SignedCosign),
}

impl<Tx: 'static + Send + Sync + Transaction> Message<Tx> {
  pub(crate) fn topic(&self) -> IdentTopic {
    match self {
      Message::TributaryMessage { tributary, .. } |
      Message::TributaryTransaction { tributary, .. } => topic_for_tributary(*tributary),
      Message::Cosign(_) => IdentTopic::new(BASE_TOPIC),
    }
  }
}

pub(crate) type Behavior = Behaviour<IdentityTransform, AllowAllSubscriptionFilter>;

pub(crate) fn new_behavior<Tx: Transaction>() -> Behavior {
  const HEARTBEAT_INTERVAL: Duration = super::LATENCY_TIME.checked_div(2).unwrap();
  const DUPLICATE_CACHE_TIME: Duration = super::LATENCY_TIME.checked_mul(8).unwrap();

  let config = ConfigBuilder::default()
    .protocol_id_prefix(LIBP2P_PROTOCOL)
    .heartbeat_interval(HEARTBEAT_INTERVAL)
    // Block size limit + 16 KB of space for signatures/metadata
    .max_transmit_size(Tx::BLOCK_SIZE_LIMIT.unwrap_or(1_024 * 1_024).saturating_add(16 * 1_024))
    .duplicate_cache_time(DUPLICATE_CACHE_TIME)
    .validation_mode(ValidationMode::Anonymous)
    // Uses a content based message ID to avoid duplicates as much as possible
    .message_id_fn(|msg| {
      MessageId::new(&Blake2b256::digest([msg.topic.as_str().as_bytes(), &msg.data].concat()))
    })
    .build();

  let mut gossip = Behavior::new(MessageAuthenticity::Anonymous, config.unwrap()).unwrap();

  // Subscribe to the base topic
  let topic = IdentTopic::new(BASE_TOPIC);
  let _ = gossip.subscribe(&topic);

  gossip
}
