use log::info;
use std::{env, str, fmt};

use subxt::{
  ext::sp_runtime::{generic::Header, traits::BlakeTwo256},
  rpc::Subscription,
  OnlineClient, PolkadotConfig,
};

use rdkafka::{
  producer::{BaseRecord, ThreadedProducer},
  consumer::{BaseConsumer, Consumer},
  ClientConfig, Message,
};

use crate::{core::ObserverConfig, core::KafkaConfig};

#[derive(serde::Serialize, serde::Deserialize)]
enum ObserverMessage {
  BlockUpdate {
    block_hash: String,
    block_number: u32,
    parent_hash: String,
    state_root: String,
    extrinsics_root: String,
  },
}

impl fmt::Display for ObserverMessage {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match &*self {
            ObserverMessage::BlockUpdate { block_hash, block_number, parent_hash, state_root, extrinsics_root }
            => write!(f,
              "BlockUpdate {{
              block_hash: {},
              block_number: {},
              parent_hash: {},
              state_root: {},
              extrinsics_root: {} }}",
            block_hash, block_number, parent_hash, state_root, extrinsics_root),
        }
  }
}

pub struct ObserverProcess {
  observer_config: ObserverConfig,
  kafka_config: KafkaConfig,
  observer_url: String,
  name: String,
}

impl ObserverProcess {
  pub fn new(observer_config: ObserverConfig, kafka_config: KafkaConfig, name: String) -> Self {
    let mut hostname = "".to_string();
    hostname.push_str(&observer_config.host_prefix);
    hostname.push_str(&name);
    hostname.push_str(":");
    hostname.push_str(&observer_config.port);
    Self {
      observer_config: observer_config,
      kafka_config: kafka_config,
      observer_url: hostname,
      name: name,
    }
  }

  // write a second version of the run function that deposits blockdata to kafka
  pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
    info!("Observer process started");
    // get host and port from config and assemble url
    let api = OnlineClient::<PolkadotConfig>::from_url(&self.observer_url).await?;

    let mut blocks: Subscription<Header<u32, BlakeTwo256>> =
      api.rpc().subscribe_finalized_block_headers().await?;

    let kafka_config = self.kafka_config.clone();
    let producer: ThreadedProducer<_> = ClientConfig::new()
      .set("bootstrap.servers", format!("{}:{}", kafka_config.host, kafka_config.port))
      .create()
      .expect("invalid producer config");

    while let Some(Ok(block)) = blocks.next().await {
      info!("Block: {:?}", block);
      let mut topic = "".to_string();
      topic.push_str(&self.name);
      topic.push_str("_");
      topic.push_str("node");

      // extract block data to kafka
      let block_hash = block.hash().to_string();
      let block_number = block.number;
      let parent_hash = block.parent_hash.to_string();
      let state_root = block.state_root.to_string();
      let extrinsics_root = block.extrinsics_root.to_string();
      let message = ObserverMessage::BlockUpdate {
        block_hash: block_hash.to_string(),
        block_number,
        parent_hash,
        state_root,
        extrinsics_root,
      };
      let payload = serde_json::to_string(&message).unwrap();
      let record = BaseRecord::to(&topic).key(&block_hash).payload(&payload);
      producer.send(record).unwrap();
    }

    Ok(())
  }
}
