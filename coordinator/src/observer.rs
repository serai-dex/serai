use log::info;
use std::{env, str, fmt};

use subxt::{
    ext::sp_runtime::{ generic::Header, traits::BlakeTwo256 },
    rpc::Subscription,
    OnlineClient,
    PolkadotConfig,
};

use rdkafka::{
    producer::{ BaseRecord, ThreadedProducer },
    consumer::{ BaseConsumer, Consumer },
    ClientConfig,
    Message,
};

use crate::{ core::ObserverConfig, core::KafkaConfig };

#[derive(Debug, PartialEq, Eq, Hash)]
enum ObserverMessage {
    BlockUpdate { block_hash: String, 
                  block_number: u32, 
                  parent_hash: String, 
                  state_root: String, 
                  extrinsics_root: String
                }
}

impl fmt::Display for ObserverMessage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ObserverMessage::BlockUpdate { block_hash, block_number, parent_hash, state_root, extrinsics_root } => write!(f, "BlockUpdate {{ block_hash: {}, block_number: {}, parent_hash: {}, state_root: {}, extrinsics_root: {} }}", block_hash, block_number, parent_hash, state_root, extrinsics_root),
            ObserverMessage::Default => write!(f, "Default"),
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

        // For non-finalised blocks use `.subscribe_blocks()`
        let mut blocks: Subscription<Header<u32, BlakeTwo256>> = api
            .rpc()
            .subscribe_finalized_block_headers().await?;

        let kafka_config = self.kafka_config.clone();
        let producer: ThreadedProducer<_> = ClientConfig::new()
            .set("bootstrap.servers", format!("{}:{}", kafka_config.host, kafka_config.port))
            .create()
            .expect("invalid producer config");

        while let Some(Ok(block)) = blocks.next().await {
            
            let block = ObserverMessage::BlockUpdate({block_number: block.number, block_hash: block.hash(), parent_hash: block.parent_hash, state_root: block.state_root, extrinsics_root: block.extrinsics_root});
            info!("Block update: {:?}", block);
            let mut topic = "".to_string();
            topic.push_str(&self.name);
            topic.push_str("_");
            topic.push_str("node");

            producer
            .send(
              BaseRecord::to(&topic)
                .key(&format!("{}", block.hash()))
                .payload(&block)
                .partition(0),
            )
            .expect("failed to send message");
        }

        Ok(())
    }
}