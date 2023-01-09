use log::info;

use subxt::{
    ext::sp_runtime::{ generic::Header, traits::BlakeTwo256 },
    rpc::Subscription,
    OnlineClient,
    PolkadotConfig,
};

use crate::{ core::ObserverConfig, core::KafkaConfig };

pub struct ObserverProcess {
    observer_config: ObserverConfig,
}

impl ObserverProcess {
    pub fn new(config: ObserverConfig) -> Self {
        Self { observer_config: config }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Observer process started");

        let api = OnlineClient::<PolkadotConfig>::from_url("ws://node-base:9944").await?;

        // For non-finalised blocks use `.subscribe_blocks()`
        let mut blocks: Subscription<Header<u32, BlakeTwo256>> = api
            .rpc()
            .subscribe_finalized_block_headers().await?;

        while let Some(Ok(block)) = blocks.next().await {
            println!(
                "block number: {} hash:{} parent:{} state root:{} extrinsics root:{}",
                block.number,
                block.hash(),
                block.parent_hash,
                block.state_root,
                block.extrinsics_root
            );
        }

        Ok(())
    }

        // // write a second version of the run function that deposits blockdata to kafka
        // pub async fn run(&self) -> Result<(), Box<dyn std::error::Error>> {
        //     // info!("Observer process started");
    
        //     // let api = OnlineClient::<PolkadotConfig>::from_url("ws://node-base:9944").await?;
    
        //     // // For non-finalised blocks use `.subscribe_blocks()`
        //     // let mut blocks: Subscription<Header<u32, BlakeTwo256>> = api
        //     //     .rpc()
        //     //     .subscribe_finalized_block_headers().await?;
    
        //     // let kafka_config = self.observer_config.kafka_config.clone();
        //     // let producer = create_producer(&kafka_config);
    
        //     // while let Some(Ok(block)) = blocks.next().await {
        //     //     println!(
        //     //         "block number: {} hash:{} parent:{} state root:{} extrinsics root:{}",
        //     //         block.number,
        //     //         block.hash(),
        //     //         block.parent_hash,
        //     //         block.state_root,
        //     //         block.extrinsics_root
        //     //     );
    
        //     //     let block_data = format!(
        //     //         "block number: {} hash:{} parent:{} state root:{} extrinsics root:{}",
        //     //         block.number,
        //     //         block.hash(),
        //     //         block.parent_hash,
        //     //         block.state_root,
        //     //         block.extrinsics_root
        //     //     );
    
        //     //     let record = BaseRecord::to(&kafka_config.topic)
        //     //         .payload(&block_data);
    
        //     //     producer.send(record, 0).unwrap();
        //     // }
    
        //     Ok(())
        // }
}