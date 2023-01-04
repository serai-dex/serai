use codec::Decode;
use kitchensink_runtime::Runtime;
use log::debug;
use sp_core::{sr25519, H256 as Hash};
use substrate_api_client::{
	rpc::{HandleSubscription, JsonrpseeClient},
	Api, AssetTipExtrinsicParams, SubscribeFrameSystem,
};

// This module depends on node_runtime.
// To avoid dependency collisions, node_runtime has been removed from the substrate-api-client library.
// Replace this crate by your own if you run a custom substrate node to get your custom events.
use kitchensink_runtime::RuntimeEvent;
pub struct ObserverProcess {
  observer_config: ObserverConfig
}

impl ObserverProcess {
  pub fn new(config: ObserverConfig) -> Self {
      Self { observer_config: config }
  }

  pub fn run(&self) {
      let host = self.observer_config.get_host();
      let port = self.observer_config.get_port();
      let poll_interval = self.observer_config.get_poll_interval();

      // Polls substrate RPC to get block height at a specified interval;

      let client = request::Client::new();
      let mut last_block = 0;
      loop {
          let block = client.get(&url).send().unwrap().text().unwrap();
          let block: u64 = block.parse().unwrap();
          if block > last_block {
              println!("New block: {}", block);
              last_block = block;
          }
          thread::sleep(Duration::from_secs(poll_interval as u64));
      }
  }
}

