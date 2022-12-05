// The coordinator observer module contains functionality to poll, decode, and publish
// data of interest from the Serai blockchain to other local services.

// Path: coordinator/src/observer.rs
// Compare this snippet from coordinator/src/core.rs:

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

