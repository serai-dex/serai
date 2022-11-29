use std::{thread, collections::HashMap};
use std::{env, str};
use rdkafka::{
  consumer::{BaseConsumer, Consumer, ConsumerContext, Rebalance},
  ClientConfig, ClientContext, Message, Offset,
};
use message_box::MessageBox;
use std::time::Duration;
use rdkafka::message::BorrowedMessage;

// The coordinator observer module contains functionality to poll, decode, and publish
// data of interest from the Serai blockchain to other local services.

// Path: coordinator/src/observer.rs
// Compare this snippet from coordinator/src/core.rs:

// pub struct ObserverProcess {
//   observer_config: ObserverConfig
// }

// impl ObserverProcess {
//   pub fn new(config: ObserverConfig) -> Self {
//       Self { observer_config: config }
//   }

//   pub fn run(&self) {
//       let host = self.observer_config.get_host();
//       let port = self.observer_config.get_port();
//       let poll_interval = self.observer_config.get_poll_interval();

//       // Polls substrate RPC to get block height at a specified interval;

//       let client = request::Client::new();
//       let mut last_block = 0;
//       loop {
//           let block = client.get(&url).send().unwrap().text().unwrap();
//           let block: u64 = block.parse().unwrap();
//           if block > last_block {
//               println!("New block: {}", block);
//               last_block = block;
//           }
//           thread::sleep(Duration::from_secs(poll_interval as u64));
//       }
//   }
// }

pub fn start() {
  println!("Starting Coordinator Observer");
  create_pubkey_consumer("pubkey", "BTC_Public_Key", "BTC_PUB".to_string());
  create_pubkey_consumer("pubkey", "ETH_Public_Key", "ETH_PUB".to_string());
  create_pubkey_consumer("pubkey", "XMR_Public_Key", "XMR_PUB".to_string());
}

fn create_pubkey_consumer(group_id: &str, topic: &str, env_key: String) {
  let consumer: BaseConsumer<ConsumerCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .set("group.id", group_id)
    .create_with_context(ConsumerCallbackLogger {})
    .expect("invalid consumer config");

  consumer.subscribe(&[&topic]).expect("failed to subscribe to topic");

  thread::spawn(move || {
    for msg_result in &consumer {
      let msg = msg_result.unwrap();
      let key: &str = msg.key_view().unwrap().unwrap();
      let value = msg.payload().unwrap();
      let public_key = str::from_utf8(value).unwrap();
      println!("Received {} Public Key: {}", &key, &public_key);
      env::set_var(env_key.clone(), public_key);
    }
  });
}

pub fn start_public_observer() {
  println!("Starting public Coordinator Observer");
  create_public_consumer("btc_public", "BTC_Topic", "BTC_Processor");
  create_public_consumer("eth_public", "ETH_Topic", "ETH_Processor");
  create_public_consumer("xmr_public", "XMR_Topic", "XMR_Processor");
}

fn create_public_consumer(group_id: &str, topic: &str, expected_key: &str) {
  let consumer: BaseConsumer<ConsumerCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .set("group.id", group_id)
    .create_with_context(ConsumerCallbackLogger {})
    .expect("invalid consumer config");

  let mut tpl = rdkafka::topic_partition_list::TopicPartitionList::new();
  tpl.add_partition(&topic, 0);
  consumer.assign(&tpl).unwrap();

  thread::spawn(move || {
    for msg_result in &consumer {
      let msg = msg_result.unwrap();
      let key: &str = msg.key_view().unwrap().unwrap();
      if "Coordinator" != &*key {
        let value = msg.payload().unwrap();
        let pub_msg = str::from_utf8(value).unwrap();
        println!("Received Public Message from {}", &key);
        println!("Public Message: {}", &pub_msg);
      }
    }
  });
}

pub fn start_encrypt_observer() {
  println!("Starting Encrypt Coordinator Observer");

  create_private_consumer("btc_private", "BTC_Topic", "BTC_PUB".to_string(), "BTC_Processor");
  create_private_consumer("btc_private", "ETH_Topic", "ETH_PUB".to_string(), "ETH_Processor");
  create_private_consumer("btc_private", "XMR_Topic", "XMR_PUB".to_string(), "XMR_Processor");
}

fn create_private_consumer(group_id: &str, topic: &str, env_key: String, processor: &'static str) {
  let consumer: BaseConsumer<ConsumerCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .set("group.id", group_id)
    .create_with_context(ConsumerCallbackLogger {})
    .expect("invalid consumer config");

  let mut tpl = rdkafka::topic_partition_list::TopicPartitionList::new();
  tpl.add_partition(&topic, 1);
  consumer.assign(&tpl).unwrap();

  thread::spawn(move || {
    for msg_result in &consumer {
      let msg = msg_result.unwrap();
      let key: &str = msg.key_view().unwrap().unwrap();
      if "Coordinator" != &*key {
        let value = msg.payload().unwrap();
        // Creates Message box used for decryption
        let pubkey =
          message_box::PublicKey::from_trusted_str(&env::var(env_key.to_string()).unwrap().to_string());

        let coord_priv =
          message_box::PrivateKey::from_string(env::var("COORD_PRIV").unwrap().to_string());

        let mut message_box_pubkeys = HashMap::new();
        message_box_pubkeys.insert(processor, pubkey);

        let message_box = MessageBox::new("Coordinator", coord_priv, message_box_pubkeys);
        let encrypted_msg = str::from_utf8(value).unwrap();

        // // Decrypt message using Message Box
        let encoded_string =
          message_box.decrypt_from_str(&processor, &encrypted_msg).unwrap();
        let decoded_string = String::from_utf8(encoded_string).unwrap();
        println!("Received Encrypted Message from {}", &processor);
        println!("Decrypted Message: {}", &decoded_string);
      }
    }
  });
}

struct ConsumerCallbackLogger;

impl ClientContext for ConsumerCallbackLogger {}

impl ConsumerContext for ConsumerCallbackLogger {
  fn pre_rebalance<'a>(&self, _rebalance: &rdkafka::consumer::Rebalance<'a>) {}

  fn post_rebalance<'a>(&self, rebalance: &rdkafka::consumer::Rebalance<'a>) {
    //println!("post_rebalance callback");

    match rebalance {
      Rebalance::Assign(tpl) => {
        for e in tpl.elements() {
          //println!("rebalanced partition {}", e.partition())
        }
      }
      Rebalance::Revoke(tpl) => {
        //println!("ALL partitions have been REVOKED")
      }
      Rebalance::Error(err_info) => {
        //println!("Post Rebalance error {}", err_info)
      }
    }
  }

  fn commit_callback(
    &self,
    result: rdkafka::error::KafkaResult<()>,
    offsets: &rdkafka::TopicPartitionList,
  ) {
    match result {
      Ok(_) => {
        for e in offsets.elements() {
          match e.offset() {
            //skip Invalid offset
            Offset::Invalid => {}
            _ => {
              //println!("committed offset {:?} in partition {}", e.offset(), e.partition())
            }
          }
        }
      }
      Err(err) => {
        println!("error committing offset - {}", err)
      }
    }
  }
}
