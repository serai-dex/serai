use std::{thread, collections::HashMap};
use std::{env, str};
use rdkafka::{
  consumer::{BaseConsumer, Consumer, ConsumerContext, Rebalance},
  ClientConfig, ClientContext, Message, Offset,
};
use message_box::MessageBox;
use std::time::Duration;

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

pub fn start() {
  println!("Starting Coordinator Observer");
  let btc_consumer: BaseConsumer<ConsumerCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .set("group.id", "serai")
    .create_with_context(ConsumerCallbackLogger {})
    .expect("invalid consumer config");

  let eth_consumer: BaseConsumer<ConsumerCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .set("group.id", "serai")
    .create_with_context(ConsumerCallbackLogger {})
    .expect("invalid consumer config");

  let xmr_consumer: BaseConsumer<ConsumerCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .set("group.id", "serai")
    .create_with_context(ConsumerCallbackLogger {})
    .expect("invalid consumer config");

  btc_consumer.subscribe(&["BTC_Public_Key"]).expect("btc pubkey topic subscribe failed");
  eth_consumer.subscribe(&["ETH_Public_Key"]).expect("eth pubkey topic subscribe failed");
  xmr_consumer.subscribe(&["XMR_Public_Key"]).expect("xmr pubkey topic subscribe failed");

  thread::spawn(move || {
    for msg_result in &btc_consumer {
      let msg = msg_result.unwrap();
      let key: &str = msg.key_view().unwrap().unwrap();
      let value = msg.payload().unwrap();
      let public_key = str::from_utf8(value).unwrap();
      println!("Received {} Public Key: {}", &key, &public_key);
      env::set_var("BTC_PUB", public_key);
    }
  });

  thread::spawn(move || {
    for msg_result in &eth_consumer {
      let msg = msg_result.unwrap();
      let key: &str = msg.key_view().unwrap().unwrap();
      let value = msg.payload().unwrap();
      let public_key = str::from_utf8(value).unwrap();
      println!("Received {} Public Key: {}", &key, &public_key);
      env::set_var("ETH_PUB", public_key);
    }
  });

  thread::spawn(move || {
    for msg_result in &xmr_consumer {
      let msg = msg_result.unwrap();
      let key: &str = msg.key_view().unwrap().unwrap();
      let value = msg.payload().unwrap();
      let public_key = str::from_utf8(value).unwrap();
      println!("Received {} Public Key: {}", &key, &public_key);
      env::set_var("XMR_PUB", public_key);
    }
  });
}

pub fn start_public_observer() {
  println!("Starting public Coordinator Observer");

  let consumer_btc_public: BaseConsumer<ConsumerCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .set("group.id", "btc_public")
    .create_with_context(ConsumerCallbackLogger {})
    .expect("invalid consumer config");

  let mut btc_tpl = rdkafka::topic_partition_list::TopicPartitionList::new();
  btc_tpl.add_partition("BTC_Topic", 0);
  consumer_btc_public.assign(&btc_tpl).unwrap();

  let consumer_eth_public: BaseConsumer<ConsumerCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .set("group.id", "eth_public")
    .create_with_context(ConsumerCallbackLogger {})
    .expect("invalid consumer config");

  let mut eth_tpl = rdkafka::topic_partition_list::TopicPartitionList::new();
  eth_tpl.add_partition("ETH_Topic", 0);
  consumer_eth_public.assign(&eth_tpl).unwrap();

  let consumer_xmr_public: BaseConsumer<ConsumerCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .set("group.id", "xmr_public")
    .create_with_context(ConsumerCallbackLogger {})
    .expect("invalid consumer config");

  let mut xmr_tpl = rdkafka::topic_partition_list::TopicPartitionList::new();
  xmr_tpl.add_partition("XMR_Topic", 0);
  consumer_xmr_public.assign(&xmr_tpl).unwrap();

  thread::spawn(move || {
    for msg_result in &consumer_btc_public {
      let msg = msg_result.unwrap();
      let key: &str = msg.key_view().unwrap().unwrap();
      if let "BTC_Processor" = &*key {
        let value = msg.payload().unwrap();
        let pub_msg = str::from_utf8(value).unwrap();
        println!("Received Public Message from {}", &key);
        println!("Public Message: {}", &pub_msg);
      }
    }
  });

  thread::spawn(move || {
    for msg_result in &consumer_eth_public {
      let msg = msg_result.unwrap();
      let key: &str = msg.key_view().unwrap().unwrap();
      if let "ETH_Processor" = &*key {
        let value = msg.payload().unwrap();
        let pub_msg = str::from_utf8(value).unwrap();
        println!("Received Public Message from {}", &key);
        println!("Public Message: {}", &pub_msg);
      }
    }
  });

  thread::spawn(move || {
    for msg_result in &consumer_xmr_public {
      let msg = msg_result.unwrap();
      let key: &str = msg.key_view().unwrap().unwrap();
      if let "XMR_Processor" = &*key {
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

  let consumer_btc_encrypt: BaseConsumer<ConsumerCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .set("group.id", "btc_private")
    .create_with_context(ConsumerCallbackLogger {})
    .expect("invalid consumer config");

  let mut btc_tpl = rdkafka::topic_partition_list::TopicPartitionList::new();
  btc_tpl.add_partition("BTC_Topic", 1);
  consumer_btc_encrypt.assign(&btc_tpl).unwrap();

  let consumer_eth_encrypt: BaseConsumer<ConsumerCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .set("group.id", "eth_private")
    .create_with_context(ConsumerCallbackLogger {})
    .expect("invalid consumer config");

  let mut eth_tpl = rdkafka::topic_partition_list::TopicPartitionList::new();
  eth_tpl.add_partition("ETH_Topic", 1);
  consumer_eth_encrypt.assign(&eth_tpl).unwrap();

  let consumer_xmr_encrypt: BaseConsumer<ConsumerCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .set("group.id", "xmr_private")
    .create_with_context(ConsumerCallbackLogger {})
    .expect("invalid consumer config");

  let mut xmr_tpl = rdkafka::topic_partition_list::TopicPartitionList::new();
  xmr_tpl.add_partition("XMR_Topic", 1);
  consumer_xmr_encrypt.assign(&xmr_tpl).unwrap();

  thread::spawn(move || {
    for msg_result in &consumer_btc_encrypt {
      let msg = msg_result.unwrap();
      let key: &str = msg.key_view().unwrap().unwrap();
      if let "BTC_Processor" = &*key {
        let value = msg.payload().unwrap();

        // Creates Message box used for decryption
        let btc_pub =
          message_box::PublicKey::from_trusted_str(&env::var("BTC_PUB").unwrap().to_string());

        let coord_priv =
          message_box::PrivateKey::from_string(env::var("COORD_PRIV").unwrap().to_string());

        let mut message_box_pubkeys = HashMap::new();
        message_box_pubkeys.insert("BTC_Processor", btc_pub);

        let message_box = MessageBox::new("Coordinator", coord_priv, message_box_pubkeys);
        let encrypted_msg = str::from_utf8(value).unwrap();

        // Decrypt message using Message Box
        let encoded_string =
          message_box.decrypt_from_str(&"BTC_Processor", &encrypted_msg).unwrap();
        let decoded_string = String::from_utf8(encoded_string).unwrap();
        println!("Received Encrypted Message from {}", &key);
        println!("Decrypted Message: {}", &decoded_string);
      }
    }
  });

  thread::spawn(move || {
    for msg_result in &consumer_eth_encrypt {
      let msg = msg_result.unwrap();
      let key: &str = msg.key_view().unwrap().unwrap();
      if let "ETH_Processor" = &*key {
        let value = msg.payload().unwrap();

        // Creates Message box used for decryption
        let eth_pub =
          message_box::PublicKey::from_trusted_str(&env::var("ETH_PUB").unwrap().to_string());

        let coord_priv =
          message_box::PrivateKey::from_string(env::var("COORD_PRIV").unwrap().to_string());

        let mut message_box_pubkeys = HashMap::new();
        message_box_pubkeys.insert("ETH_Processor", eth_pub);

        let message_box = MessageBox::new("Coordinator", coord_priv, message_box_pubkeys);
        let encrypted_msg = str::from_utf8(value).unwrap();

        // Decrypt message using Message Box
        let encoded_string =
          message_box.decrypt_from_str(&"ETH_Processor", &encrypted_msg).unwrap();
        let decoded_string = String::from_utf8(encoded_string).unwrap();
        println!("Received Encrypted Message from {}", &key);
        println!("Decrypted Message: {}", &decoded_string);
      }
    }
  });

  thread::spawn(move || {
    for msg_result in &consumer_xmr_encrypt {
      let msg = msg_result.unwrap();
      let key: &str = msg.key_view().unwrap().unwrap();
      if let "XMR_Processor" = &*key {
        let value = msg.payload().unwrap();

        // Creates Message box used for decryption
        let xmr_pub =
          message_box::PublicKey::from_trusted_str(&env::var("XMR_PUB").unwrap().to_string());

        let coord_priv =
          message_box::PrivateKey::from_string(env::var("COORD_PRIV").unwrap().to_string());

        let mut message_box_pubkeys = HashMap::new();
        message_box_pubkeys.insert("XMR_Processor", xmr_pub);

        let message_box = MessageBox::new("Coordinator", coord_priv, message_box_pubkeys);
        let encrypted_msg = str::from_utf8(value).unwrap();

        // Decrypt message using Message Box
        let encoded_string =
          message_box.decrypt_from_str(&"XMR_Processor", &encrypted_msg).unwrap();
        let decoded_string = String::from_utf8(encoded_string).unwrap();
        println!("Received Encrypted Message from {}", &key);
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
        println!("Post Rebalance error {}", err_info)
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
