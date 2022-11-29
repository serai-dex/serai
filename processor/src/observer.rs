use std::{thread, time::Duration, collections::HashMap};
use std::{env, str};
use rdkafka::{
  consumer::{BaseConsumer, Consumer, ConsumerContext, Rebalance},
  message::ToBytes,
  ClientConfig, ClientContext, Message, Offset,
};
use message_box::{MessageBox, SecureMessage};

pub fn start() {
  println!("Starting Processor Observer");
  let consumer_coord_pubkey: BaseConsumer<ConsumerCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .set("group.id", "serai")
    .create_with_context(ConsumerCallbackLogger {})
    .expect("invalid consumer config");

    consumer_coord_pubkey.subscribe(&["Coord_Public_Key"]).expect("public_key_topic subscribe failed");
  
    thread::spawn(move || {
      for msg_result in &consumer_coord_pubkey {
        let msg = msg_result.unwrap();
        let key: &str = msg.key_view().unwrap().unwrap();
        let value = msg.payload().unwrap();
        let public_key = str::from_utf8(value).unwrap();
        println!("Received {} Public Key: {}", &key, &public_key);
        env::set_var("COORD_PUB", public_key);
      }
    });
}

pub fn start_public_observer() {
  println!("Starting public Processor Observer");
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
        if let "Coordinator" = &*key {
        let value = msg.payload().unwrap();
        str::from_utf8(value).unwrap();
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
        if let "Coordinator" = &*key {
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
        if let "Coordinator" = &*key {
        let value = msg.payload().unwrap();
        let pub_msg = str::from_utf8(value).unwrap();
        println!("Received Public Message from {}", &key);
        println!("Public Message: {}", &pub_msg);
        }
      }
    });
}

pub fn start_encrypt_observer() {
  println!("Starting Encrypt Processor Observer");
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
        if let "Coordinator" = &*key {
        let value = msg.payload().unwrap();
        // Creates Message box used for decryption
        let COORD_PUB =
        message_box::PublicKey::from_trusted_str(&env::var("COORD_PUB").unwrap().to_string());
      
        let BTC_PRIV =
        message_box::PrivateKey::from_string(env::var("BTC_PRIV").unwrap().to_string());
      
        let mut message_box_pubkeys = HashMap::new();
        message_box_pubkeys.insert("Coordinator", COORD_PUB);
      
        let message_box = MessageBox::new("BTC_Processor", BTC_PRIV, message_box_pubkeys);
        let encrypted_msg = str::from_utf8(value).unwrap();
      
        // Decrypt message using Message Box
        let encoded_string = message_box.decrypt_from_str(&"Coordinator", &encrypted_msg).unwrap();
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
        if let "Coordinator" = &*key {
        let value = msg.payload().unwrap();
        // Creates Message box used for decryption
        let COORD_PUB =
        message_box::PublicKey::from_trusted_str(&env::var("COORD_PUB").unwrap().to_string());
      
        let BTC_PRIV =
        message_box::PrivateKey::from_string(env::var("ETH_PRIV").unwrap().to_string());
      
        let mut message_box_pubkeys = HashMap::new();
        message_box_pubkeys.insert("Coordinator", COORD_PUB);
      
        let message_box = MessageBox::new("ETH_Processor", BTC_PRIV, message_box_pubkeys);
        let encrypted_msg = str::from_utf8(value).unwrap();
      
        // Decrypt message using Message Box
        let encoded_string = message_box.decrypt_from_str(&"Coordinator", &encrypted_msg).unwrap();
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
        if let "Coordinator" = &*key {
        let value = msg.payload().unwrap();
        // Creates Message box used for decryption
        let COORD_PUB =
        message_box::PublicKey::from_trusted_str(&env::var("COORD_PUB").unwrap().to_string());
      
        let BTC_PRIV =
        message_box::PrivateKey::from_string(env::var("XMR_PRIV").unwrap().to_string());
      
        let mut message_box_pubkeys = HashMap::new();
        message_box_pubkeys.insert("Coordinator", COORD_PUB);
      
        let message_box = MessageBox::new("XMR_Processor", BTC_PRIV, message_box_pubkeys);
        let encrypted_msg = str::from_utf8(value).unwrap();
      
        // Decrypt message using Message Box
        let encoded_string = message_box.decrypt_from_str(&"Coordinator", &encrypted_msg).unwrap();
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
