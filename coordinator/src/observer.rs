use std::{thread, time::Duration, collections::HashMap};
use std::{env, str};
use rdkafka::{
  consumer::{BaseConsumer, Consumer, ConsumerContext, Rebalance},
  message::ToBytes,
  ClientConfig, ClientContext, Message, Offset,
};
use message_box::{MessageBox, SecureMessage};
use std::io;

pub fn start() {
  println!("Starting Coordinator Observer");
  let consumer: BaseConsumer<ConsumerCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .set("group.id", "serai")
    .create_with_context(ConsumerCallbackLogger {})
    .expect("invalid consumer config");

    consumer.subscribe(&["Public_Keys"]).expect("public_key_topic subscribe failed");
    consumer.subscribe(&["BTC_Topic"]).expect("btc topic subscribe failed");
    consumer.subscribe(&["ETH_Topic"]).expect("eth topic subscribe failed");
    consumer.subscribe(&["XMR_Topic"]).expect("xmr topic subscribe failed");
  
    thread::spawn(move || {
    for msg_result in &consumer {
      let msg = msg_result.unwrap();
      match msg.topic() {
        "Public_Keys" => {
          let key: &str = msg.key_view().unwrap().unwrap();
          let value = msg.payload().unwrap();
          let public_key = str::from_utf8(value).unwrap();
          println!("Received public key");
          dbg!(&public_key);
          dbg!(&key);
        },
        "BTC_Topic" => {
          let key: &str = msg.key_view().unwrap().unwrap();
          let value = msg.payload().unwrap();

          if let "BTC_Processor" = &*key {
            // Creates Message box used for decryption
            let BTC_PUB =
            message_box::PublicKey::from_trusted_str(&env::var("BTC_PUB").unwrap().to_string());

            let COORD_PRIV =
            message_box::PrivateKey::from_string(env::var("COORD_PRIV").unwrap().to_string());

            let mut message_box_pubkeys = HashMap::new();
            message_box_pubkeys.insert("BTC_Processor", BTC_PUB);

            let message_box = MessageBox::new("Coordinator", COORD_PRIV, message_box_pubkeys);
            let encrypted_msg = str::from_utf8(value).unwrap();

            // Decrypt message using Message Box
            let encoded_string = message_box.decrypt_from_str(&"BTC_Processor", &encrypted_msg).unwrap();
            let decoded_string = String::from_utf8(encoded_string).unwrap();
            dbg!(&decoded_string);
          }
        },
        "ETH_Topic" => {
          let key: &str = msg.key_view().unwrap().unwrap();
          let value = msg.payload().unwrap();

          if let "ETH_Processor" = &*key {
            // Creates Message box used for decryption
            let ETH_PUB =
            message_box::PublicKey::from_trusted_str(&env::var("ETH_PUB").unwrap().to_string());

            let COORD_PRIV =
            message_box::PrivateKey::from_string(env::var("COORD_PRIV").unwrap().to_string());

            let mut message_box_pubkeys = HashMap::new();
            message_box_pubkeys.insert("ETH_Processor", ETH_PUB);

            let message_box = MessageBox::new("Coordinator", COORD_PRIV, message_box_pubkeys);
            let encrypted_msg = str::from_utf8(value).unwrap();

            // Decrypt message using Message Box
            let encoded_string = message_box.decrypt_from_str(&"ETH_Processor", &encrypted_msg).unwrap();
            let decoded_string = String::from_utf8(encoded_string).unwrap();
            dbg!(&decoded_string);
          }
        },
        "XMR_Topic" => {
          let key: &str = msg.key_view().unwrap().unwrap();
          let value = msg.payload().unwrap();

          if let "XMR_Processor" = &*key {
            // Creates Message box used for decryption
            let XMR_PUB =
            message_box::PublicKey::from_trusted_str(&env::var("XMR_PUB").unwrap().to_string());

            let COORD_PRIV =
            message_box::PrivateKey::from_string(env::var("COORD_PRIV").unwrap().to_string());

            let mut message_box_pubkeys = HashMap::new();
            message_box_pubkeys.insert("XMR_Processor", XMR_PUB);

            let message_box = MessageBox::new("Coordinator", COORD_PRIV, message_box_pubkeys);
            let encrypted_msg = str::from_utf8(value).unwrap();

            // Decrypt message using Message Box
            let encoded_string = message_box.decrypt_from_str(&"XMR_Processor", &encrypted_msg).unwrap();
            let decoded_string = String::from_utf8(encoded_string).unwrap();
            dbg!(&decoded_string);
          }
        },
        _ => println!("Topic Not Found"),
      }
    }
  });
}

struct ConsumerCallbackLogger;

impl ClientContext for ConsumerCallbackLogger {}

impl ConsumerContext for ConsumerCallbackLogger {
  fn pre_rebalance<'a>(&self, _rebalance: &rdkafka::consumer::Rebalance<'a>) {}

  fn post_rebalance<'a>(&self, rebalance: &rdkafka::consumer::Rebalance<'a>) {
    println!("post_rebalance callback");

    match rebalance {
      Rebalance::Assign(tpl) => {
        for e in tpl.elements() {
          println!("rebalanced partition {}", e.partition())
        }
      }
      Rebalance::Revoke(tpl) => {
        println!("ALL partitions have been REVOKED")
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
              println!("committed offset {:?} in partition {}", e.offset(), e.partition())
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
