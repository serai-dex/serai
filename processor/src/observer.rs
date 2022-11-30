use std::{thread, collections::HashMap};
use std::{env, str};
use rdkafka::{
  consumer::{BaseConsumer, Consumer, ConsumerContext, Rebalance},
  ClientConfig, ClientContext, Message, Offset,
};
use message_box::MessageBox;

pub fn start() {
  println!("Starting Processor Observer");
  let consumer_coord_pubkey: BaseConsumer<ConsumerCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .set("group.id", "serai")
    .create_with_context(ConsumerCallbackLogger {})
    .expect("invalid consumer config");

  consumer_coord_pubkey
    .subscribe(&["Coord_Public_Key"])
    .expect("public_key_topic subscribe failed");

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
  println!("Starting Public Processor Observer");
  create_public_consumer("btc_public", "BTC_Topic");
  create_public_consumer("eth_public", "ETH_Topic");
  create_public_consumer("xmr_public", "XMR_Topic");
}

fn create_public_consumer(group_id: &str, topic: &str) {
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
      if key == "Coordinator" {
        let value = msg.payload().unwrap();
        let pub_msg = str::from_utf8(value).unwrap();
        println!("Received Public Message from {}", &key);
        println!("Public Message: {}", &pub_msg);
      }
    }
  });
}

pub fn start_private_observer() {
  println!("Starting Private Processor Observer");
  create_private_consumer("btc_private", "BTC_Topic", "BTC_PRIV".to_string(), "BTC_Processor");
  create_private_consumer("eth_private", "ETH_Topic", "ETH_PRIV".to_string(), "ETH_Processor");
  create_private_consumer("xmr_private", "XMR_Topic", "XMR_PRIV".to_string(), "XMR_Processor");
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
      if key == "Coordinator" {
        let value = msg.payload().unwrap();
        // Creates Message box used for decryption
        let coord_pub =
          message_box::PublicKey::from_trusted_str(&env::var("COORD_PUB").unwrap().to_string());

        let coin_priv =
          message_box::PrivateKey::from_string(env::var(env_key.to_string()).unwrap().to_string());

        let mut message_box_pubkeys = HashMap::new();
        message_box_pubkeys.insert("Coordinator", coord_pub);

        let message_box = MessageBox::new(processor, coin_priv, message_box_pubkeys);
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
