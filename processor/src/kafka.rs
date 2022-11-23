use std::{thread, time::Duration, collections::HashMap};
use std::{env, str};
use rdkafka::{
  consumer::{BaseConsumer, Consumer, ConsumerContext, Rebalance},
  message::ToBytes,
  producer::{BaseProducer, BaseRecord, Producer, ProducerContext, ThreadedProducer},
  ClientConfig, ClientContext, Message, Offset,
};
use message_box::{MessageBox, SecureMessage};
use std::io;

pub fn start() {
  let consumer: BaseConsumer<ConsumerCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .set("group.id", "serai")
    .create_with_context(ConsumerCallbackLogger {})
    .expect("invalid consumer config");

  consumer.subscribe(&["public_keys"]).expect("topic subscribe failed");

  thread::spawn(move || {
    for msg_result in &consumer {
      // Pulls recent messages from Kafka
      let msg = msg_result.unwrap();
      let key: &str = msg.key_view().unwrap().unwrap();
      let value = msg.payload().unwrap();
      let public_key = str::from_utf8(value).unwrap();
      println!("Received public key");
      dbg!(&public_key);
      dbg!(&key);
    }
  });

  // Creates a producer to send message
  let producer: ThreadedProducer<ProduceCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .create_with_context(ProduceCallbackLogger {})
    .expect("invalid producer config");

  println!("Sending public keys");

  // Creates a public key message for each coin
  let btc_pub = env::var("BTC_PUB");
  let btc_msg = btc_pub.unwrap();

  // Sends btc pubkey to Kafka
  producer
    .send(BaseRecord::to("public_keys").key(&format!("btc_processor")).payload(&btc_msg))
    .expect("failed to send message");

  let eth_pub = env::var("ETH_PUB");
  let eth_msg = eth_pub.unwrap();

  // Sends eth pubkey to Kafka
  producer
    .send(BaseRecord::to("public_keys").key(&format!("eth_processor")).payload(&eth_msg))
    .expect("failed to send message");

  let xmr_pub = env::var("XMR_PUB");
  let xmr_msg = xmr_pub.unwrap();

  // Sends xmr pubkey to Kafka
  producer
    .send(BaseRecord::to("public_keys").key(&format!("xmr_processor")).payload(&xmr_msg))
    .expect("failed to send message");

  //thread::sleep(Duration::from_secs(10));
  io::stdin().read_line(&mut String::new()).unwrap();
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

struct ProduceCallbackLogger;

impl ClientContext for ProduceCallbackLogger {}

impl ProducerContext for ProduceCallbackLogger {
  type DeliveryOpaque = ();

  fn delivery(
    &self,
    delivery_result: &rdkafka::producer::DeliveryResult<'_>,
    _delivery_opaque: Self::DeliveryOpaque,
  ) {
    let dr = delivery_result.as_ref();
    let msg = dr.unwrap();

    match dr {
      Ok(msg) => {
        let key: &str = msg.key_view().unwrap().unwrap();
        println!(
          "Produced message with key {} in offset {} of partition {}",
          key,
          msg.offset(),
          msg.partition()
        );
      }
      Err(producer_err) => {
        let key: &str = producer_err.1.key_view().unwrap().unwrap();

        println!("failed to produce message with key {} - {}", key, producer_err.0,)
      }
    }
  }
}
