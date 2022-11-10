use std::{thread, time::Duration, collections::HashMap};
use std::env;
use rdkafka::{
  consumer::{BaseConsumer, Consumer, ConsumerContext, Rebalance},
  message::ToBytes,
  producer::{BaseProducer, BaseRecord, Producer, ProducerContext, ThreadedProducer},
  ClientConfig, ClientContext, Message, Offset,
};

use message_box::MessageBox;

const A: &'static str = "A";
const B: &'static str = "B";

pub fn start() {
  // Create 2 priv / pub key pairs
  let (a_priv, a_pub) = message_box::key_gen();
  let (b_priv, b_pub) = message_box::key_gen();

  // Create a HashMap of each pair using service name and public key
  let mut a_others = HashMap::new();
  a_others.insert(B, b_pub);

  let mut b_others = HashMap::new();
  b_others.insert(A, a_pub);

  // Initialize a MessageBox for each service
  let a_box = MessageBox::new(A, a_priv, a_others);
  let b_box = MessageBox::new(B, b_priv, b_others);

  // Set an encryption key used for decrypting messages as environment variable
  let MESSAGE_BOX_A = "MESSAGE_BOX_A";
  env::set_var(MESSAGE_BOX_A, a_box);

  let MESSAGE_BOX_B = "MESSAGE_BOX_B";
  env::set_var(MESSAGE_BOX_B, b_box);

  let consumer: BaseConsumer<ConsumerCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    //for auth
    /*.set("security.protocol", "SASL_SSL")
    .set("sasl.mechanisms", "PLAIN")
    .set("sasl.username", "<update>")
    .set("sasl.password", "<update>")*/
    .set("group.id", "serai")
    .create_with_context(ConsumerCallbackLogger {})
    .expect("invalid consumer config");

  consumer.subscribe(&["test_topic"]).expect("topic subscribe failed");

  thread::spawn(move || loop {
    for msg_result in consumer.iter() {
      let msg = msg_result.unwrap();
      let key: &str = msg.key_view().unwrap().unwrap();
      let value = msg.payload().unwrap();
      // let message_box = MessageBox::new(&static str , dalek_ff_group::Scalar, HashMap<&static str, dalek_ff_group::RistrettoPoint>);
      let encrypted_string = std::str::from_utf8(&value).unwrap();
      let decrypted_string = String::from_utf8(b_box.decrypt(A, &encrypted_string).unwrap());
      let user: User =
        serde_json::from_str(&decrypted_string).expect("failed to deserialize JSON to User");
      //println!("{}", decrypted_string);
      println!(
        "received key {} with value {:?} in offset {:?} from partition {}",
        key,
        user,
        msg.offset(),
        msg.partition()
      )
    }
  });

  let producer: ThreadedProducer<ProduceCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    //for auth
    /*.set("security.protocol", "SASL_SSL")
    .set("sasl.mechanisms", "PLAIN")
    .set("sasl.username", "<update>")
    .set("sasl.password", "<update>")*/
    .create_with_context(ProduceCallbackLogger {})
    .expect("invalid producer config");

  for i in 1..100 {
    println!("sending message");

    let user = User { id: i, email: format!("user-{}@foobar.com", i) };

    let user_json = serde_json::to_string_pretty(&user).expect("json serialization failed");

    let msg = user_json.as_bytes().to_vec();
    let enc = a_box.encrypt(B, msg.clone());

    producer
      .send(BaseRecord::to("test_topic").key(&format!("user-{}", i)).payload(&enc))
      .expect("failed to send message");

    thread::sleep(Duration::from_secs(3));
  }
}

use serde::{Deserialize, Serialize};

use self::crypt::SeraiCrypt;
#[derive(Serialize, Deserialize, Debug)]
struct User {
  id: i32,
  email: String,
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
    //let msg = dr.unwrap();

    match dr {
      Ok(msg) => {
        let key: &str = msg.key_view().unwrap().unwrap();
        println!(
          "produced message with key {} in offset {} of partition {}",
          key,
          msg.offset(),
          msg.partition()
        )
      }
      Err(producer_err) => {
        let key: &str = producer_err.1.key_view().unwrap().unwrap();

        println!("failed to produce message with key {} - {}", key, producer_err.0,)
      }
    }
  }
}
