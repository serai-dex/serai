use std::{thread, time::Duration, collections::HashMap};
use std::{env, str};
use rdkafka::{
  consumer::{BaseConsumer, Consumer, ConsumerContext, Rebalance},
  message::ToBytes,
  producer::{BaseProducer, BaseRecord, Producer, ProducerContext, ThreadedProducer},
  ClientConfig, ClientContext, Message, Offset,
};
use message_box::{MessageBox, SecureMessage};

pub fn start() {
  println!("Starting Coordinator Kafka Test");
  let consumer: BaseConsumer<ConsumerCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .set("group.id", "serai")
    .create_with_context(ConsumerCallbackLogger {})
    .expect("invalid consumer config");

  consumer.subscribe(&["btc_to_coord_topic"]).expect("btc topic subscribe failed");
//   consumer.subscribe(&["eth_topic"]).expect("eth topic subscribe failed");
//   consumer.subscribe(&["xmr_topic"]).expect("xmr topic subscribe failed");
//   consumer.subscribe(&["substrate_topic"]).expect("substrate topic subscribe failed");
//   consumer.subscribe(&["node_topic"]).expect("node topic subscribe failed");

  thread::spawn(move || {
    for msg_result in &consumer {
      dbg!(&msg_result);
      // Pulls recent messages from Kafka
      let msg = msg_result.unwrap();
      dbg!(&msg);
      let key: &str = msg.key_view().unwrap().unwrap();
      let value = msg.payload().unwrap();

      // Converts message from kafka UI into encrytped string
      let encrypted_msg = str::from_utf8(value).unwrap();
      dbg!(&encrypted_msg);

      //   match msg.topic() {
      //     "btc_topic" => {
      //       // Creates Message box used for decryption
      //       let A_PUB =
      //         message_box::PublicKey::from_str(&env::var("BTC_BOX_PUB").unwrap().to_string());

      //       let B_PRIV =
      //         message_box::PrivateKey::from_string(env::var("COORD_BOX_PRIV").unwrap().to_string());

      //       let mut b_others = HashMap::new();
      //       b_others.insert("BTC_Procesor", A_PUB);

      //       let b_box = MessageBox::new("Coordinator", B_PRIV, b_others);

      //       // Decrypt message using Message Box
      //       let encoded_string = b_box.decrypt_from_str(&"BTC_Procesor", &encrypted_msg).unwrap();
      //       let decoded_string = String::from_utf8(encoded_string).unwrap();
      //       dbg!(&decoded_string);
      //     }
      //     "eth_topic" => {
      //       // Creates Message box used for decryption
      //       let A_PUB =
      //         message_box::PublicKey::from_str(&env::var("ETH_BOX_PUB").unwrap().to_string());

      //       let B_PRIV =
      //         message_box::PrivateKey::from_string(env::var("COORD_BOX_PRIV").unwrap().to_string());

      //       let mut b_others = HashMap::new();
      //       b_others.insert("ETH_Procesor", A_PUB);

      //       let b_box = MessageBox::new("Coordinator", B_PRIV, b_others);

      //       // Decrypt message using Message Box
      //       let encoded_string = b_box.decrypt_from_str(&"ETH_Procesor", &encrypted_msg).unwrap();
      //       let decoded_string = String::from_utf8(encoded_string).unwrap();
      //       dbg!(&decoded_string);
      //     }
      //     "xmr_topic" => {
      //       // Creates Message box used for decryption
      //       let A_PUB =
      //         message_box::PublicKey::from_str(&env::var("XMR_BOX_PUB").unwrap().to_string());

      //       let B_PRIV =
      //         message_box::PrivateKey::from_string(env::var("COORD_BOX_PRIV").unwrap().to_string());

      //       let mut b_others = HashMap::new();
      //       b_others.insert("XMR_Procesor", A_PUB);

      //       let b_box = MessageBox::new("Coordinator", B_PRIV, b_others);

      //       // Decrypt message using Message Box
      //       let encoded_string = b_box.decrypt_from_str(&"XMR_Procesor", &encrypted_msg).unwrap();
      //       let decoded_string = String::from_utf8(encoded_string).unwrap();
      //       dbg!(&decoded_string);
      //     }

      //     "node_topic" => {
      //       // Creates Message box used for decryption
      //       let A_PUB =
      //         message_box::PublicKey::from_str(&env::var("NODE_BOX_PUB").unwrap().to_string());

      //       let B_PRIV =
      //         message_box::PrivateKey::from_string(env::var("COORD_BOX_PRIV").unwrap().to_string());

      //       let mut b_others = HashMap::new();
      //       b_others.insert("Node_Procesor", A_PUB);

      //       let b_box = MessageBox::new("Coordinator", B_PRIV, b_others);

      //       // Decrypt message using Message Box
      //       let encoded_string = b_box.decrypt_from_str(&"Node_Procesor", &encrypted_msg).unwrap();
      //       let decoded_string = String::from_utf8(encoded_string).unwrap();
      //       dbg!(&decoded_string);
      //     }

      //     "substrate_topic" => {
      //         // Creates Message box used for decryption
      //         let A_PUB =
      //           message_box::PublicKey::from_str(&env::var("SUBSTRATE_BOX_PUB").unwrap().to_string());

      //         let B_PRIV =
      //           message_box::PrivateKey::from_string(env::var("COORD_BOX_PRIV").unwrap().to_string());

      //         let mut b_others = HashMap::new();
      //         b_others.insert("Substrate_Procesor", A_PUB);

      //         let b_box = MessageBox::new("Coordinator", B_PRIV, b_others);

      //         // Decrypt message using Message Box
      //         let encoded_string = b_box.decrypt_from_str(&"Substrate_Procesor", &encrypted_msg).unwrap();
      //         let decoded_string = String::from_utf8(encoded_string).unwrap();
      //         dbg!(&decoded_string);
      //       }
      //}
    }
  });

  kafka_send_msg();
}

pub fn kafka_send_msg() {
  // Parses ENV variables to proper priv/pub keys
  let A_PRIV =
    message_box::PrivateKey::from_string(env::var("COORD_BOX_PRIV").unwrap().to_string());
  let A_PUB = message_box::PublicKey::from_str(&env::var("COORD_BOX_PUB").unwrap().to_string());

  let B_PRIV = message_box::PrivateKey::from_string(env::var("NODE_BOX_PRIV").unwrap().to_string());
  let B_PUB = message_box::PublicKey::from_str(&env::var("NODE_BOX_PUB").unwrap().to_string());

  // Create a HashMap of each pair using service name and public key
  let mut a_others = HashMap::new();
  a_others.insert("Node_Processor", B_PUB);

  let mut b_others = HashMap::new();
  b_others.insert("Coordinator", A_PUB);

  // Initialize a MessageBox for each service
  let a_box = MessageBox::new("Coordinator", A_PRIV, a_others);
  let b_box = MessageBox::new("Node_Processor", B_PRIV, b_others);
  // Creates a producer to send message
  let producer: ThreadedProducer<ProduceCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .create_with_context(ProduceCallbackLogger {})
    .expect("invalid producer config");

  println!("Sending Coordinator message to Node_Processor");

  // Creates a message & encryptes using Message Box
  let msg = b"Private Coordinator Message to Node_Processor".to_vec();
  let enc = a_box.encrypt_to_string(&"Node_Processor", &msg.clone());

  // Sends message to Kafka
  producer
    .send(BaseRecord::to("node_topic").key(&format!("node-user-{}", 1)).payload(&enc))
    .expect("Coordinator failed to send message");

  thread::sleep(Duration::from_secs(3));
}

struct ConsumerCallbackLogger;

impl ClientContext for ConsumerCallbackLogger {}

impl ConsumerContext for ConsumerCallbackLogger {
  fn pre_rebalance<'a>(&self, _rebalance: &rdkafka::consumer::Rebalance<'a>) {}

  fn post_rebalance<'a>(&self, rebalance: &rdkafka::consumer::Rebalance<'a>) {
    println!("Coordinator post_rebalance callback");

    match rebalance {
      Rebalance::Assign(tpl) => {
        for e in tpl.elements() {
          println!("Coordinator rebalanced partition {}", e.partition())
        }
      }
      Rebalance::Revoke(tpl) => {
        println!("Coordinator ALL partitions have been REVOKED")
      }
      Rebalance::Error(err_info) => {
        println!("Coordinator Post Rebalance error {}", err_info)
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
              println!("Coordinator committed offset {:?} in partition {}", e.offset(), e.partition())
            }
          }
        }
      }
      Err(err) => {
        println!("Coordinator error committing offset - {}", err)
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
          "Coordinator Produced message with key {} in offset {} of partition {}",
          key,
          msg.offset(),
          msg.partition()
        );
      }
      Err(producer_err) => {
        let key: &str = producer_err.1.key_view().unwrap().unwrap();

        println!("Coordinator failed to produce message with key {} - {}", key, producer_err.0,)
      }
    }
  }
}
