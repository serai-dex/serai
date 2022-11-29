use std::{thread, time::Duration, collections::HashMap};
use std::{env, str};
use rdkafka::{
  producer::{BaseRecord, ProducerContext, ThreadedProducer},
  ClientConfig, ClientContext, Message
};
use message_box::{MessageBox};

pub fn btc_send_message() {
  // Creates a producer to send message
  let producer_private: ThreadedProducer<ProduceCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .create_with_context(ProduceCallbackLogger {})
    .expect("invalid producer config");

  let producer_public: ThreadedProducer<ProduceCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .create_with_context(ProduceCallbackLogger {})
    .expect("invalid producer config");

  println!("Sending BTC Encrytped & Public Message");

  // Load Coord Priv / Pub Env variable
  let btc_priv = message_box::PrivateKey::from_string(env::var("BTC_PRIV").unwrap().to_string());

  // Load pubkey for Coordinator
  let coord_priv =
    message_box::PublicKey::from_trusted_str(&env::var("COORD_PUB").unwrap().to_string());

  // Should use an additional pub key for IDs to use external message box instead of internal
  let mut message_box_pubkeys = HashMap::new();
  message_box_pubkeys.insert("Coordinator", coord_priv);

  // Create Coordinator Message Box
  let message_box = MessageBox::new("BTC_Processor", btc_priv, message_box_pubkeys);

  // Create Encrypted Message for each processor
  let msg = b"BTC Processor message to Coordinator".to_vec();
  let enc = message_box.encrypt_to_string(&"Coordinator", &msg.clone());

  // Send messages to secure partition
  producer_private
    .send(BaseRecord::to("BTC_Topic").key(&format!("BTC_Processor")).payload(&enc).partition(1))
    .expect("failed to send message");
  thread::sleep(Duration::from_secs(1));

  // Send message to public partition
  producer_public
    .send(BaseRecord::to("BTC_Topic").key(&format!("BTC_Processor")).payload(&msg).partition(0))
    .expect("failed to send message");
  thread::sleep(Duration::from_secs(1));
}

pub fn eth_send_message() {
  // Creates a producer to send message
  let producer_private: ThreadedProducer<ProduceCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .create_with_context(ProduceCallbackLogger {})
    .expect("invalid producer config");

  let producer_public: ThreadedProducer<ProduceCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .create_with_context(ProduceCallbackLogger {})
    .expect("invalid producer config");

  println!("Sending ETH Encrytped & Public Message");

  // Load Coord Priv / Pub Env variable
  let eth_priv = message_box::PrivateKey::from_string(env::var("ETH_PRIV").unwrap().to_string());

  // Load pubkey for Coordinator
  let coord_pub =
    message_box::PublicKey::from_trusted_str(&env::var("COORD_PUB").unwrap().to_string());

  // Should use an additional pub key for IDs to use external message box instead of internal
  let mut message_box_pubkeys = HashMap::new();
  message_box_pubkeys.insert("Coordinator", coord_pub);

  // Create Coordinator Message Box
  let message_box = MessageBox::new("ETH_Processor", eth_priv, message_box_pubkeys);

  // Create Encrypted Message for each processor
  let msg = b"ETH Processor message to Coordinator".to_vec();
  let enc = message_box.encrypt_to_string(&"Coordinator", &msg.clone());

  // Send message to secure partition
  producer_private
    .send(BaseRecord::to("ETH_Topic").key(&format!("ETH_Processor")).payload(&enc).partition(1))
    .expect("failed to send message");
  thread::sleep(Duration::from_secs(1));

  // Send message to public partition
  producer_public
    .send(BaseRecord::to("ETH_Topic").key(&format!("ETH_Processor")).payload(&msg).partition(0))
    .expect("failed to send message");
  thread::sleep(Duration::from_secs(1));
}

pub fn xmr_send_message() {
  // Creates a producer to send message
  let producer_private: ThreadedProducer<ProduceCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .create_with_context(ProduceCallbackLogger {})
    .expect("invalid producer config");

  let producer_public: ThreadedProducer<ProduceCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .create_with_context(ProduceCallbackLogger {})
    .expect("invalid producer config");

  println!("Sending XMR Encrytped & Public Message");

  // Load Coord Priv / Pub Env variable
  let xmr_priv = message_box::PrivateKey::from_string(env::var("XMR_PRIV").unwrap().to_string());

  // Load pubkey for Coordinator
  let coord_pub =
    message_box::PublicKey::from_trusted_str(&env::var("COORD_PUB").unwrap().to_string());

  // Should use an additional pub key for IDs to use external message box instead of internal
  let mut message_box_pubkeys = HashMap::new();
  message_box_pubkeys.insert("Coordinator", coord_pub);

  // Create Coordinator Message Box
  let message_box = MessageBox::new("XMR_Processor", xmr_priv, message_box_pubkeys);

  // Create Encrypted Message for each processor
  let msg = b"XMR Processor message to Coordinator".to_vec();
  let enc = message_box.encrypt_to_string(&"Coordinator", &msg.clone());

  // Send message to secure partition
  producer_private
    .send(BaseRecord::to("XMR_Topic").key(&format!("XMR_Processor")).payload(&enc).partition(1))
    .expect("failed to send message");
  thread::sleep(Duration::from_secs(1));

  // Send message to public partition
  producer_public
    .send(BaseRecord::to("XMR_Topic").key(&format!("XMR_Processor")).payload(&msg).partition(0))
    .expect("failed to send message");
  thread::sleep(Duration::from_secs(1));
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
        // println!(
        //   "Produced message with key {} in offset {} of partition {}",
        //   key,
        //   msg.offset(),
        //   msg.partition()
        // );
      }
      Err(producer_err) => {
        let key: &str = producer_err.1.key_view().unwrap().unwrap();

        println!("failed to produce message with key {} - {}", key, producer_err.0,)
      }
    }
  }
}
