use std::{thread, time::Duration, collections::HashMap};
use std::{env, str};
use rdkafka::{
  producer::{BaseRecord, ProducerContext, ThreadedProducer},
  ClientConfig, ClientContext, Message,
};
use message_box::MessageBox;

pub fn send_message() {
  // Creates a producer to send message
  let producer_btc_private: ThreadedProducer<ProduceCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .create_with_context(ProduceCallbackLogger {})
    .expect("invalid producer config");

  let producer_eth_private: ThreadedProducer<ProduceCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .create_with_context(ProduceCallbackLogger {})
    .expect("invalid producer config");

  let producer_xmr_private: ThreadedProducer<ProduceCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .create_with_context(ProduceCallbackLogger {})
    .expect("invalid producer config");

  let producer_btc_public: ThreadedProducer<ProduceCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .create_with_context(ProduceCallbackLogger {})
    .expect("invalid producer config");

  let producer_eth_public: ThreadedProducer<ProduceCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .create_with_context(ProduceCallbackLogger {})
    .expect("invalid producer config");

  let producer_xmr_public: ThreadedProducer<ProduceCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .create_with_context(ProduceCallbackLogger {})
    .expect("invalid producer config");

  println!("Sending Encrytped & Public Message");

  // Load Coord Priv Env variable
  let coord_priv =
    message_box::PrivateKey::from_string(env::var("COORD_PRIV").unwrap().to_string());

  // Load pubkeys for processors
  let btc_pub = message_box::PublicKey::from_trusted_str(&env::var("BTC_PUB").unwrap().to_string());
  let eth_pub = message_box::PublicKey::from_trusted_str(&env::var("ETH_PUB").unwrap().to_string());
  let xmr_pub = message_box::PublicKey::from_trusted_str(&env::var("XMR_PUB").unwrap().to_string());

  // Should use an additional pub key for IDs to use external message box instead of internal
  let mut message_box_pubkeys = HashMap::new();
  message_box_pubkeys.insert("BTC_Processor", btc_pub);
  message_box_pubkeys.insert("ETH_Processor", eth_pub);
  message_box_pubkeys.insert("XMR_Processor", xmr_pub);

  // Create Coordinator Message Box
  let message_box = MessageBox::new("Coordinator", coord_priv, message_box_pubkeys);

  // Create Encrypted Message for each processor
  let btc_msg = b"Coordinator message to BTC Processor".to_vec();
  let btc_enc = message_box.encrypt_to_string(&"BTC_Processor", &btc_msg.clone());

  let eth_msg = b"Coordinator message to ETH Processor".to_vec();
  let eth_enc = message_box.encrypt_to_string(&"ETH_Processor", &eth_msg.clone());

  let xmr_msg = b"Coordinator message to XMR Processor".to_vec();
  let xmr_enc = message_box.encrypt_to_string(&"XMR_Processor", &xmr_msg.clone());

  // Send messages to secure partition
  producer_btc_private
    .send(BaseRecord::to("BTC_Topic").key(&format!("Coordinator")).payload(&btc_enc).partition(1))
    .expect("failed to send message");
  thread::sleep(Duration::from_secs(1));

  producer_eth_private
    .send(BaseRecord::to("ETH_Topic").key(&format!("Coordinator")).payload(&eth_enc).partition(1))
    .expect("failed to send message");
  thread::sleep(Duration::from_secs(1));

  producer_xmr_private
    .send(BaseRecord::to("XMR_Topic").key(&format!("Coordinator")).payload(&xmr_enc).partition(1))
    .expect("failed to send message");
  thread::sleep(Duration::from_secs(1));

  // Send messages to public partition
  producer_btc_public
    .send(BaseRecord::to("BTC_Topic").key(&format!("Coordinator")).payload(&btc_msg).partition(0))
    .expect("failed to send message");
  thread::sleep(Duration::from_secs(1));

  producer_eth_public
    .send(BaseRecord::to("ETH_Topic").key(&format!("Coordinator")).payload(&eth_msg).partition(0))
    .expect("failed to send message");
  thread::sleep(Duration::from_secs(1));

  producer_xmr_public
    .send(BaseRecord::to("XMR_Topic").key(&format!("Coordinator")).payload(&xmr_msg).partition(0))
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
