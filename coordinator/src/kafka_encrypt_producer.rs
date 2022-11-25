use std::{thread, time::Duration, collections::HashMap};
use std::{env, str};
use rdkafka::{
  message::ToBytes,
  producer::{BaseProducer, BaseRecord, Producer, ProducerContext, ThreadedProducer},
  ClientConfig, ClientContext, Message, Offset,
};
use message_box::{MessageBox, SecureMessage};
use std::io;

pub fn send_message() {
  // Creates a producer to send message
  let producer: ThreadedProducer<ProduceCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .create_with_context(ProduceCallbackLogger {})
    .expect("invalid producer config");

  println!("Sending encrytped message");

  // Load Coord Priv / Pub Env variable
  let COORD_PRIV =
  message_box::PrivateKey::from_string(env::var("COORD_PRIV").unwrap().to_string());
  let COORD_PUB = message_box::PublicKey::from_trusted_str(&env::var("COORD_PUB").unwrap().to_string());

  // Load pubkeys for processors
  let BTC_PUB = message_box::PublicKey::from_trusted_str(&env::var("BTC_PUB").unwrap().to_string());
  let ETH_PUB = message_box::PublicKey::from_trusted_str(&env::var("ETH_PUB").unwrap().to_string());
  let XMR_PUB = message_box::PublicKey::from_trusted_str(&env::var("XMR_PUB").unwrap().to_string());

  // Should use an additional pub key for IDs to use external message box instead of internal
  let mut message_box_pubkeys = HashMap::new();
  message_box_pubkeys.insert("btc", BTC_PUB);
  message_box_pubkeys.insert("eth", ETH_PUB);
  message_box_pubkeys.insert("xmr", XMR_PUB);

  // Create Coordinator Message Box
  let coordinator_message_box = MessageBox::new("Coordinator", COORD_PRIV, message_box_pubkeys);
  
  // Create Encrypted Message for each processor
  let btc_msg = "Cooordinator message to BTC Processor".to_vec();
  let btc_enc = coordinator_message_box.encrypt_to_string(&"BTC_Processor", &btc_msg.clone());

  let eth_msg = "Cooordinator message to ETH Processor".to_vec();
  let eth_enc = coordinator_message_box.encrypt_to_string(&"ETH_Processor", &eth_msg.clone());
  
  let xmr_msg = "Cooordinator message to XMR Processor".to_vec();
  let xmr_enc = coordinator_message_box.encrypt_to_string(&"XMR_Processor", &xmr_msg.clone());

  // Send Encrypted Messages to secure partitian
  producer
    .send(BaseRecord::to("btc_topic").key(&format!("coordinator")).payload(&btc_enc))
    .expect("failed to send message");

  producer
    .send(BaseRecord::to("eth_topic").key(&format!("coordinator")).payload(&eth_enc))
    .expect("failed to send message");
  
  producer
    .send(BaseRecord::to("xmr_topic").key(&format!("coordinator")).payload(&xmr_enc))
    .expect("failed to send message");

  io::stdin().read_line(&mut String::new()).unwrap();
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
