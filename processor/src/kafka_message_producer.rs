use std::{thread, time::Duration, collections::HashMap};
use std::{env, str};
use rdkafka::{
  producer::{BaseRecord, ProducerContext, ThreadedProducer},
  ClientConfig, ClientContext, Message
};
use message_box::{MessageBox};

pub fn send_messages() {
  send_message_from_producer(
    "BTC_Topic",
    "BTC_PRIV".to_string(),
    "BTC_Processor",
    b"BTC Processor message to Coordinator".to_vec(),
  );
  send_message_from_producer(
    "ETH_Topic",
    "ETH_PRIV".to_string(),
    "ETH_Processor",
    b"ETH_Processor message to Coordinator".to_vec(),
  );
  send_message_from_producer(
    "XMR_Topic",
    "XMR_PRIV".to_string(),
    "XMR_Processor",
    b"ETH_Processor message to Coordinator".to_vec(),
  );
}

fn send_message_from_producer(topic: &str, env_key: String, processor: &'static str, msg: Vec<u8>) {
  let producer: ThreadedProducer<ProduceCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .create_with_context(ProduceCallbackLogger {})
    .expect("invalid producer config");

  // Load Coordinator private environment variable
  let coin_priv =
    message_box::PrivateKey::from_string(env::var(env_key.to_string()).unwrap().to_string());

  // Load Pubkey for Coordinator
  let pubkey =
    message_box::PublicKey::from_trusted_str(&env::var("COORD_PUB").unwrap().to_string());
  let mut message_box_pubkey = HashMap::new();
  message_box_pubkey.insert("Coordinator", pubkey);

  // Create Coin Message Box
  let message_box = MessageBox::new(processor, coin_priv, message_box_pubkey);
  let enc = message_box.encrypt_to_string(&"Coordinator", &msg.clone());

  // Partition 1 is Private
  producer
    .send(BaseRecord::to(&topic).key(&format!("{}", &processor)).payload(&enc).partition(1))
    .expect("failed to send message");
  thread::sleep(Duration::from_secs(1));

  // Partition 2 is public
  producer
    .send(BaseRecord::to(&topic).key(&format!("{}", &processor)).payload(&msg).partition(0))
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
