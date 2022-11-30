use std::{thread, time::Duration, collections::HashMap};
use std::{env, str};
use rdkafka::{
  producer::{BaseRecord, ProducerContext, ThreadedProducer},
  ClientConfig, ClientContext, Message,
};
use message_box::MessageBox;

pub fn send_message() {
  send_message_from_producer("BTC_Topic", "BTC_PUB".to_string(), "BTC_Processor", b"Coordinator message to BTC Processor".to_vec());  
  send_message_from_producer("ETH_Topic", "ETH_PUB".to_string(), "ETH_Processor", b"Coordinator message to ETH Processor".to_vec());  
  send_message_from_producer("XMR_Topic", "XMR_PUB".to_string(), "XMR_Processor", b"Coordinator message to XMR Processor".to_vec());  
}

fn send_message_from_producer(topic: &str, env_key: String, processor: &'static str, msg: Vec<u8>){

  let producer: ThreadedProducer<ProduceCallbackLogger> = ClientConfig::new()
  .set("bootstrap.servers", "localhost:9094")
  .create_with_context(ProduceCallbackLogger {})
  .expect("invalid producer config");

   // Load Coord Priv Env variable
   let coord_priv =
   message_box::PrivateKey::from_string(env::var("COORD_PRIV").unwrap().to_string());

   // Load pubkeys for processors
  let pubkey = message_box::PublicKey::from_trusted_str(&env::var(env_key.to_string()).unwrap().to_string());
  let mut message_box_pubkey = HashMap::new();
  message_box_pubkey.insert(processor, pubkey);

  // Create Coordinator Message Box
  let message_box = MessageBox::new("Coordinator", coord_priv, message_box_pubkey);
  let enc = message_box.encrypt_to_string(&processor, &msg.clone());

  producer
    .send(BaseRecord::to(&topic).key(&format!("Coordinator")).payload(&enc).partition(1))
    .expect("failed to send message");
  thread::sleep(Duration::from_secs(1));

  producer
    .send(BaseRecord::to(&topic).key(&format!("Coordinator")).payload(&msg).partition(0))
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
