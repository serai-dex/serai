use std::{thread, time::Duration};
use std::{env, str};
use rdkafka::{
  producer::{BaseRecord, ProducerContext, ThreadedProducer},
  ClientConfig, ClientContext, Message,
};

pub fn start() {
  // Creates a producer to send message
  let producer: ThreadedProducer<ProduceCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .create_with_context(ProduceCallbackLogger {})
    .expect("invalid producer config");

  println!("Sending Public Keys");
  send_message_from_producer("BTC_Public_Key", "BTC_PUB".to_string(), "BTC_Processor");
  send_message_from_producer("ETH_Public_Key", "ETH_PUB".to_string(), "ETH_Processor");
  send_message_from_producer("XMR_Public_Key", "XMR_PUB".to_string(), "XMR_Processor");
}

fn send_message_from_producer(topic: &str, env_key: String, processor: &'static str) {
  let producer: ThreadedProducer<ProduceCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .create_with_context(ProduceCallbackLogger {})
    .expect("invalid producer config");

  // Load Pubkeys for processor
  let coin_pub = env::var(env_key.to_string());
  let coin_msg = coin_pub.unwrap();

  // Send pubkey to kafka topic
  producer
    .send(BaseRecord::to(&topic).key(&format!("{}", processor)).payload(&coin_msg))
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
