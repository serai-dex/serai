use std::{env, str};
use rdkafka::{
  producer::{BaseRecord, ProducerContext, ThreadedProducer},
  ClientConfig, ClientContext, Message
};

pub fn start() {
  // Creates a producer to send message
  let producer: ThreadedProducer<ProduceCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .create_with_context(ProduceCallbackLogger {})
    .expect("invalid producer config");

  println!("Sending Public Keys");

  // Creates a public key message for each coin
  let btc_pub = env::var("BTC_PUB");
  let btc_msg = btc_pub.unwrap();

  // Sends btc pubkey to Kafka
  producer
    .send(BaseRecord::to("BTC_Public_Key").key(&format!("BTC_Processor")).payload(&btc_msg))
    .expect("failed to send message");

  let eth_pub = env::var("ETH_PUB");
  let eth_msg = eth_pub.unwrap();

  // Sends eth pubkey to Kafka
  producer
    .send(BaseRecord::to("ETH_Public_Key").key(&format!("ETH_Processor")).payload(&eth_msg))
    .expect("failed to send message");

  let xmr_pub = env::var("XMR_PUB");
  let xmr_msg = xmr_pub.unwrap();

  // Sends xmr pubkey to Kafka
  producer
    .send(BaseRecord::to("XMR_Public_Key").key(&format!("XMR_Processor")).payload(&xmr_msg))
    .expect("failed to send message");
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
