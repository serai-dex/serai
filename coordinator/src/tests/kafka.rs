use std::{env, str};
use rdkafka::{
  consumer::{ConsumerContext, Rebalance},
  producer::ProducerContext,
  ClientContext, Message, Offset,
};

fn instantiate_keys() {
  // A_PRIV and B_PRIV are dynamic testing keys for kafka
  const A_PRIV: &str = "543600cc54df140d0186f604b3a606cb3d2103327106703e80c183a481cf2a09";
  env::set_var("A_PRIV", A_PRIV);

  const A_PUB: &str = "ecb27e79e414f51ed0b1b14502611247a99fc81a58ff78604cb7789aaceebf02";
  env::set_var("A_PUB", A_PUB);

  const B_PRIV: &str = "db97aa4549842b113bf502ec47905a31c0a97837dcaa8e59ed0f12ee6b33a60c";
  env::set_var("B_PRIV", B_PRIV);

  const B_PUB: &str = "bc5e598f9337bb98b0e58b4b62fd99f2ccefbc5d4befbfe1e16dcbebab44115c";
  env::set_var("B_PUB", B_PUB);
}

#[tokio::test]
pub async fn produce_consume_message() {
  instantiate_keys();
  // Parses ENV variables to proper priv/pub keys
  let a_priv = message_box::PrivateKey::from_string(env::var("A_PRIV").unwrap().to_string());
  let a_pub = message_box::PublicKey::from_trusted_str(&env::var("A_PUB").unwrap().to_string());

  let b_priv = message_box::PrivateKey::from_string(env::var("B_PRIV").unwrap().to_string());
  let b_pub = message_box::PublicKey::from_trusted_str(&env::var("B_PUB").unwrap().to_string());

  // Create a HashMap of each pair using service name and public key
  let mut a_others = HashMap::new();
  a_others.insert(B, b_pub);

  let mut b_others = HashMap::new();
  b_others.insert(A, a_pub);

  // Initialize a MessageBox for each service
  let a_box = MessageBox::new(A, a_priv, a_others);
  let b_box = MessageBox::new(B, b_priv, b_others);

  let consumer: StreamConsumer<ConsumerCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .set("group.id", "serai")
    .set("auto.offset.reset", "smallest")
    .create_with_context(ConsumerCallbackLogger {})
    .expect("invalid consumer config");

  consumer.subscribe(&["test_topic"]).expect("topic subscribe failed");

  // Creates a producer to send message
  let producer: ThreadedProducer<ProduceCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .create_with_context(ProduceCallbackLogger {})
    .expect("invalid producer config");

  println!("Sending message");

  // Creates a message & encryptes using Message Box
  let msg = b"Private Message".to_vec();
  let enc = a_box.encrypt_to_string(&B, &msg.clone());

  // Sends message to Kafka
  producer
    .send(BaseRecord::to("test_topic").key(&format!("msg_key-1")).payload(&enc))
    .expect("failed to send message");

  let _consumer_future = consumer
    .stream()
    .take(1)
    .for_each(|message| {
      match message {
        Ok(msg_result) => {
          // Pulls recent messages from Kafka
          let msg = msg_result;
          let _key: &str = msg.key_view().unwrap().unwrap();
          let value = msg.payload().unwrap();

          // Converts message from kafka UI into encrytped string
          let encrypted_msg = str::from_utf8(value).unwrap();

          // Creates Message box used for decryption
          // I use REF to illustrate pulling env variables, there's existing A_PUB in scope
          let a_pub_ref =
            message_box::PublicKey::from_trusted_str(&env::var("A_PUB").unwrap().to_string());

          let b_priv_ref =
            message_box::PrivateKey::from_string(env::var("B_PRIV").unwrap().to_string());

          let mut b_others_ref = HashMap::new();
          b_others_ref.insert(A, a_pub_ref);

          let b_box_ref = MessageBox::new(B, b_priv_ref, b_others_ref);

          // Decrypt message using Message Box
          let encoded_string = b_box_ref.decrypt_from_str(&A, &encrypted_msg).unwrap();
          let decoded_string = String::from_utf8(encoded_string).unwrap();
          dbg!(&decoded_string);
          assert_eq!("Private Message", &decoded_string)
        }
        Err(e) => panic!("Error receiving message: {:?}", e),
      };
    })
    .await;
}

struct ConsumerCallbackLogger;

impl ClientContext for ConsumerCallbackLogger {}

impl ConsumerContext for ConsumerCallbackLogger {
  fn pre_rebalance(&self, _rebalance: &rdkafka::consumer::Rebalance) {}

  fn post_rebalance(&self, rebalance: &rdkafka::consumer::Rebalance) {
    println!("post_rebalance callback");

    match rebalance {
      Rebalance::Assign(tpl) => {
        for e in tpl.elements() {
          println!("rebalanced partition {}", e.partition())
        }
      }
      Rebalance::Revoke(_) => {
        println!("ALL partitions have been REVOKED")
      }
      Rebalance::Error(err_info) => {
        println!("Post Rebalance error {err_info}")
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
        println!("error committing offset - {err}")
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
    match dr {
      Ok(msg) => {
        let key: &str = msg.key_view().unwrap().unwrap();
        println!(
          "Produced message with key {key} in offset {} of partition {}",
          msg.offset(),
          msg.partition()
        );
      }
      Err(producer_err) => {
        let key: &str = producer_err.1.key_view().unwrap().unwrap();

        println!("failed to produce message with key {key} - {}", producer_err.0,)
      }
    }
  }
}
