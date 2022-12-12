use std::{thread, collections::HashMap};
use std::{env, str, fmt};
use rdkafka::{
  producer::{BaseRecord, ProducerContext, ThreadedProducer},
  consumer::{BaseConsumer, Consumer, ConsumerContext, Rebalance},
  ClientConfig, ClientContext, Message, Offset,
  admin::{AdminClient, TopicReplication, NewTopic, AdminOptions},
  client::DefaultClientContext,
};
use message_box::MessageBox;
use std::time::Duration;

use serde::{Deserialize};
use crate::ProcessorConfig;
use crate::core::ChainConfig;

#[derive(Debug, PartialEq, Eq, Hash)]
enum Coin {
  SRI,
  BTC,
  ETH,
  XMR,
}

impl fmt::Display for Coin {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      Coin::SRI => write!(f, "SRI"),
      Coin::BTC => write!(f, "BTC"),
      Coin::ETH => write!(f, "ETH"),
      Coin::XMR => write!(f, "XMR"),
    }
  }
}

#[derive(Clone, Debug, Deserialize)]
pub struct SignatureProcess {
  chain_config: ChainConfig,
  identity: String,
}

fn create_config() -> ClientConfig {
  let mut config = ClientConfig::new();
  config.set("bootstrap.servers", "localhost:9094");
  config
}

fn create_admin_client() -> AdminClient<DefaultClientContext> {
  create_config().create().expect("admin client creation failed")
}

impl SignatureProcess {
  pub fn new(config: ProcessorConfig, identity: String) -> Self {
    println!("New Signature Process");
    let chain_config = config.get_chain();
    Self { chain_config: chain_config, identity: identity }
  }

  pub async fn run(self) {
    println!("Starting Signature Process");

    // Check/initialize kakf topics
    let j = serde_json::to_string(&self.chain_config).unwrap();
    let mut topic_ref: HashMap<String, bool> = serde_json::from_str(&j).unwrap();
    topic_ref.insert("Coordinator".to_string(), true);

    let admin_client = create_admin_client();
    let opts = AdminOptions::new().operation_timeout(Some(Duration::from_secs(1)));

    // Loop through each coin & initialize each kakfa topic
    for (key, value) in topic_ref.into_iter() {
      let mut topic: String = "".to_string();
      topic.push_str(&self.identity);
      let topic_ref = &mut String::from(&key);
      if (topic_ref != "Coordinator") {
        *topic_ref = topic_ref.to_uppercase();
      }
      topic.push_str("_");
      topic.push_str(topic_ref);
      topic.push_str("_Topic");

      let initialized_topic = NewTopic {
        name: &topic,
        num_partitions: 2,
        replication: TopicReplication::Fixed(1),
        config: Vec::new(),
      };

      admin_client.create_topics(&[initialized_topic], &opts).await.expect("topic creation failed");
    }

    // Create Hashmap based on coins
    let coin_hashmap = create_coin_hashmap(&self.chain_config);

    // Create/Start Consumer used to read pubkey messages on public partition 0
    start_pubkey_consumer(&self.identity);

    // Create Pubkey Producer & sends pubkey message on public partiion 0
    start_pubkey_producer(&self.identity, &coin_hashmap);

    // Wait to receive Coordinator Pubkey
    process_received_pubkey();

    // Create/Start Consumer used to read public messages on public partition 0
    start_public_consumer(&self.identity, &coin_hashmap);

    // Create/Start Consumer used to read encrypted message on private partition 1
    start_private_consumer(&self.identity, &coin_hashmap);

    // Create/Start Producer that sends a public message on partition 0 and encrytped message on partition 1
    start_pub_priv_producer(&self.identity, &coin_hashmap);
  }

  fn stop(self) {
    println!("Stopping Signature Process");
  }
}

// Create/Start Consumer used to read pubkey messages on public partition 0
fn start_pubkey_consumer(identity: &str) {
  let consumer: BaseConsumer<ConsumerCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .set("group.id", "Coord_Pubkey")
    .set("auto.offset.reset", "smallest")
    .create_with_context(ConsumerCallbackLogger {})
    .expect("invalid consumer config");

  let mut tpl = rdkafka::topic_partition_list::TopicPartitionList::new();
  tpl.add_partition(&format!("{}_Coordinator_Topic", &identity), 0);
  consumer.assign(&tpl).unwrap();

  thread::spawn(move || {
    for msg_result in &consumer {
      let msg = msg_result.unwrap();
      let key: &str = msg.key_view().unwrap().unwrap();
      let value = msg.payload().unwrap();
      let public_key = str::from_utf8(value).unwrap();
      println!("Received {} Public Key: {}", &key, &public_key);
      env::set_var("COORD_PUB", public_key);
    }
  });
}

// Create/Start Consumer used to read public messages on public partition 0
fn start_public_consumer(identity: &str, coin_hashmap: &HashMap<Coin, bool>) {
  let hashmap_clone = coin_hashmap.clone();

  // Loop through each coin & if active, create pubkey consumer
  for (key, value) in hashmap_clone.into_iter() {
    if *value == true {
      let group_id = &mut key.to_string();
      group_id.push_str("_Public");
      let mut topic: String = String::from(identity);
      topic.push_str("_");
      topic.push_str(&key.to_string());
      topic.push_str("_Topic");
      initialize_consumer(&group_id, &topic, None, None, "public");
    }
  }
}

// Create/Start Consumer used to read encrypted message on private partition 1
fn start_private_consumer(identity: &str, coin_hashmap: &HashMap<Coin, bool>) {
  let hashmap_clone = coin_hashmap.clone();

  // Loop through each coin & if active, create pubkey consumer
  for (key, value) in hashmap_clone.into_iter() {
    if *value == true {
      let group_id = &mut key.to_string();
      group_id.push_str("_Private");
      let mut topic: String = String::from(identity);
      topic.push_str("_");
      topic.push_str(&key.to_string());
      topic.push_str("_Topic");
      let env_key = &mut key.to_string();
      env_key.push_str("_PRIV");
      initialize_consumer(
        &group_id,
        &topic,
        Some(env_key.to_string()),
        Some(&key.to_string()),
        "private",
      );
    }
  }
}

// Will Create a Consumer based on Pubkey, Public, or Private
// Pubkey Consumer is used to read pubkey messages on public partition 0
// Public Consumer is used to read public messages on public partition 0
// Private Consumer is used to read encrypted message on private partition 1
fn initialize_consumer(
  group_id: &str,
  topic: &str,
  env_key: Option<String>,
  coin: Option<&String>,
  consumer_type: &str,
) {
  let consumer: BaseConsumer<ConsumerCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .set("group.id", group_id)
    .create_with_context(ConsumerCallbackLogger {})
    .expect("invalid consumer config");

  let mut env_key_ref: String = "".to_string();
  match env_key {
    Some(p) => {
      env_key_ref = String::from(p);
    }
    None => {}
  }

  let mut coin_ref: String = "".to_string();
  match coin {
    Some(p) => {
      coin_ref = String::from(p);
    }
    None => {}
  }

  match consumer_type {
    "pubkey" => {
      let mut tpl = rdkafka::topic_partition_list::TopicPartitionList::new();
      tpl.add_partition(&topic, 2);
      consumer.assign(&tpl).unwrap();

      thread::spawn(move || {
        for msg_result in &consumer {
          let msg = msg_result.unwrap();
          let key: &str = msg.key_view().unwrap().unwrap();
          if key.contains("COORDINATOR") && key.contains("Pubkey") {
            let value = msg.payload().unwrap();
            let public_key = str::from_utf8(value).unwrap();
            println!("Received Message from {}: {}", &key, &public_key);
            env::set_var(env_key_ref.clone(), public_key);
          }
        }
      });
    }
    "public" => {
      let mut tpl = rdkafka::topic_partition_list::TopicPartitionList::new();
      tpl.add_partition(&topic, 0);
      consumer.assign(&tpl).unwrap();

      thread::spawn(move || {
        for msg_result in &consumer {
          let msg = msg_result.unwrap();
          let key: &str = msg.key_view().unwrap().unwrap();
          if key.contains("COORDINATOR") && key.contains("Public") {
            let value = msg.payload().unwrap();
            let pub_msg = str::from_utf8(value).unwrap();
            println!("Received Public Message from {}", &key);
            println!("Public Message: {}", &pub_msg);
          }
        }
      });
    }
    "private" => {
      let mut tpl = rdkafka::topic_partition_list::TopicPartitionList::new();
      tpl.add_partition(&topic, 1);
      consumer.assign(&tpl).unwrap();

      thread::spawn(move || {
        for msg_result in &consumer {
          let msg = msg_result.unwrap();
          let key: &str = msg.key_view().unwrap().unwrap();
          if key.contains("COORDINATOR") {
            let value = msg.payload().unwrap();
            // Creates Message box used for decryption
            let pubkey =
              message_box::PublicKey::from_trusted_str(&env::var("COORD_PUB").unwrap().to_string());

            let coin_priv = message_box::PrivateKey::from_string(
              env::var(env_key_ref.to_string()).unwrap().to_string(),
            );

            let processor_id = retrieve_message_box_id(&coin_ref);

            let mut message_box_pubkeys = HashMap::new();
            message_box_pubkeys.insert(message_box::ids::COORDINATOR, pubkey);

            let message_box = MessageBox::new(processor_id, coin_priv, message_box_pubkeys);
            let encrypted_msg = str::from_utf8(value).unwrap();

            // Decrypt message using Message Box
            let encoded_string =
              message_box.decrypt_from_str(&message_box::ids::COORDINATOR, &encrypted_msg).unwrap();
            let decoded_string = String::from_utf8(encoded_string).unwrap();
            println!("Received Encrypted Message from {}", &key);
            println!("Decrypted Message: {}", &decoded_string);
          }
        }
      });
    }
    _ => {}
  }
}

// Create Pubkey Producer & sends pubkey message on public partiion 0
fn start_pubkey_producer(identity: &str, coin_hashmap: &HashMap<Coin, bool>) {
  let hashmap_clone = coin_hashmap.clone();
  // Loop through each coin & if active, create pubkey consumer
  for (key, value) in hashmap_clone.into_iter() {
    if *value == true {
      let mut topic: String = String::from(identity);
      topic.push_str("_");
      topic.push_str(&key.to_string());
      topic.push_str("_Topic");
      let env_key = &mut key.to_string();
      env_key.push_str("_PUB");
      let processor_id = retrieve_message_box_id(&key.to_string());
      send_pubkey_from_producer(&topic, env_key.to_string(), processor_id);
    }
  }
}

fn send_pubkey_from_producer(topic: &str, env_key: String, processor: &'static str) {
  let producer: ThreadedProducer<ProduceCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .create_with_context(ProduceCallbackLogger {})
    .expect("invalid producer config");

  // Load Pubkeys for processor
  let coin_pub = env::var(env_key.to_string());
  let coin_msg = coin_pub.unwrap();

  // Send pubkey to kafka topic
  producer
    .send(
      BaseRecord::to(&topic).key(&format!("{}_Pubkey", processor)).payload(&coin_msg).partition(0),
    )
    .expect("failed to send message");
  thread::sleep(Duration::from_secs(1));
}

// Wait to receive all Processer Pubkeys
fn process_received_pubkey() {
  // Runs a loop to check if Coordinator pubkey is found
  let mut coord_key_found = false;
  while !coord_key_found {
    let coord_pub_check = env::var("COORD_PUB");
    if !coord_pub_check.is_err() {
      println!("Coord Pubkey Ready");
      coord_key_found = true;
    } else {
      thread::sleep(Duration::from_secs(1));
    }
  }
}

// Create Hashmap based on coins
fn create_coin_hashmap(chain_config: &ChainConfig) -> HashMap<Coin, bool> {
  // Create Hashmap based on coins
  let j = serde_json::to_string(&chain_config).unwrap();
  let mut coins: HashMap<Coin, bool> = HashMap::new();
  let coins_ref: HashMap<String, bool> = serde_json::from_str(&j).unwrap();
  for (key, value) in coins_ref.into_iter() {
    if value == true {
      match key.as_str() {
        "sri" => {
          coins.insert(Coin::SRI, true);
        }
        "btc" => {
          coins.insert(Coin::BTC, true);
        }
        "eth" => {
          coins.insert(Coin::ETH, true);
        }
        "xmr" => {
          coins.insert(Coin::XMR, true);
        }
        &_ => {}
      };
    }
  }
  coins
}

// Requests Coin ID from Message Box
fn retrieve_message_box_id(coin: &String) -> &'static str {
  let id = match coin.as_str() {
    "SRI" => message_box::ids::SRI_PROCESSOR,
    "BTC" => message_box::ids::BTC_PROCESSOR,
    "ETH" => message_box::ids::ETH_PROCESSOR,
    "XMR" => message_box::ids::XMR_PROCESSOR,
    &_ => "",
  };
  id
}

// Create/Start Producer for each coin
fn start_pub_priv_producer(identity: &str, coin_hashmap: &HashMap<Coin, bool>) {
  let hashmap_clone = coin_hashmap.clone();

  // Loop through each coin & if active, create pubkey consumer
  for (key, value) in hashmap_clone.into_iter() {
    if *value == true {
      let mut topic: String = String::from(identity);
      topic.push_str("_");
      topic.push_str(&key.to_string());
      topic.push_str("_Topic");
      let env_key = &mut key.to_string();
      env_key.push_str("_PRIV");

      let processor_id = retrieve_message_box_id(&key.to_string());
      let mut msg: String = "".to_string();
      msg.push_str(&processor_id);
      msg.push_str(" message to COORDINATOR");

      send_message_from_pub_priv_producer(
        &topic,
        env_key.to_string(),
        &processor_id,
        msg.as_bytes().to_vec(),
      );
    }
  }
}

// Send a public message on partition 0 and encrytped message on partition 1
fn send_message_from_pub_priv_producer(
  topic: &str,
  env_key: String,
  processor: &'static str,
  msg: Vec<u8>,
) {
  let producer: ThreadedProducer<ProduceCallbackLogger> = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .create_with_context(ProduceCallbackLogger {})
    .expect("invalid producer config");

  // Load Coordinator private environment variable
  let coin_priv =
    message_box::PrivateKey::from_string(env::var(env_key.to_string()).unwrap().to_string());

  // Load Pubkeys for processors
  let pubkey =
    message_box::PublicKey::from_trusted_str(&env::var("COORD_PUB").unwrap().to_string());
  let mut message_box_pubkey = HashMap::new();
  message_box_pubkey.insert(message_box::ids::COORDINATOR, pubkey);

  // Create Coordinator Message Box
  let message_box = MessageBox::new(processor, coin_priv, message_box_pubkey);
  let enc = message_box.encrypt_to_string(&message_box::ids::COORDINATOR, &msg.clone());

  // Partition 0 is public
  producer
    .send(BaseRecord::to(&topic).key(&format!("{}_PUBLIC", &processor)).payload(&msg).partition(0))
    .expect("failed to send message");
  thread::sleep(Duration::from_secs(1));

  // Partition 1 is Private
  producer
    .send(BaseRecord::to(&topic).key(&format!("{}_PRIVATE", &processor)).payload(&enc).partition(1))
    .expect("failed to send message");
  thread::sleep(Duration::from_secs(1));
}

struct ConsumerCallbackLogger;

impl ClientContext for ConsumerCallbackLogger {}

impl ConsumerContext for ConsumerCallbackLogger {
  fn pre_rebalance<'a>(&self, _rebalance: &rdkafka::consumer::Rebalance<'a>) {}

  fn post_rebalance<'a>(&self, rebalance: &rdkafka::consumer::Rebalance<'a>) {
    //println!("post_rebalance callback");

    match rebalance {
      Rebalance::Assign(tpl) => {
        for e in tpl.elements() {
          //println!("rebalanced partition {}", e.partition())
        }
      }
      Rebalance::Revoke(tpl) => {
        //println!("ALL partitions have been REVOKED")
      }
      Rebalance::Error(err_info) => {
        //println!("Post Rebalance error {}", err_info)
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
              //println!("committed offset {:?} in partition {}", e.offset(), e.partition())
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
