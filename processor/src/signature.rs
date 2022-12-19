use std::collections::HashMap;
use std::{env, str, fmt};
use rdkafka::{
  producer::{BaseRecord, ThreadedProducer},
  consumer::{BaseConsumer, Consumer},
  ClientConfig, Message,
  admin::{AdminClient, TopicReplication, NewTopic, AdminOptions},
  client::DefaultClientContext,
};
use message_box::MessageBox;
use std::time::Duration;
use log::info;

use serde::{Deserialize};
use crate::core::ChainConfig;
use crate::core::KafkaConfig;

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
  kafka_config: KafkaConfig,
  identity: String,
}

fn create_config(kafka_config: &KafkaConfig) -> ClientConfig {
  let mut config = ClientConfig::new();
  config.set("bootstrap.servers", format!("{}:{}", kafka_config.host, kafka_config.port));
  config
}

fn create_admin_client(kafka_config: &KafkaConfig) -> AdminClient<DefaultClientContext> {
  create_config(kafka_config).create().expect("admin client creation failed")
}

// SignatureProcess communicates General & Secure Messages using Kafak
// General Messages will contain communicated pubkeys & general messages
// General Messages are contained in partition 0
// Secure Messages are contained in parition 1
impl SignatureProcess {
  pub fn new(chain_config: ChainConfig, kafka_config: KafkaConfig, identity: String) -> Self {
    info!("New Signature Process");
    Self { chain_config: chain_config, identity: identity, kafka_config: kafka_config }
  }

  pub async fn run(self) {
    info!("Starting Signature Process");

    // Check/initialize kakf topics
    let j = serde_json::to_string(&self.chain_config).unwrap();
    let mut topic_ref: HashMap<String, bool> = serde_json::from_str(&j).unwrap();
    topic_ref.insert(String::from(message_box::ids::COORDINATOR).to_lowercase(), true);

    let admin_client = create_admin_client(&self.kafka_config);
    let opts = AdminOptions::new().operation_timeout(Some(Duration::from_secs(1)));

    // Loop through each coin & initialize each kakfa topic
    for (_key, value) in topic_ref.into_iter() {
      let mut topic: String = "".to_string();
      topic.push_str(&self.identity);
      let topic_ref = &mut String::from(&_key);
      if topic_ref != &String::from(message_box::ids::COORDINATOR).to_lowercase() {
        *topic_ref = topic_ref.to_lowercase();
      }
      topic.push_str("_");
      topic.push_str(topic_ref);

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

    // Initialize consumers to read the coordinator pubkey on general partition
    consume_pubkey_coordinator(&self.kafka_config, &self.identity);

    // Initialize producer to send processor pubkeys to coordinator on general partition
    produce_processor_pubkey(&self.kafka_config, &self.identity, &coin_hashmap);

    // Wait to receive Coordinator Pubkey
    process_received_pubkey().await;

    // Initialize consumer used to read test messages from coordinator on general partition
    consume_coordinator_general_test_message(&self.kafka_config, &self.identity, &coin_hashmap);

    // Initialize consumer used to read secure test messages from coordinator on secure partition
    consume_coordinator_secure_test_message(&self.kafka_config, &self.identity, &coin_hashmap);

    // Initialize a producer that sends a general & secure test message
    produce_general_and_secure_test_message(&self.kafka_config, &self.identity, &coin_hashmap).await;
  }

  fn stop(self) {
    info!("Stopping Signature Process");
  }
}

// Initialize consumers to read the coordinator pubkey on general partition
fn consume_pubkey_coordinator(kafka_config: &KafkaConfig, identity: &str) {
  let mut group_id = String::from(identity);
      group_id.push_str("_coord_pubkey");

  let consumer: BaseConsumer = ClientConfig::new()
    .set("bootstrap.servers", format!("{}:{}", kafka_config.host, kafka_config.port))
    .set("group.id", &group_id)
    .set("auto.offset.reset", kafka_config.offset_reset.to_owned())
    .create()
    .expect("invalid consumer config");

  let mut tpl = rdkafka::topic_partition_list::TopicPartitionList::new();
  tpl.add_partition(&format!("{}_{}", &identity, String::from(message_box::ids::COORDINATOR).to_lowercase()), 0);
  consumer.assign(&tpl).unwrap();

  tokio::spawn(async move {
    for msg_result in &consumer {
      let msg = msg_result.unwrap();
      let key: &str = msg.key_view().unwrap().unwrap();
      let value = msg.payload().unwrap();
      let public_key = str::from_utf8(value).unwrap();
      info!("Received {} Public Key: {}", &key, &public_key);
      env::set_var("COORD_PUB", public_key);
    }
  });
}

// Initialize consumer used to read test messages from coordinator on general partition
fn consume_coordinator_general_test_message(kafka_config: &KafkaConfig, identity: &str, coin_hashmap: &HashMap<Coin, bool>) {
  let hashmap_clone = coin_hashmap.clone();

  // Loop through each coin & if active, create general message consumer
  for (_key, value) in hashmap_clone.into_iter() {
    if *value == true {
      let mut group_id = String::from(identity);
      group_id.push_str("_");
      group_id.push_str(&mut _key.to_string().to_lowercase());
      group_id.push_str("_general");
      let mut topic: String = String::from(identity);
      topic.push_str("_");
      topic.push_str(&_key.to_string().to_lowercase());
      initialize_consumer(kafka_config, &group_id, &topic, None, None, "general");
    }
  }
}

// Initialize consumer used to read secure test messages from coordinator on secure partition
fn consume_coordinator_secure_test_message(kafka_config: &KafkaConfig, identity: &str, coin_hashmap: &HashMap<Coin, bool>) {
  let hashmap_clone = coin_hashmap.clone();

  // Loop through each coin & if active, create secure message consumer
  for (_key, value) in hashmap_clone.into_iter() {
    if *value == true {
      let mut group_id = String::from(identity);
      group_id.push_str("_");
      group_id.push_str(&mut _key.to_string().to_lowercase());
      group_id.push_str("_secure");
      let mut topic: String = String::from(identity);
      topic.push_str("_");
      topic.push_str(&_key.to_string().to_lowercase());
      let env_key = &mut _key.to_string();
      env_key.push_str("_PRIV");
      initialize_consumer(
        kafka_config,
        &group_id,
        &topic,
        Some(env_key.to_string()),
        Some(&_key.to_string()),
        "secure",
      );
    }
  }
}

// Initializes consumer based on general or secure partition
fn initialize_consumer(
  kafka_config: &KafkaConfig,
  group_id: &str,
  topic: &str,
  env_key: Option<String>,
  coin: Option<&String>,
  consumer_type: &str,
) {
  let consumer: BaseConsumer = ClientConfig::new()
    .set("bootstrap.servers", format!("{}:{}", kafka_config.host, kafka_config.port))
    .set("group.id", group_id)
    .set("auto.offset.reset", kafka_config.offset_reset.to_owned())
    .create()
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
    "general" => {
      let mut tpl = rdkafka::topic_partition_list::TopicPartitionList::new();
      tpl.add_partition(&topic, 0);
      consumer.assign(&tpl).unwrap();

      tokio::spawn(async move {
        for msg_result in &consumer {
          let msg = msg_result.unwrap();
          let key: &str = msg.key_view().unwrap().unwrap();
          if key.contains(&String::from(message_box::ids::COORDINATOR).to_lowercase()) && key.contains("general") {
            let value = msg.payload().unwrap();
            let pub_msg = str::from_utf8(value).unwrap();
            info!("Received Public Message from {}", &key);
            info!("Public Message: {}", &pub_msg);
          }
        }
      });
    }
    "secure" => {
      let mut tpl = rdkafka::topic_partition_list::TopicPartitionList::new();
      tpl.add_partition(&topic, 1);
      consumer.assign(&tpl).unwrap();

      tokio::spawn(async move {
        for msg_result in &consumer {
          let msg = msg_result.unwrap();
          let key: &str = msg.key_view().unwrap().unwrap();
          if key.contains(&String::from(message_box::ids::COORDINATOR).to_lowercase()) {
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
            info!("Received Encrypted Message from {}", &key);
            info!("Decrypted Message: {}", &decoded_string);
          }
        }
      });
    }
    _ => {}
  }
}

// Initialize producer to send processor pubkeys to coordinator on general partition
fn produce_processor_pubkey(kafka_config: &KafkaConfig, identity: &str, coin_hashmap: &HashMap<Coin, bool>) {
  let hashmap_clone = coin_hashmap.clone();
  // Loop through each coin & if active, create producer and send processor pubkeys to coordinator
  for (_key, value) in hashmap_clone.into_iter() {
    if *value == true {
      let mut topic: String = String::from(identity);
      topic.push_str("_");
      topic.push_str(&_key.to_string().to_lowercase());
      let env_key = &mut _key.to_string();
      env_key.push_str("_PUB");
      let processor_id = retrieve_message_box_id(&_key.to_string());
      send_processor_pubkey(&kafka_config, &identity, &topic, env_key.to_string(), processor_id);
    }
  }
}

// Sends processor pubkeys to coordinator on general partition
fn send_processor_pubkey(kafka_config: &KafkaConfig, identity: &str, topic: &str, env_key: String, processor: &'static str) {
  let producer: ThreadedProducer<_> = ClientConfig::new()
    .set("bootstrap.servers", format!("{}:{}", kafka_config.host, kafka_config.port))
    .create()
    .expect("invalid producer config");

  // Load Processor Pubkeys
  let coin_pub = env::var(env_key.to_string());
  let coin_msg = coin_pub.unwrap();

  // Send pubkey to kafka topic
  producer
    .send(
      BaseRecord::to(&topic).key(&format!("{}_{}_pubkey", identity, String::from(processor).to_lowercase())).payload(&coin_msg).partition(0),
    )
    .expect("failed to send message");
}

// Wait to receive Coordinator Pubkey
async fn process_received_pubkey() {
  // Runs a loop to check if Coordinator pubkey is found
  let mut coord_key_found = false;
  while !coord_key_found {
    let coord_pub_check = env::var("COORD_PUB");
    if !coord_pub_check.is_err() {
      info!("Coord Pubkey Ready");
      coord_key_found = true;
    } else {
      // Add small delay for checking pubkeys
      tokio::time::sleep(Duration::from_millis(500)).await;
    }
  }
}

// Create Hashmap based on coins
fn create_coin_hashmap(chain_config: &ChainConfig) -> HashMap<Coin, bool> {
  let j = serde_json::to_string(&chain_config).unwrap();
  let mut coins: HashMap<Coin, bool> = HashMap::new();
  let coins_ref: HashMap<String, bool> = serde_json::from_str(&j).unwrap();
  for (_key, value) in coins_ref.into_iter() {
    if value == true {
      match _key.as_str() {
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

// Initialize a producer that sends a general & secure test message
async fn produce_general_and_secure_test_message(kafka_config: &KafkaConfig, identity: &str, coin_hashmap: &HashMap<Coin, bool>) {
  let hashmap_clone = coin_hashmap.clone();

  // Loop through each coin & if active, create general and secure producer
  for (_key, value) in hashmap_clone.into_iter() {
    if *value == true {
      let mut topic: String = String::from(identity);
      topic.push_str("_");
      topic.push_str(&_key.to_string().to_lowercase());
      let env_key = &mut _key.to_string();
      env_key.push_str("_PRIV");

      let processor_id = retrieve_message_box_id(&_key.to_string());
      let mut msg: String = "".to_string();
      msg.push_str(&processor_id.to_lowercase());
      msg.push_str(&format!(" message to {}", String::from(message_box::ids::COORDINATOR)).to_lowercase());

      send_general_and_secure_test_message(
        &kafka_config,
        &identity,
        &topic,
        env_key.to_string(),
        &processor_id,
        msg.as_bytes().to_vec(),
      ).await;
    }
  }
}

// Initializes a producer then sends both a general and secure test message
async fn send_general_and_secure_test_message(
  kafka_config: &KafkaConfig,
  identity: &str,
  topic: &str,
  env_key: String,
  processor: &'static str,
  msg: Vec<u8>,
) {
  let producer: ThreadedProducer<_> = ClientConfig::new()
    .set("bootstrap.servers", format!("{}:{}", kafka_config.host, kafka_config.port))
    .create()
    .expect("invalid producer config");

  // Load Processor private key environment variable
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

  // Parition 0 is General
  producer
    .send(BaseRecord::to(&topic).key(&format!("{}_{}_general", &identity, &String::from(processor).to_lowercase())).payload(&msg).partition(0))
    .expect("failed to send message");
    // Add small delay for sending messages
    tokio::time::sleep(Duration::from_millis(500)).await;

  // Partition 1 is Secure
  producer
    .send(BaseRecord::to(&topic).key(&format!("{}_{}_secure", &identity, &String::from(processor).to_lowercase())).payload(&enc).partition(1))
    .expect("failed to send message");
    // Add small delay for sending messages
    tokio::time::sleep(Duration::from_millis(500)).await;
}