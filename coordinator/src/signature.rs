use std::{thread, collections::HashMap};
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

use serde::{Deserialize};
use crate::CoordinatorConfig;
use crate::core::ChainConfig;
use crate::core::KafkaConfig;

#[derive(Clone, Debug, Deserialize)]
pub struct SignatureProcess {
  chain_config: ChainConfig,
  kafka_config: KafkaConfig,
  identity: String,
}

#[derive(Debug, PartialEq, Eq, Hash)]
enum Coin{
  SRI,
  BTC,
  ETH,
  XMR
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

// Configuration for admin client to check / initialize topics
fn create_config(server: &String) -> ClientConfig {
  let mut config = ClientConfig::new();
  config.set("bootstrap.servers", server);
  config
}

// Creates admin client used to check / initialize topics
fn create_admin_client(server: &String) -> AdminClient<DefaultClientContext> {
  create_config(server)
      .create()
      .expect("admin client creation failed")
}

// SignatureProcess communicates General & Secure Messages using Kafka
// General Messages will contain communicated pubkeys & general messages
// General Messages are contained in partition 0
// Secure Messages are contained in parition 1
impl SignatureProcess {
  pub fn new(config: CoordinatorConfig, identity: String) -> Self {
    println!("New Signature Process");
    let chain_config = config.get_chain();
    let kafka_config = config.get_kafka();
    Self { chain_config: chain_config, identity: identity, kafka_config: kafka_config}
  }

  pub async fn run(self) {
    println!("Starting Signature Process");

    let kafka_server = &self.kafka_config.server;

    // Check/initialize kakf topics
    let j = serde_json::to_string(&self.chain_config).unwrap();
    let mut topic_ref: HashMap<String, bool> = serde_json::from_str(&j).unwrap();
    topic_ref.insert("Coordinator".to_string(), true);

    let admin_client = create_admin_client(&kafka_server);
    let opts = AdminOptions::new().operation_timeout(Some(Duration::from_secs(1)));
  
    // Loop through each coin & initialize each kakfa topic
    for (_key, value) in topic_ref.into_iter() {
      let mut topic: String = "".to_string();
      topic.push_str(&self.identity);
      let topic_ref = &mut String::from(&_key);
      if topic_ref != "Coordinator"{
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

    // Initialize consumers to read processor pubkeys on general partition
    consume_pubkey_processor(&kafka_server, &self.identity, &coin_hashmap);

    // Initialize producer to send coordinator pubkey to processors on general partition
    produce_coordinator_pubkey(&kafka_server, &self.identity);

    // Wait to receive all Processer Pubkeys
    process_received_pubkeys(&coin_hashmap).await;

    // Initialize consumer used to read test messages from processors on general partition
    consume_processor_general_test_message(&kafka_server, &self.identity, &coin_hashmap);

    // Initialize consumer used to read secure test messages from processors on secure partition
    consume_processor_secure_test_message(&kafka_server, &self.identity, &coin_hashmap);

    // Initialize a producer that sends a general & secure test message
    produce_general_and_secure_test_message(&kafka_server, &self.identity, &coin_hashmap).await;
  }

  fn stop(self) {
    println!("Stopping Signature Process");
  }
}

// Initialize consumers to read processor pubkeys on general partition
fn consume_pubkey_processor(server: &str, identity: &str, coin_hashmap: &HashMap<Coin, bool>) {
  let hashmap_clone = coin_hashmap.clone();

  // Loop through each coin & if active, create pubkey consumer
  for (_key, value) in hashmap_clone.into_iter() {
    if *value == true {
      let mut group_id = String::from(identity);
      group_id.push_str("_");
      group_id.push_str(&mut _key.to_string());
      group_id.push_str("_PUBKEY");
      let mut topic: String = String::from(identity);
      topic.push_str("_");
      topic.push_str(&_key.to_string());
      topic.push_str("_Topic");
      let env_key = &mut _key.to_string().to_owned();
      env_key.push_str("_PUB");
      initialize_consumer(&server, &group_id, &topic, Some(env_key.to_string()), None, "general");
    }
  }
}

// Initialize consumer used to read test messages from processors on general partition
fn consume_processor_general_test_message(server: &str, identity: &str, coin_hashmap: &HashMap<Coin, bool>) {
  let hashmap_clone = coin_hashmap.clone();

  // Loop through each coin & if active, create general message consumer
  for (_key, value) in hashmap_clone.into_iter() {
    if *value == true {
      let mut group_id = String::from(identity);
      group_id.push_str("_");
      group_id.push_str(&mut _key.to_string());
      group_id.push_str("_GENERAL");
      let mut topic: String = String::from(identity);
      topic.push_str("_");
      topic.push_str(&_key.to_string());
      topic.push_str("_Topic");
      initialize_consumer(&server, &group_id, &topic, None, None, "general");
    }
  }
}

// Initialize consumer used to read secure test messages from processors on secure partition
fn consume_processor_secure_test_message(server: &str, identity: &str, coin_hashmap: &HashMap<Coin, bool>) {
  let hashmap_clone = coin_hashmap.clone();

  // Loop through each coin & if active, create secure message consumer
  for (key, value) in hashmap_clone.into_iter() {
    if *value == true {
      let mut group_id = String::from(identity);
      group_id.push_str("_");
      group_id.push_str(&mut key.to_string());
      group_id.push_str("_SECURE");
      let mut topic: String = String::from(identity);
      topic.push_str("_");
      topic.push_str(&key.to_string());
      topic.push_str("_Topic");
      let env_key = &mut key.to_string();
      // ENV_KEY references the processor pubkey we want to use with message box
      env_key.push_str("_PUB");
      initialize_consumer(&server, &group_id, &topic, Some(env_key.to_string()), Some(&mut key.to_string()), "secure");
    }
  }
}

// Initializes consumer based on general or secure partition
fn initialize_consumer(
  server: &str,
  group_id: &str,
  topic: &str,
  env_key: Option<String>,
  coin: Option<&String>,
  consumer_type: &str,
) {
  let consumer: BaseConsumer = ClientConfig::new()
    .set("bootstrap.servers", server)
    .set("group.id", group_id)
    .set("auto.offset.reset", "smallest")
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

      thread::spawn(move || {
        for msg_result in &consumer {
          let msg = msg_result.unwrap();
          let key: &str = msg.key_view().unwrap().unwrap();
          if !key.contains("COORDINATOR") && key.contains("PUBKEY") && env_key_ref != "" {
            let value = msg.payload().unwrap();
            let public_key = str::from_utf8(value).unwrap();
            println!("Received Pubkey from {}: {}", &key, &public_key);
            env::set_var(env_key_ref.clone(), public_key);
          } else if !key.contains("COORDINATOR") && key.contains("GENERAL") && env_key_ref == "" {
            let value = msg.payload().unwrap();
            let pub_msg = str::from_utf8(value).unwrap();
            println!("Received Public Message from {}", &key);
            println!("Public Message: {}", &pub_msg);
          }
        }
      });
    }
    "secure" => {
      let mut tpl = rdkafka::topic_partition_list::TopicPartitionList::new();
      tpl.add_partition(&topic, 1);
      consumer.assign(&tpl).unwrap();

      thread::spawn(move || {
        for msg_result in &consumer {
          let msg = msg_result.unwrap();
          let key: &str = msg.key_view().unwrap().unwrap();
          if !key.contains("COORDINATOR") {
            let value = msg.payload().unwrap();
            // Creates Message box used for decryption
            let pubkey = message_box::PublicKey::from_trusted_str(
              &env::var(env_key_ref.to_string()).unwrap().to_string(),
            );

            let coord_priv =
              message_box::PrivateKey::from_string(env::var("COORD_PRIV").unwrap().to_string());

            let processor_id = retrieve_message_box_id(&coin_ref);

            let mut message_box_pubkeys = HashMap::new();
            message_box_pubkeys.insert(processor_id, pubkey);

            let message_box =
              MessageBox::new(message_box::ids::COORDINATOR, coord_priv, message_box_pubkeys);
            let encrypted_msg = str::from_utf8(value).unwrap();

            // Decrypt message using Message Box
            let encoded_string =
              message_box.decrypt_from_str(&processor_id, &encrypted_msg).unwrap();
            let decoded_string = String::from_utf8(encoded_string).unwrap();
            println!("Received Encrypted Message from {}", &processor_id);
            println!("Decrypted Message: {}", &decoded_string);
          }
        }
      });
    }
    _ => {}
  }
}

// Initialize producer to send coordinator pubkey to processors on general partition
fn produce_coordinator_pubkey(server: &str, identity: &str) {
  // Creates a producer to send coordinator pubkey message
  let producer: ThreadedProducer<_> = ClientConfig::new()
    .set("bootstrap.servers", server)
    .create()
    .expect("invalid producer config");

  println!("Sending Public Key");

  // Load Coordinator Pubkey
  let coord_pub = env::var("COORD_PUB");
  let msg = coord_pub.unwrap();

  // Sends message to Kafka
  producer
    .send(
      BaseRecord::to(&format!("{}_Coordinator_Topic", &identity))
        .key(&format!("{}_PUBKEY", message_box::ids::COORDINATOR))
        .payload(&msg).partition(0),
    )
    .expect("failed to send message");
}

// Wait to receive all Processer Pubkeys
async fn process_received_pubkeys(coin_hashmap: &HashMap<Coin, bool>) {
  // Runs a loop to check if all processor keys are found
  let mut all_keys_found = false;
  while !all_keys_found {
    let hashmap_key_check = coin_hashmap.clone();
    let hashmap_clone = coin_hashmap.clone();

    let mut active_keys = 0;
    let mut keys_found = 0;
    for (_key, value) in hashmap_key_check.into_iter() {
      if *value == true {
        active_keys += 1;
      }
    }

    for (_key, value) in hashmap_clone.into_iter() {
      if *value == true {
        let mut env_key = &mut _key.to_string();
        env_key.push_str("_PUB");

        let pub_check = env::var(env_key);
        if (!pub_check.is_err()) {
          keys_found += 1;
        }
      }
    }

    if active_keys == keys_found {
      println!("All Processor Pubkeys Ready");
      all_keys_found = true;
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
  for (key, value) in coins_ref.into_iter() {
    if value == true {
      match key.as_str() {
        "sri" => {
          coins.insert(Coin::SRI, true);
        },
        "btc" => {
          coins.insert(Coin::BTC, true);
        },
        "eth" => {
          coins.insert(Coin::ETH, true);
        },
        "xmr" => {
          coins.insert(Coin::XMR, true);
        },
        &_ => {},
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
async fn produce_general_and_secure_test_message(server: &str, identity: &str, coin_hashmap: &HashMap<Coin, bool>) {
  let hashmap_clone = coin_hashmap.clone();

  // Loop through each coin & if active, create general and secure producer
  for (key, value) in hashmap_clone.into_iter() {
    if *value == true {
      let mut topic: String = String::from(identity);
      topic.push_str("_");
      topic.push_str(&key.to_string());
      topic.push_str("_Topic");
      let env_key = &mut key.to_string();
      env_key.push_str("_PUB");

      let processor_id = retrieve_message_box_id(&mut key.to_string());
      let mut msg: String = String::from("COORDINATOR message to ");
      msg.push_str(processor_id);

      send_general_and_secure_test_message(
        &server,
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
  server: &str,
  identity: &str,
  topic: &str,
  env_key: String,
  processor: &'static str,
  msg: Vec<u8>,
) {
  let producer: ThreadedProducer<_> = ClientConfig::new()
    .set("bootstrap.servers", server)
    .create()
    .expect("invalid producer config");

  // Load Coordinator private key environment variable
  let coord_priv =
    message_box::PrivateKey::from_string(env::var("COORD_PRIV").unwrap().to_string());

  // Load Pubkeys for processors
  let pubkey =
    message_box::PublicKey::from_trusted_str(&env::var(env_key.to_string()).unwrap().to_string());

  let mut message_box_pubkey = HashMap::new();
  message_box_pubkey.insert(processor, pubkey);

  // Create Procesor Message Box
  let message_box = MessageBox::new(message_box::ids::COORDINATOR, coord_priv, message_box_pubkey);
  let enc = message_box.encrypt_to_string(&processor, &msg.clone());

  // Partition 0 is General
  producer
    .send(
      BaseRecord::to(&topic)
        .key(&format!("{}_{}_GENERAL", identity, message_box::ids::COORDINATOR))
        .payload(&msg)
        .partition(0),
    )
    .expect("failed to send message");
    // Add small delay for sending messages
    tokio::time::sleep(Duration::from_millis(500)).await;

  // Partition 1 is Secure
  producer
    .send(
      BaseRecord::to(&topic)
        .key(&format!("{}_{}_SECURE", identity, message_box::ids::COORDINATOR))
        .payload(&enc)
        .partition(1),
    )
    .expect("failed to send message");
    // Add small delay for sending messages
    tokio::time::sleep(Duration::from_millis(500)).await;
}
