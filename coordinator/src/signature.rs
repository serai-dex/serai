use std::collections::HashMap;
use std::{env, str, fmt};
use rdkafka::{
  producer::{BaseRecord, ThreadedProducer, Producer},
  consumer::{BaseConsumer, Consumer},
  ClientConfig, Message,
};
use message_box::MessageBox;
use std::time::Duration;
use log::info;

use serde::{Deserialize};
use crate::{core::ChainConfig, core::KafkaConfig};

#[derive(Clone, Debug, Deserialize)]
pub struct SignatureProcess {
  chain_config: ChainConfig,
  kafka_config: KafkaConfig,
  name: String,
  signers: Vec<config::Value>,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum Coin {
  BTC,
  ETH,
  XMR,
}

impl fmt::Display for Coin {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      Coin::BTC => write!(f, "BTC"),
      Coin::ETH => write!(f, "ETH"),
      Coin::XMR => write!(f, "XMR"),
    }
  }
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum SignatureMessageType {
  // The coordinator sends its public key to the processor.
  CoordinatorPubkeyToProcessor,

  // The coordinator sends a general message to the processor.
  CoordinatorGeneralMessageToProcessor,

  // The coordinator sends a secure test message to the processor.
  CoordinatorSecureTestMessageToProcessor,

  // The processor sends its public key to the coordinator.
  ProcessorPubkeyToCoordinator,

  // The processor sends a general message to the coordinator.
  ProcessorGeneralMessageToCoordinator,

  // The processor sends a secure test message to the coordinator.
  ProcessorSecureTestMessageToCoordinator,

  // The coordinator sends recieved processor pubkey to its processor.
  ProcessorPubkeyToProcessor,

  // The coordinator sends signer list to processor.
  CoordinatorSignerListToProcessor,

  // Default message type.
  Default,
}

impl fmt::Display for SignatureMessageType {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    match self {
      SignatureMessageType::CoordinatorPubkeyToProcessor => {
        write!(f, "coordinator_pubkey_to_processor")
      }
      SignatureMessageType::CoordinatorGeneralMessageToProcessor => {
        write!(f, "coordinator_general_message_to_processor")
      }
      SignatureMessageType::CoordinatorSecureTestMessageToProcessor => {
        write!(f, "coordinator_secure_test_message_to_processor")
      }
      SignatureMessageType::ProcessorPubkeyToCoordinator => {
        write!(f, "processor_pubkey_to_coordinator")
      }
      SignatureMessageType::ProcessorGeneralMessageToCoordinator => {
        write!(f, "processor_general_message_to_coordinator")
      }
      SignatureMessageType::ProcessorSecureTestMessageToCoordinator => {
        write!(f, "processor_secure_test_message_to_coordinator")
      }
      SignatureMessageType::ProcessorPubkeyToProcessor => {
        write!(f, "processor_pubkey_to_processor")
      }
      SignatureMessageType::CoordinatorSignerListToProcessor => {
        write!(f, "coordinator_signer_list_to_processor")
      }
      SignatureMessageType::Default => write!(f, "Default"),
    }
  }
}

// Parses the message type from a string to a SignatureMessageType.
// The message type is used to determine which type of message is being sent
// to the coordinator.
pub fn parse_message_type(message_type: &str) -> SignatureMessageType {
  let mut msg_type = SignatureMessageType::Default;
  match message_type {
    "coordinator_pubkey_to_processor" => {
      msg_type = SignatureMessageType::CoordinatorPubkeyToProcessor;
    }
    "coordinator_general_message_to_processor" => {
      msg_type = SignatureMessageType::CoordinatorGeneralMessageToProcessor;
    }
    "coordinator_secure_test_message_to_processor" => {
      msg_type = SignatureMessageType::CoordinatorSecureTestMessageToProcessor;
    }
    "processor_pubkey_to_coordinator" => {
      msg_type = SignatureMessageType::ProcessorPubkeyToCoordinator;
    }
    "processor_general_message_to_coordinator" => {
      msg_type = SignatureMessageType::ProcessorGeneralMessageToCoordinator;
    }
    "processor_secure_test_message_to_coordinator" => {
      msg_type = SignatureMessageType::ProcessorSecureTestMessageToCoordinator;
    }
    "coordinator_signer_list_to_processor" => {
      msg_type = SignatureMessageType::CoordinatorSignerListToProcessor;
    }
    _ => {}
  }
  msg_type
}

// SignatureProcess communicates General & Secure Messages using Kafka
// General Messages will contain communicated pubkeys & general messages
// General Messages are contained in partition 0
// Secure Messages are contained in parition 1
impl SignatureProcess {
  pub fn new(
    chain_config: ChainConfig,
    kafka_config: KafkaConfig,
    name: String,
    signers: Vec<config::Value>,
  ) -> Self {
    info!("New Signature Process");
    let chain_config = chain_config;
    let kafka_config = kafka_config;
    let signers = signers;
    Self { chain_config: chain_config, name: name, kafka_config: kafka_config, signers: signers }
  }

  pub async fn run(self) {
    info!("Starting Signature Process");

    // Create Hashmap based on coins
    let coin_hashmap = create_coin_hashmap(&self.chain_config);

    info!("Spawning Processor Threads");
    // Loop through each coin & if active, create processor thread
    for (_key, value) in coin_hashmap.into_iter() {
      if value == true {
        spawn_processor_thread(
          _key.to_string().to_owned(),
          self.kafka_config.clone().to_owned(),
          self.name.to_string(),
          self.signers.clone(),
        )
        .await;
      }
    }
  }

  fn stop(self) {
    info!("Stopping Signature Process");
  }
}

// Spawn a thread for each coin that is active
async fn spawn_processor_thread(
  coin: String,
  kafka_config: KafkaConfig,
  name: String,
  signers: Vec<config::Value>,
) {
  tokio::spawn(async move {
    // Send signers to processor
    send_signers_to_processor(&kafka_config, &name, &coin.to_string(), &signers).await;

    // Initialize consumers to read the processor pubkey, general/secure test messages
    consume_messages_from_processor(&kafka_config, &name, &coin.to_string());

    // Initialize producer to send coordinator pubkey to processors on general partition
    produce_coordinator_pubkey(&kafka_config, &name, &coin.to_string());

    // Wait to receive Processer Pubkey
    process_received_pubkey(&coin.to_string(), &name).await;

    // Initialize a producer that sends a general & secure test message
    produce_general_and_secure_test_message(&kafka_config, &name, &coin.to_string()).await;
  });
}

// Initialize consumers to read the processor pubkey, general/secure test messages
fn consume_messages_from_processor(kafka_config: &KafkaConfig, name: &str, coin: &str) {
  let group_id = &mut name.to_string().to_lowercase();
  group_id.push_str("_coordinator_");
  group_id.push_str(&mut coin.to_owned().to_string().to_lowercase());
  let mut topic: String = String::from(name);
  topic.push_str("_processor_");
  topic.push_str(&coin.to_string().to_lowercase());
  let pub_env_key = &mut coin.to_string().to_owned().to_uppercase();
  pub_env_key.push_str(format!("_{}_PUB", &name.to_uppercase()).as_str());
  let priv_env_key = &mut coin.to_string().to_owned().to_uppercase();
  priv_env_key.push_str(format!("_{}_PRIV", &name.to_uppercase()).as_str());
  initialize_consumer(
    kafka_config,
    &group_id,
    &topic,
    Some(pub_env_key.to_string()),
    Some(priv_env_key.to_string()),
    Some(&coin.to_string()),
    &name,
  );
}

// Initializes consumer based on general or secure partition
fn initialize_consumer(
  kafka_config: &KafkaConfig,
  group_id: &str,
  topic: &str,
  pub_env_key: Option<String>,
  priv_env_key: Option<String>,
  coin: Option<&String>,
  name: &str,
) {
  let consumer: BaseConsumer = ClientConfig::new()
    .set("bootstrap.servers", format!("{}:{}", kafka_config.host, kafka_config.port))
    .set("group.id", group_id)
    .set("auto.offset.reset", kafka_config.offset_reset.to_owned())
    .create()
    .expect("invalid consumer config");

  let mut pub_env_key_ref: String = "".to_string();
  match pub_env_key {
    Some(p) => {
      pub_env_key_ref = String::from(p);
    }
    None => {}
  }

  let mut priv_env_key_ref: String = "".to_string();
  match priv_env_key {
    Some(p) => {
      priv_env_key_ref = String::from(p);
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

  let mut tpl = rdkafka::topic_partition_list::TopicPartitionList::new();
  tpl.add_partition(&topic, 0);
  tpl.add_partition(&topic, 1);
  consumer.assign(&tpl).unwrap();

  let name_arg = name.to_owned();
  tokio::spawn(async move {
    for msg_result in &consumer {
      let msg = msg_result.unwrap();
      let key: &str = msg.key_view().unwrap().unwrap();
      let msg_type = parse_message_type(&key);
      match msg_type {
        SignatureMessageType::ProcessorPubkeyToCoordinator => {
          let value = msg.payload().unwrap();
          let public_key = str::from_utf8(value).unwrap();
          info!("Received Pubkey from {}: {}", &key, &public_key);
          env::set_var(pub_env_key_ref.clone(), public_key);
        }
        SignatureMessageType::ProcessorGeneralMessageToCoordinator => {
          let value = msg.payload().unwrap();
          let pub_msg = str::from_utf8(value).unwrap();
          info!("Received Public Message from {}", &key);
          info!("Public Message: {}", &pub_msg);
        }
        SignatureMessageType::ProcessorSecureTestMessageToCoordinator => {
          let value = msg.payload().unwrap();
          // Creates Message box used for decryption
          let pubkey = message_box::PublicKey::from_trusted_str(
            &env::var(pub_env_key_ref.to_string()).unwrap().to_string(),
          );

          let mut env_priv_key = "COORD".to_string();
          env_priv_key.push_str(format!("_{}_PRIV", &name_arg.to_uppercase()).as_str());

          let coord_priv =
            message_box::PrivateKey::from_string(env::var(env_priv_key).unwrap().to_string());

          let processor_id = retrieve_message_box_id(&coin_ref);

          let mut message_box_pubkeys = HashMap::new();
          message_box_pubkeys.insert(processor_id, pubkey);

          let message_box =
            MessageBox::new(message_box::ids::COORDINATOR, coord_priv, message_box_pubkeys);
          let encrypted_msg = str::from_utf8(value).unwrap();

          // Decrypt message using Message Box
          let encoded_string = message_box.decrypt_from_str(&processor_id, &encrypted_msg).unwrap();
          let decoded_string = String::from_utf8(encoded_string).unwrap();
          info!("Received Encrypted Message from {}", &String::from(processor_id).to_lowercase());
          info!("Decrypted Message: {}", &decoded_string);
        }
        _ => {}
      }
    }
  });
}

// Initialize producer to send coordinator pubkey to processors on general partition
fn produce_coordinator_pubkey(kafka_config: &KafkaConfig, name: &str, coin: &str) {
  info!("Sending Public Key to {}", coin);

  // Creates a producer to send coordinator pubkey message
  let producer: ThreadedProducer<_> = ClientConfig::new()
    .set("bootstrap.servers", format!("{}:{}", kafka_config.host, kafka_config.port))
    .create()
    .expect("invalid producer config");

  // Load Coordinator Pubkey
  let mut env_key = "COORD".to_string();
  env_key.push_str(format!("_{}_PUB", &name.to_uppercase()).as_str());
  let coord_pub = env::var(env_key);
  let msg = coord_pub.unwrap();

  // Sends message to Kafka
  producer
    .send(
      BaseRecord::to(&format!("{}_processor_{}", &name, &coin.to_string().to_lowercase()))
        .key(&format!("{}", SignatureMessageType::CoordinatorPubkeyToProcessor.to_string()))
        .payload(&msg)
        .partition(0),
    )
    .expect("failed to send message");

  // Flushes producer
  producer.flush(Duration::from_secs(10));
}

// Wait to receive all Processer Pubkeys
async fn process_received_pubkey(coin: &str, name: &str) {
  let mut pubkey_found = false;
  while !pubkey_found {
    let env_key = &mut coin.to_string().to_uppercase();

    env_key.push_str(format!("_{}_PUB", name.to_uppercase()).as_str());

    let pub_check = env::var(env_key);
    if !pub_check.is_err() {
      pubkey_found = true;
      info!("{} Processor Pubkey Ready", &coin.to_string().to_uppercase());
    } else {
      // Add small delay for checking pubkeys
      tokio::time::sleep(Duration::from_millis(500)).await;
    }
  }
}

// Create Hashmap based on coins
pub fn create_coin_hashmap(chain_config: &ChainConfig) -> HashMap<Coin, bool> {
  let j = serde_json::to_string(&chain_config).unwrap();
  let mut coins: HashMap<Coin, bool> = HashMap::new();
  let coins_ref: HashMap<String, bool> = serde_json::from_str(&j).unwrap();
  for (key, value) in coins_ref.into_iter() {
    if value == true {
      match key.as_str() {
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
      }
    }
  }
  coins
}

// Requests Coin ID from Message Box
fn retrieve_message_box_id(coin: &String) -> &'static str {
  let id = match coin.as_str() {
    "BTC" => message_box::ids::BTC_PROCESSOR,
    "ETH" => message_box::ids::ETH_PROCESSOR,
    "XMR" => message_box::ids::XMR_PROCESSOR,
    &_ => "",
  };
  id
}

// Initialize a producer that sends a general & secure test message
async fn produce_general_and_secure_test_message(
  kafka_config: &KafkaConfig,
  name: &str,
  coin: &str,
) {
  let mut topic: String = String::from(name);
  topic.push_str("_processor_");
  topic.push_str(&coin.to_string().to_lowercase());
  let env_key = &mut coin.to_string();
  env_key.push_str(format!("_{}_PUB", &name.to_uppercase()).as_str());

  let processor_id = retrieve_message_box_id(&mut coin.to_string().to_uppercase());
  let mut msg: String = String::from("coordinator message to ");
  msg.push_str(&processor_id.to_lowercase());

  send_general_and_secure_test_message(
    &kafka_config,
    &topic,
    env_key.to_string(),
    &processor_id,
    msg.as_bytes().to_vec(),
    &name,
  )
  .await;
}

// Initializes a producer then sends both a general and secure test message
async fn send_general_and_secure_test_message(
  kafka_config: &KafkaConfig,
  topic: &str,
  env_key: String,
  processor: &'static str,
  msg: Vec<u8>,
  name: &str,
) {
  let producer: ThreadedProducer<_> = ClientConfig::new()
    .set("bootstrap.servers", format!("{}:{}", kafka_config.host, kafka_config.port))
    .create()
    .expect("invalid producer config");

  // Load Coordinator private key environment variable
  let coord_priv = message_box::PrivateKey::from_string(
    env::var(format!("COORD_{}_PRIV", &name.to_uppercase()).as_str()).unwrap().to_string(),
  );

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
        .key(&format!("{}", SignatureMessageType::CoordinatorGeneralMessageToProcessor.to_string()))
        .payload(&msg)
        .partition(0),
    )
    .expect("failed to send message");

  // Partition 1 is Secure
  producer
    .send(
      BaseRecord::to(&topic)
        .key(&format!(
          "{}",
          SignatureMessageType::CoordinatorSecureTestMessageToProcessor.to_string()
        ))
        .payload(&enc)
        .partition(1),
    )
    .expect("failed to send message");

  // Flushes producer
  producer.flush(Duration::from_secs(10));

  // Add small delay for checking pubkeys
  tokio::time::sleep(Duration::from_millis(500)).await;
}

// Send signers to processor
async fn send_signers_to_processor(
  kafka_config: &KafkaConfig,
  name: &String,
  coin: &String,
  signers: &Vec<config::Value>,
) {
  // Create message containing signers
  let mut signers_list = Vec::new();
  for signer in signers {
    signers_list.push(signer.to_string());
  }

  let msg = serde_json::to_string(&signers_list).unwrap();

  let producer: ThreadedProducer<_> = ClientConfig::new()
    .set("bootstrap.servers", format!("{}:{}", kafka_config.host, kafka_config.port))
    .create()
    .expect("invalid producer config");

  // Sends message to Kafka
  producer
    .send(
      BaseRecord::to(&format!("{}_processor_{}", &name, &coin.to_string().to_lowercase()))
        .key(&format!("{}", SignatureMessageType::CoordinatorSignerListToProcessor.to_string()))
        .payload(&msg)
        .partition(0),
    )
    .expect("failed to send message");

  // Flushes producer
  producer.flush(Duration::from_secs(10));
}
