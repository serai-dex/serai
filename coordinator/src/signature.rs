use std::collections::HashMap;
use std::{ env, str, fmt };
use rdkafka::{
    producer::{ BaseRecord, ThreadedProducer },
    consumer::{ BaseConsumer, Consumer },
    ClientConfig,
    Message,
    admin::{ AdminClient, TopicReplication, NewTopic, AdminOptions },
    client::DefaultClientContext,
};
use message_box::MessageBox;
use std::time::Duration;
use log::info;

use serde::{ Deserialize };
use crate::{ core::ChainConfig, core::KafkaConfig };

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
enum PartitionType {
    General,
    Secure,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SignatureProcess {
    chain_config: ChainConfig,
    kafka_config: KafkaConfig,
    name: String,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
enum Coin {
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
enum MessageType {
    CoordinatorPubkeyToProcessor,
    CoordinatorGeneralMessageToProcessor,
    CoordinatorSecureTestMessageToProcessor,
    ProcessorPubkeyToCoordinator,
    ProcessorGeneralMessageToCoordinator,
    ProcessorSecureTestMessageToCoordinator,
    Default,
}

impl fmt::Display for MessageType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MessageType::CoordinatorPubkeyToProcessor =>
                write!(f, "coordinator_pubkey_to_processor"),
            MessageType::CoordinatorGeneralMessageToProcessor => {
                write!(f, "coordinator_general_message_to_processor")
            }
            MessageType::CoordinatorSecureTestMessageToProcessor => {
                write!(f, "coordinator_secure_test_message_to_processor")
            }
            MessageType::ProcessorPubkeyToCoordinator =>
                write!(f, "processor_pubkey_to_coordinator"),
            MessageType::ProcessorGeneralMessageToCoordinator => {
                write!(f, "processor_general_message_to_coordinator")
            }
            MessageType::ProcessorSecureTestMessageToCoordinator => {
                write!(f, "processor_secure_test_message_to_coordinator")
            }
            MessageType::Default => write!(f, "Default"),
        }
    }
}

fn parse_message_type(message_type: &str) -> MessageType {
    let mut msg_type = MessageType::Default;
    match message_type {
        "coordinator_pubkey_to_processor" => {
            msg_type = MessageType::CoordinatorPubkeyToProcessor;
        }
        "coordinator_general_message_to_processor" => {
            msg_type = MessageType::CoordinatorGeneralMessageToProcessor;
        }
        "coordinator_secure_test_message_to_processor" => {
            msg_type = MessageType::CoordinatorSecureTestMessageToProcessor;
        }
        "processor_pubkey_to_coordinator" => {
            msg_type = MessageType::ProcessorPubkeyToCoordinator;
        }
        "processor_general_message_to_coordinator" => {
            msg_type = MessageType::ProcessorGeneralMessageToCoordinator;
        }
        "processor_secure_test_message_to_coordinator" => {
            msg_type = MessageType::ProcessorSecureTestMessageToCoordinator;
        }
        _ => {}
    }
    msg_type
}

// Configuration for admin client to check / initialize topics
fn create_config(kafka_config: &KafkaConfig) -> ClientConfig {
    let mut config = ClientConfig::new();
    config.set("bootstrap.servers", format!("{}:{}", kafka_config.host, kafka_config.port));
    config
}

// Creates admin client used to check / initialize topics
fn create_admin_client(kafka_config: &KafkaConfig) -> AdminClient<DefaultClientContext> {
    create_config(kafka_config).create().expect("admin client creation failed")
}

// SignatureProcess communicates General & Secure Messages using Kafka
// General Messages will contain communicated pubkeys & general messages
// General Messages are contained in partition 0
// Secure Messages are contained in parition 1
impl SignatureProcess {
    pub fn new(chain_config: ChainConfig, kafka_config: KafkaConfig, name: String) -> Self {
        info!("New Signature Process");
        let chain_config = chain_config;
        let kafka_config = kafka_config;
        Self { chain_config: chain_config, name: name, kafka_config: kafka_config }
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
                    self.name.to_string()
                ).await;
            }
        }
    }

    fn stop(self) {
        info!("Stopping Signature Process");
    }
}

// Spawn a thread for each coin that is active
async fn spawn_processor_thread(coin: String, kafka_config: KafkaConfig, name: String) {
    tokio::spawn(async move {
        // Initialize consumers to read the processor pubkey & general test messages on partition 0
        consume_general_messages_from_processor(&kafka_config, &name, &coin.to_string());

        // Initialize producer to send coordinator pubkey to processors on general partition
        produce_coordinator_pubkey(&kafka_config, &name, &coin.to_string());

    // Wait to receive Processer Pubkey
    process_received_pubkey(&coin.to_string(), &name).await;

        // Initialize consumer used to read secure test messages from processors on secure partition
        consume_processor_secure_test_message(&kafka_config, &name, &coin.to_string());

        // Initialize a producer that sends a general & secure test message
        produce_general_and_secure_test_message(&kafka_config, &name, &coin.to_string()).await;
    });
}

// Initialize consumers to read the processor pubkey & general test messages on partition 0
fn consume_general_messages_from_processor(kafka_config: &KafkaConfig, name: &str, coin: &str) {
  let mut group_id = &coin.to_string().to_lowercase();
  let mut topic: String = String::from(name);
  topic.push_str("_processor_");
  topic.push_str(&coin.to_string().to_lowercase());
  let env_key = &mut coin.to_string().to_owned().to_uppercase();
  env_key.push_str(format!("_{}_PUB", &name.to_string().to_uppercase()).as_str());
  initialize_consumer(
    kafka_config,
    &group_id,
    &topic,
    Some(env_key.to_string()),
    None,
    &PartitionType::General,
    &name,
  );
}

// Initialize consumer used to read secure test messages from processors on secure partition
fn consume_processor_secure_test_message(kafka_config: &KafkaConfig, name: &str, coin: &str) {
  let mut group_id = &coin.to_string().to_lowercase();
  let mut topic: String = String::from(name);
  topic.push_str("_processor_");
  topic.push_str(&coin.to_string().to_lowercase());
  // ENV_KEY references the processor pubkey we want to use with message box
  let env_key = &mut coin.to_string().to_uppercase();
  env_key.push_str(format!("_{}_PUB", &name.to_uppercase()).as_str());
  initialize_consumer(
    kafka_config,
    &group_id,
    &topic,
    Some(env_key.to_string()),
    Some(&mut coin.to_string()),
    &PartitionType::Secure,
    &name,
  );
}

// Initializes consumer based on general or secure partition
fn initialize_consumer(
  kafka_config: &KafkaConfig,
  group_id: &str,
  topic: &str,
  env_key: Option<String>,
  coin: Option<&String>,
  partition_type: &PartitionType,
  name: &str,
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

    match partition_type {
        PartitionType::General => {
            let mut tpl = rdkafka::topic_partition_list::TopicPartitionList::new();
            tpl.add_partition(&topic, 0);
            consumer.assign(&tpl).unwrap();

      tokio::spawn(async move {
        for msg_result in &consumer {
          let msg = msg_result.unwrap();
          let key: &str = msg.key_view().unwrap().unwrap();
          let msg_type = parse_message_type(&key);
          match msg_type {
            MessageType::ProcessorPubkeyToCoordinator => {
              let value = msg.payload().unwrap();
              let public_key = str::from_utf8(value).unwrap();
              info!("Received Pubkey from {}: {}", &key, &public_key);
              env::set_var(env_key_ref.clone(), public_key);
            }
            MessageType::ProcessorGeneralMessageToCoordinator => {
              let value = msg.payload().unwrap();
              let pub_msg = str::from_utf8(value).unwrap();
              info!("Received Public Message from {}", &key);
              info!("Public Message: {}", &pub_msg);
            }
            _ => {}
          }
        }
      });
    }
    PartitionType::Secure => {
      let mut tpl = rdkafka::topic_partition_list::TopicPartitionList::new();
      tpl.add_partition(&topic, 1);
      consumer.assign(&tpl).unwrap();

      let name_arg = name.to_owned();

      tokio::spawn(async move {
        for msg_result in &consumer {
          let msg = msg_result.unwrap();
          let key: &str = msg.key_view().unwrap().unwrap();
          let msg_type = parse_message_type(&key);
          match msg_type {
            MessageType::ProcessorSecureTestMessageToCoordinator => {
              let value = msg.payload().unwrap();
              // Creates Message box used for decryption
              let pubkey = message_box::PublicKey::from_trusted_str(
                &env::var(env_key_ref.to_string()).unwrap().to_string(),
              );

              let mut env_priv_key = "COORD".to_string();
              env_priv_key.push_str(format!("_{}_PRIV", &name_arg.to_uppercase()).as_str());

              let coord_priv =
                message_box::PrivateKey::from_string(env::var(env_priv_key).unwrap().to_string());

                            let processor_id = retrieve_message_box_id(&coin_ref);

                            let mut message_box_pubkeys = HashMap::new();
                            message_box_pubkeys.insert(processor_id, pubkey);

                            let message_box = MessageBox::new(
                                message_box::ids::COORDINATOR,
                                coord_priv,
                                message_box_pubkeys
                            );
                            let encrypted_msg = str::from_utf8(value).unwrap();

                            // Decrypt message using Message Box
                            let encoded_string = message_box
                                .decrypt_from_str(&processor_id, &encrypted_msg)
                                .unwrap();
                            let decoded_string = String::from_utf8(encoded_string).unwrap();
                            info!(
                                "Received Encrypted Message from {}",
                                &String::from(processor_id).to_lowercase()
                            );
                            info!("Decrypted Message: {}", &decoded_string);
                        }
                        _ => {}
                    }
                }
            });
        }
        _ => {}
    }
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
                .key(&format!("{}", MessageType::CoordinatorPubkeyToProcessor.to_string()))
                .payload(&msg)
                .partition(0)
        )
        .expect("failed to send message");
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
fn create_coin_hashmap(chain_config: &ChainConfig) -> HashMap<Coin, bool> {
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
        "SRI" => message_box::ids::SRI_PROCESSOR,
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
    coin: &str
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
  let coord_priv =
    message_box::PrivateKey::from_string(env::var(format!("COORD_{}_PRIV", &name.to_uppercase()).as_str()).unwrap().to_string());

    // Load Pubkeys for processors
    let pubkey = message_box::PublicKey::from_trusted_str(
        &env::var(env_key.to_string()).unwrap().to_string()
    );

    let mut message_box_pubkey = HashMap::new();
    message_box_pubkey.insert(processor, pubkey);

    // Create Procesor Message Box
    let message_box = MessageBox::new(
        message_box::ids::COORDINATOR,
        coord_priv,
        message_box_pubkey
    );
    let enc = message_box.encrypt_to_string(&processor, &msg.clone());

    // Partition 0 is General
    producer
        .send(
            BaseRecord::to(&topic)
                .key(&format!("{}", MessageType::CoordinatorGeneralMessageToProcessor.to_string()))
                .payload(&msg)
                .partition(0)
        )
        .expect("failed to send message");

    // Partition 1 is Secure
    producer
        .send(
            BaseRecord::to(&topic)
                .key(
                    &format!("{}", MessageType::CoordinatorSecureTestMessageToProcessor.to_string())
                )
                .payload(&enc)
                .partition(1)
        )
        .expect("failed to send message");

    // Add small delay for checking pubkeys
    tokio::time::sleep(Duration::from_millis(500)).await;
}