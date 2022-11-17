mod btc_kafka;
mod eth_kafka;
mod xmr_kafka;
mod substrate_kafka;
mod node_kafka;
mod coordinator_kafka;

pub fn start() {
  // Initialize BTC Kafka Consumer/Producer
  btc_kafka::start();

  // Initialize ETH Kafka Consumer/Producer
  eth_kafka::start();

  // Initialize XMR Kafka Consumer/Producer
  xmr_kafka::start();

  // Initialize Substrate Kafka Consumer/Producer
  substrate_kafka::start();

  // Initialize Node Kafka Consumer/Producer
  node_kafka::start();

  // Initialize Coordinator Kafka Consumer/Producer
  coordinator_kafka::start();
}
