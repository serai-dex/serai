use rdkafka::config::ClientConfig;
use rdkafka::consumer::{CommitMode, Consumer, StreamConsumer};
use rdkafka::message::{Headers, Message};
use rdkafka::producer::{FutureProducer, FutureRecord};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use async_std::stream::StreamExt;
use std::process;
use futures::future::ready;
use log::{info, warn};

// Test Criteria:
// Need to have more control when reading messages
// Try using a StreamConsumer to achieve this
// Then read meta data in preperation for next text
// Next Test will be message consumption based on consumer
// Single topic with 2 producer/consumer pairs both sending/consuming messages based on meta data 

pub async fn start() {
  let consumer: StreamConsumer = ClientConfig::new()
    .set("bootstrap.servers", "localhost:9094")
    .set("session.timeout.ms", "6000")
    .set("enable.auto.commit", "false")
    .set("group.id", "serai")
    .create()
    .expect("Consumer creation failed");
  consumer.subscribe(&["meta_test_topic"]).unwrap();

  loop {
    match consumer.recv().await {
        Err(e) => warn!("Kafka error: {}", e),
        Ok(m) => {
            let payload = match m.payload_view::<str>() {
                None => "",
                Some(Ok(s)) => s,
                Some(Err(e)) => {
                    warn!("Error while deserializing message payload: {:?}", e);
                    ""
                }
            };
            info!("key: '{:?}', payload: '{}', topic: {}, partition: {}, offset: {}, timestamp: {:?}",
                  m.key(), payload, m.topic(), m.partition(), m.offset(), m.timestamp());
            consumer.commit_message(&m, CommitMode::Async).unwrap();
        }
    };
}
}


