#![allow(dead_code)]
//! Test administrative commands using the admin API.

use std::time::Duration;
use std::collections::HashMap;
use std::env::{self, VarError};


use backoff::{ExponentialBackoff, Operation};

use rdkafka::admin::{
    AdminClient, AdminOptions, AlterConfig, ConfigEntry, ConfigSource, NewPartitions,
    NewTopic, OwnedResourceSpecifier, ResourceSpecifier, TopicReplication,
};
use rdkafka::client::DefaultClientContext;
use rdkafka::consumer::{BaseConsumer, CommitMode, Consumer, DefaultConsumerContext};
use rdkafka::error::{KafkaError, RDKafkaErrorCode};
use rdkafka::metadata::Metadata;
use rdkafka::{ClientConfig, TopicPartitionList};

use rand::Rng;
use regex::Regex;

use rdkafka::client::ClientContext;
use rdkafka::consumer::ConsumerContext;
use rdkafka::error::KafkaResult;
use rdkafka::message::ToBytes;
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::statistics::Statistics;


fn create_config() -> ClientConfig {
    let mut config = ClientConfig::new();
    config.set("bootstrap.servers", get_bootstrap_server().as_str());
    config
}

fn create_admin_client() -> AdminClient<DefaultClientContext> {
    create_config()
        .create()
        .expect("admin client creation failed")
}

async fn create_consumer_group(consumer_group_name: &str) {
    let admin_client = create_admin_client();
    let topic_name = &rand_test_topic();
    let consumer: BaseConsumer = create_config()
        .set("group.id", consumer_group_name.clone())
        .create()
        .expect("create consumer failed");

    admin_client
        .create_topics(
            &[NewTopic {
                name: topic_name,
                num_partitions: 1,
                replication: TopicReplication::Fixed(1),
                config: vec![],
            }],
            &AdminOptions::default(),
        )
        .await
        .expect("topic creation failed");
    let topic_partition_list = {
        let mut lst = TopicPartitionList::new();
        lst.add_partition(topic_name, 0);
        lst
    };
    consumer
        .assign(&topic_partition_list)
        .expect("assign topic partition list failed");
    consumer
        .fetch_metadata(None, Duration::from_secs(3))
        .expect("unable to fetch metadata");
    consumer
        .store_offset(topic_name, 0, -1)
        .expect("store offset failed");
    consumer
        .commit_consumer_state(CommitMode::Sync)
        .expect("commit the consumer state failed");
}

fn fetch_metadata(topic: &str) -> Metadata {
    let consumer: BaseConsumer<DefaultConsumerContext> =
        create_config().create().expect("consumer creation failed");
    let timeout = Some(Duration::from_secs(1));

    let mut backoff = ExponentialBackoff::default();
    backoff.max_elapsed_time = Some(Duration::from_secs(5));
    (|| {
        let metadata = consumer
            .fetch_metadata(Some(topic), timeout)
            .map_err(|e| e.to_string())?;
        if metadata.topics().len() == 0 {
            Err("metadata fetch returned no topics".to_string())?
        }
        let topic = &metadata.topics()[0];
        if topic.partitions().len() == 0 {
            Err("metadata fetch returned a topic with no partitions".to_string())?
        }
        Ok(metadata)
    })
    .retry(&mut backoff)
    .unwrap()
}

fn verify_delete(topic: &str) {
    let consumer: BaseConsumer<DefaultConsumerContext> =
        create_config().create().expect("consumer creation failed");
    let timeout = Some(Duration::from_secs(1));

    let mut backoff = ExponentialBackoff::default();
    backoff.max_elapsed_time = Some(Duration::from_secs(5));
    (|| {
        // Asking about the topic specifically will recreate it (under the
        // default Kafka configuration, at least) so we have to ask for the list
        // of all topics and search through it.
        let metadata = consumer
            .fetch_metadata(None, timeout)
            .map_err(|e| e.to_string())?;
        if let Some(_) = metadata.topics().iter().find(|t| t.name() == topic) {
            Err(format!("topic {} still exists", topic))?
        }
        Ok(())
    })
    .retry(&mut backoff)
    .unwrap()
}

#[tokio::test]
async fn test_topics() {
    let admin_client = create_admin_client();
    let opts = AdminOptions::new().operation_timeout(Some(Duration::from_secs(1)));

    // Verify that topics are created as specified, and that they can later
    // be deleted.
    {
        let name1 = rand_test_topic();
        let name2 = rand_test_topic();

        // Test both the builder API and the literal construction.
        let topic1 =
            NewTopic::new(&name1, 1, TopicReplication::Fixed(1)).set("max.message.bytes", "1234");
        let topic2 = NewTopic {
            name: &name2,
            num_partitions: 3,
            replication: TopicReplication::Variable(&[&[0], &[0], &[0]]),
            config: Vec::new(),
        };

        let res = admin_client
            .create_topics(&[topic1, topic2], &opts)
            .await
            .expect("topic creation failed");
        assert_eq!(res, &[Ok(name1.clone()), Ok(name2.clone())]);

        let metadata1 = fetch_metadata(&name1);
        let metadata2 = fetch_metadata(&name2);
        assert_eq!(1, metadata1.topics().len());
        assert_eq!(1, metadata2.topics().len());
        let metadata_topic1 = &metadata1.topics()[0];
        let metadata_topic2 = &metadata2.topics()[0];
        assert_eq!(&name1, metadata_topic1.name());
        assert_eq!(&name2, metadata_topic2.name());
        assert_eq!(1, metadata_topic1.partitions().len());
        assert_eq!(3, metadata_topic2.partitions().len());

        let res = admin_client
            .describe_configs(
                &[
                    ResourceSpecifier::Topic(&name1),
                    ResourceSpecifier::Topic(&name2),
                ],
                &opts,
            )
            .await
            .expect("describe configs failed");
        let config1 = &res[0].as_ref().expect("describe configs failed on topic 1");
        let config2 = &res[1].as_ref().expect("describe configs failed on topic 2");
        let mut expected_entry1 = ConfigEntry {
            name: "max.message.bytes".into(),
            value: Some("1234".into()),
            source: ConfigSource::DynamicTopic,
            is_read_only: false,
            is_default: false,
            is_sensitive: false,
        };
        let expected_entry2 = ConfigEntry {
            name: "max.message.bytes".into(),
            value: Some("1000012".into()),
            source: ConfigSource::Default,
            is_read_only: false,
            is_default: true,
            is_sensitive: false,
        };
        if get_broker_version() < KafkaVersion(1, 1, 0, 0) {
            expected_entry1.source = ConfigSource::Unknown;
        }
        assert_eq!(Some(&expected_entry1), config1.get("max.message.bytes"));
        assert_eq!(Some(&expected_entry2), config2.get("max.message.bytes"));
        let config_entries1 = config1.entry_map();
        let config_entries2 = config2.entry_map();
        assert_eq!(config1.entries.len(), config_entries1.len());
        assert_eq!(config2.entries.len(), config_entries2.len());
        assert_eq!(
            Some(&&expected_entry1),
            config_entries1.get("max.message.bytes")
        );
        assert_eq!(
            Some(&&expected_entry2),
            config_entries2.get("max.message.bytes")
        );

        let partitions1 = NewPartitions::new(&name1, 5);
        let res = admin_client
            .create_partitions(&[partitions1], &opts)
            .await
            .expect("partition creation failed");
        assert_eq!(res, &[Ok(name1.clone())]);

        let mut tries = 0;
        loop {
            let metadata = fetch_metadata(&name1);
            let topic = &metadata.topics()[0];
            let n = topic.partitions().len();
            if n == 5 {
                break;
            } else if tries >= 5 {
                panic!("topic has {} partitions, but expected {}", n, 5);
            } else {
                tries += 1;
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }

        let res = admin_client
            .delete_topics(&[&name1, &name2], &opts)
            .await
            .expect("topic deletion failed");
        assert_eq!(res, &[Ok(name1.clone()), Ok(name2.clone())]);
        verify_delete(&name1);
        verify_delete(&name2);
    }

    // Verify that incorrect replication configurations are ignored when
    // creating topics.
    {
        let topic = NewTopic::new("ignored", 1, TopicReplication::Variable(&[&[0], &[0]]));
        let res = admin_client.create_topics(&[topic], &opts).await;
        assert_eq!(
            Err(KafkaError::AdminOpCreation(
                "replication configuration for topic 'ignored' assigns 2 partition(s), \
                 which does not match the specified number of partitions (1)"
                    .into()
            )),
            res,
        )
    }

    // Verify that incorrect replication configurations are ignored when
    // creating partitions.
    {
        let name = rand_test_topic();
        let topic = NewTopic::new(&name, 1, TopicReplication::Fixed(1));

        let res = admin_client
            .create_topics(vec![&topic], &opts)
            .await
            .expect("topic creation failed");
        assert_eq!(res, &[Ok(name.clone())]);
        let _ = fetch_metadata(&name);

        // This partition specification is obviously garbage, and so trips
        // a client-side error.
        let partitions = NewPartitions::new(&name, 2).assign(&[&[0], &[0], &[0]]);
        let res = admin_client.create_partitions(&[partitions], &opts).await;
        assert_eq!(
            res,
            Err(KafkaError::AdminOpCreation(format!(
                "partition assignment for topic '{}' assigns 3 partition(s), \
                 which is more than the requested total number of partitions (2)",
                name
            )))
        );

        // Only the server knows that this partition specification is garbage.
        let partitions = NewPartitions::new(&name, 2).assign(&[&[0], &[0]]);
        let res = admin_client
            .create_partitions(&[partitions], &opts)
            .await
            .expect("partition creation failed");
        assert_eq!(
            res,
            &[Err((name, RDKafkaErrorCode::InvalidReplicaAssignment))],
        );
    }

    // Verify that deleting a non-existent topic fails.
    {
        let name = rand_test_topic();
        let res = admin_client
            .delete_topics(&[&name], &opts)
            .await
            .expect("delete topics failed");
        assert_eq!(
            res,
            &[Err((name, RDKafkaErrorCode::UnknownTopicOrPartition))]
        );
    }

    // Verify that mixed-success operations properly report the successful and
    // failing operators.
    {
        let name1 = rand_test_topic();
        let name2 = rand_test_topic();

        let topic1 = NewTopic::new(&name1, 1, TopicReplication::Fixed(1));
        let topic2 = NewTopic::new(&name2, 1, TopicReplication::Fixed(1));

        let res = admin_client
            .create_topics(vec![&topic1], &opts)
            .await
            .expect("topic creation failed");
        assert_eq!(res, &[Ok(name1.clone())]);
        let _ = fetch_metadata(&name1);

        let res = admin_client
            .create_topics(vec![&topic1, &topic2], &opts)
            .await
            .expect("topic creation failed");
        assert_eq!(
            res,
            &[
                Err((name1.clone(), RDKafkaErrorCode::TopicAlreadyExists)),
                Ok(name2.clone())
            ]
        );
        let _ = fetch_metadata(&name2);

        let res = admin_client
            .delete_topics(&[&name1], &opts)
            .await
            .expect("topic deletion failed");
        assert_eq!(res, &[Ok(name1.clone())]);
        verify_delete(&name1);

        let res = admin_client
            .delete_topics(&[&name2, &name1], &opts)
            .await
            .expect("topic deletion failed");
        assert_eq!(
            res,
            &[
                Ok(name2.clone()),
                Err((name1.clone(), RDKafkaErrorCode::UnknownTopicOrPartition))
            ]
        );
    }
}

#[tokio::test]
async fn test_configs() {
    let admin_client = create_admin_client();
    let opts = AdminOptions::new();
    let broker = ResourceSpecifier::Broker(0);

    let res = admin_client
        .describe_configs(&[broker], &opts)
        .await
        .expect("describe configs failed");
    let config = &res[0].as_ref().expect("describe configs failed");
    let orig_val = config
        .get("log.flush.interval.messages")
        .expect("original config entry missing")
        .value
        .as_ref()
        .expect("original value missing");

    let config = AlterConfig::new(broker).set("log.flush.interval.messages", "1234");
    let res = admin_client
        .alter_configs(&[config], &opts)
        .await
        .expect("alter configs failed");
    assert_eq!(res, &[Ok(OwnedResourceSpecifier::Broker(0))]);

    let mut tries = 0;
    loop {
        let res = admin_client
            .describe_configs(&[broker], &opts)
            .await
            .expect("describe configs failed");
        let config = &res[0].as_ref().expect("describe configs failed");
        let entry = config.get("log.flush.interval.messages");
        let expected_entry = if get_broker_version() < KafkaVersion(1, 1, 0, 0) {
            // Pre-1.1, the AlterConfig operation will silently fail, and the
            // config will remain unchanged, which I guess is worth testing.
            ConfigEntry {
                name: "log.flush.interval.messages".into(),
                value: Some(orig_val.clone()),
                source: ConfigSource::Default,
                is_read_only: true,
                is_default: true,
                is_sensitive: false,
            }
        } else {
            ConfigEntry {
                name: "log.flush.interval.messages".into(),
                value: Some("1234".into()),
                source: ConfigSource::DynamicBroker,
                is_read_only: false,
                is_default: false,
                is_sensitive: false,
            }
        };
        if entry == Some(&expected_entry) {
            break;
        } else if tries >= 5 {
            panic!("{:?} != {:?}", entry, Some(&expected_entry));
        } else {
            tries += 1;
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    let config = AlterConfig::new(broker).set("log.flush.interval.ms", &orig_val);
    let res = admin_client
        .alter_configs(&[config], &opts)
        .await
        .expect("alter configs failed");
    assert_eq!(res, &[Ok(OwnedResourceSpecifier::Broker(0))]);
}

// #[tokio::test]
// async fn test_groups() {
//     let admin_client = create_admin_client();

//     // Verify that a valid group can be deleted.
//     {
//         let group_name = rand_test_group();
//         create_consumer_group(&group_name).await;
//         let res = admin_client
//             .delete_groups(&[&group_name], &AdminOptions::default())
//             .await;
//         assert_eq!(res, Ok(vec![Ok(group_name.to_string())]));
//     }

//     // Verify that attempting to delete an unknown group returns a "group not
//     // found" error.
//     {
//         let unknown_group_name = rand_test_group();
//         let res = admin_client
//             .delete_groups(&[&unknown_group_name], &AdminOptions::default())
//             .await;
//         let expected: GroupResult = Err((unknown_group_name, RDKafkaErrorCode::GroupIdNotFound));
//         assert_eq!(res, Ok(vec![expected]));
//     }

//     // Verify that deleting a valid and invalid group results in a mixed result
//     // set.
//     {
//         let group_name = rand_test_group();
//         let unknown_group_name = rand_test_group();
//         create_consumer_group(&group_name).await;
//         let res = admin_client
//             .delete_groups(
//                 &[&group_name, &unknown_group_name],
//                 &AdminOptions::default(),
//             )
//             .await;
//         assert_eq!(
//             res,
//             Ok(vec![
//                 Ok(group_name.to_string()),
//                 Err((
//                     unknown_group_name.to_string(),
//                     RDKafkaErrorCode::GroupIdNotFound
//                 ))
//             ])
//         );
//     }
// }

// Tests whether each admin operation properly reports an error if the entire
// request fails. The original implementations failed to check this, resulting
// in confusing situations where a failed admin request would return Ok([]).
#[tokio::test]
async fn test_event_errors() {
    // Configure an admin client to target a Kafka server that doesn't exist,
    // then set an impossible timeout. This will ensure that every request fails
    // with an OperationTimedOut error, assuming, of course, that the request
    // passes client-side validation.
    let admin_client = ClientConfig::new()
        .set("bootstrap.servers", "noexist")
        .create::<AdminClient<DefaultClientContext>>()
        .expect("admin client creation failed");
    let opts = AdminOptions::new().request_timeout(Some(Duration::from_nanos(1)));

    let res = admin_client.create_topics(&[], &opts).await;
    assert_eq!(
        res,
        Err(KafkaError::AdminOp(RDKafkaErrorCode::OperationTimedOut))
    );

    let res = admin_client.create_partitions(&[], &opts).await;
    assert_eq!(
        res,
        Err(KafkaError::AdminOp(RDKafkaErrorCode::OperationTimedOut))
    );

    let res = admin_client.delete_topics(&[], &opts).await;
    assert_eq!(
        res,
        Err(KafkaError::AdminOp(RDKafkaErrorCode::OperationTimedOut))
    );

    let res = admin_client.describe_configs(&[], &opts).await;
    assert_eq!(
        res.err(),
        Some(KafkaError::AdminOp(RDKafkaErrorCode::OperationTimedOut))
    );

    let res = admin_client.alter_configs(&[], &opts).await;
    assert_eq!(
        res,
        Err(KafkaError::AdminOp(RDKafkaErrorCode::OperationTimedOut))
    );
}


pub fn rand_test_topic() -> String {
    let id = rand::thread_rng()
        .gen_ascii_chars()
        .take(10)
        .collect::<String>();
    format!("__test_{}", id)
}

pub fn rand_test_group() -> String {
    let id = rand::thread_rng()
        .gen_ascii_chars()
        .take(10)
        .collect::<String>();
    format!("__test_{}", id)
}

pub fn rand_test_transactional_id() -> String {
    let id = rand::thread_rng()
        .gen_ascii_chars()
        .take(10)
        .collect::<String>();
    format!("__test_{}", id)
}

pub fn get_bootstrap_server() -> String {
    env::var("KAFKA_HOST").unwrap_or_else(|_| "localhost:9092".to_owned())
}

pub fn get_broker_version() -> KafkaVersion {
    // librdkafka doesn't expose this directly, sadly.
    match env::var("KAFKA_VERSION") {
        Ok(v) => {
            let regex = Regex::new(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?$").unwrap();
            match regex.captures(&v) {
                Some(captures) => {
                    let extract = |i| {
                        captures
                            .get(i)
                            .map(|m| m.as_str().parse().unwrap())
                            .unwrap_or(0)
                    };
                    KafkaVersion(extract(1), extract(2), extract(3), extract(4))
                }
                None => panic!("KAFKA_VERSION env var was not in expected [n[.n[.n[.n]]]] format"),
            }
        }
        Err(VarError::NotUnicode(_)) => {
            panic!("KAFKA_VERSION env var contained non-unicode characters")
        }
        // If the environment variable is unset, assume we're running the latest version.
        Err(VarError::NotPresent) => {
            KafkaVersion(std::u32::MAX, std::u32::MAX, std::u32::MAX, std::u32::MAX)
        }
    }
}

#[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct KafkaVersion(pub u32, pub u32, pub u32, pub u32);

pub struct ProducerTestContext {
    _some_data: i64, // Add some data so that valgrind can check proper allocation
}

impl ClientContext for ProducerTestContext {
    fn stats(&self, _: Statistics) {} // Don't print stats
}

pub async fn create_topic(name: &str, partitions: i32) {
    let client: AdminClient<_> = consumer_config("create_topic", None).create().unwrap();
    client
        .create_topics(
            &[NewTopic::new(name, partitions, TopicReplication::Fixed(1))],
            &AdminOptions::new(),
        )
        .await
        .unwrap();
}

/// Produce the specified count of messages to the topic and partition specified. A map
/// of (partition, offset) -> message id will be returned. It panics if any error is encountered
/// while populating the topic.
pub async fn populate_topic<P, K, J, Q>(
    topic_name: &str,
    count: i32,
    value_fn: &P,
    key_fn: &K,
    partition: Option<i32>,
    timestamp: Option<i64>,
) -> HashMap<(i32, i64), i32>
where
    P: Fn(i32) -> J,
    K: Fn(i32) -> Q,
    J: ToBytes,
    Q: ToBytes,
{
    let prod_context = ProducerTestContext { _some_data: 1234 };

    // Produce some messages
    let producer = &ClientConfig::new()
        .set("bootstrap.servers", get_bootstrap_server().as_str())
        .set("statistics.interval.ms", "500")
        .set("api.version.request", "true")
        .set("debug", "all")
        .set("message.timeout.ms", "30000")
        .create_with_context::<ProducerTestContext, FutureProducer<_>>(prod_context)
        .expect("Producer creation error");

    let futures = (0..count)
        .map(|id| {
            let future = async move {
                producer
                    .send(
                        FutureRecord {
                            topic: topic_name,
                            payload: Some(&value_fn(id)),
                            key: Some(&key_fn(id)),
                            partition,
                            timestamp,
                            headers: None,
                        },
                        Duration::from_secs(1),
                    )
                    .await
            };
            (id, future)
        })
        .collect::<Vec<_>>();

    let mut message_map = HashMap::new();
    for (id, future) in futures {
        match future.await {
            Ok((partition, offset)) => message_map.insert((partition, offset), id),
            Err((kafka_error, _message)) => panic!("Delivery failed: {}", kafka_error),
        };
    }

    message_map
}

pub fn value_fn(id: i32) -> String {
    format!("Message {}", id)
}

pub fn key_fn(id: i32) -> String {
    format!("Key {}", id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_populate_topic() {
        let topic_name = rand_test_topic();
        let message_map = populate_topic(&topic_name, 100, &value_fn, &key_fn, Some(0), None).await;

        let total_messages = message_map
            .iter()
            .filter(|&(&(partition, _), _)| partition == 0)
            .count();
        assert_eq!(total_messages, 100);

        let mut ids = message_map.iter().map(|(_, id)| *id).collect::<Vec<_>>();
        ids.sort();
        assert_eq!(ids, (0..100).collect::<Vec<_>>());
    }
}

pub struct ConsumerTestContext {
    pub _n: i64, // Add data for memory access validation
}

impl ClientContext for ConsumerTestContext {
    // Access stats
    fn stats(&self, stats: Statistics) {
        let stats_str = format!("{:?}", stats);
        println!("Stats received: {} bytes", stats_str.len());
    }
}

impl ConsumerContext for ConsumerTestContext {
    fn commit_callback(&self, result: KafkaResult<()>, _offsets: &TopicPartitionList) {
        println!("Committing offsets: {:?}", result);
    }
}

pub fn consumer_config(
    group_id: &str,
    config_overrides: Option<HashMap<&str, &str>>,
) -> ClientConfig {
    let mut config = ClientConfig::new();

    config.set("group.id", group_id);
    config.set("client.id", "rdkafka_integration_test_client");
    config.set("bootstrap.servers", get_bootstrap_server().as_str());
    config.set("enable.partition.eof", "false");
    config.set("session.timeout.ms", "6000");
    config.set("enable.auto.commit", "false");
    config.set("statistics.interval.ms", "500");
    config.set("api.version.request", "true");
    config.set("debug", "all");
    config.set("auto.offset.reset", "earliest");

    if let Some(overrides) = config_overrides {
        for (key, value) in overrides {
            config.set(key, value);
        }
    }

    config
}