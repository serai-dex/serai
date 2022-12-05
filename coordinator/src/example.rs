use std::thread;
use std::io::Write;
use std::time::Duration;

use clap::{value_t, App, Arg};
use futures::stream::FuturesUnordered;
use futures::{StreamExt, TryStreamExt};
use log::info;

use rdkafka::config::ClientConfig;
use rdkafka::consumer::stream_consumer::StreamConsumer;
use rdkafka::consumer::Consumer;
use rdkafka::message::{BorrowedMessage, OwnedMessage};
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::Message;

use chrono::prelude::*;
use env_logger::fmt::Formatter;
use env_logger::Builder;
use log::{LevelFilter, Record};

mod example {

  struct Example {}

  impl Example {
    fn new() -> Self {
      Self {}
    }

    fn setup_logger(&self, log_thread: bool, rust_log: Option<&str>) {
      let output_format = move |formatter: &mut Formatter, record: &Record| {
        let thread_name = if log_thread {
          format!("(t: {}) ", thread::current().name().unwrap_or("unknown"))
        } else {
          "".to_string()
        };

        let local_time: DateTime<Local> = Local::now();
        let time_str = local_time.format("%H:%M:%S%.3f").to_string();
        write!(
          formatter,
          "{} {}{} - {} - {}\n",
          time_str,
          thread_name,
          record.level(),
          record.target(),
          record.args()
        )
      };
      let mut builder = Builder::new();
      builder.format(output_format).filter(None, LevelFilter::Info);

      rust_log.map(|conf| builder.parse_filters(conf));

      builder.init();
    }

    async fn record_borrowed_message_receipt(msg: &BorrowedMessage<'_>) {
      // Simulate some work that must be done in the same order as messages are
      // received; i.e., before truly parallel processing can begin.
      info!("Message received: {}", msg.offset());
    }

    async fn record_owned_message_receipt(_msg: &OwnedMessage) {
      // Like `record_borrowed_message_receipt`, but takes an `OwnedMessage`
      // instead, as in a real-world use case  an `OwnedMessage` might be more
      // convenient than a `BorrowedMessage`.
      info!("Message received: {:?}", _msg.payload().unwrap());
    }

    // Emulates an expensive, synchronous computation.
    fn expensive_computation<'a>(msg: OwnedMessage) -> String {
      info!("Starting expensive computation on message {}", msg.offset());
      thread::sleep(Duration::from_millis(rand::random::<u64>() % 5000));
      info!("Expensive computation completed on message {}", msg.offset());
      match msg.payload_view::<str>() {
        Some(Ok(payload)) => format!("Payload len for {} is {}", payload, payload.len()),
        Some(Err(_)) => "Message payload is not a string".to_owned(),
        None => "No payload".to_owned(),
      }
    }

    // Creates all the resources and runs the event loop. The event loop will:
    //   1) receive a stream of messages from the `StreamConsumer`.
    //   2) filter out eventual Kafka errors.
    //   3) send the message to a thread pool for processing.
    //   4) produce the result to the output topic.
    // `tokio::spawn` is used to handle IO-bound tasks in parallel (e.g., producing
    // the messages), while `tokio::task::spawn_blocking` is used to handle the
    // simulated CPU-bound task.
    async fn run_async_processor(
      brokers: String,
      group_id: String,
      input_topic: String,
      output_topic: String,
    ) {
      println!("Starting async processor");
      // Create the `StreamConsumer`, to receive the messages from the topic in form of a `Stream`.
      let consumer: StreamConsumer = ClientConfig::new()
        .set("group.id", &group_id)
        .set("bootstrap.servers", &brokers)
        .set("enable.partition.eof", "false")
        .set("session.timeout.ms", "6000")
        .set("enable.auto.commit", "false")
        .create()
        .expect("Consumer creation failed");

      consumer.subscribe(&[&input_topic]).expect("Can't subscribe to specified topic");

      // Create the `FutureProducer` to produce asynchronously.
      let producer: FutureProducer = ClientConfig::new()
        .set("bootstrap.servers", &brokers)
        .set("message.timeout.ms", "5000")
        .create()
        .expect("Producer creation error");

      // Create the outer pipeline on the message stream.
      let stream_processor = consumer.stream().try_for_each(|borrowed_message| {
        let producer = producer.clone();
        let output_topic = output_topic.to_string();
        println!("borrowed_message: {:?}", borrowed_message);
        async move {
          // Process each message
          record_borrowed_message_receipt(&borrowed_message).await;
          // Borrowed messages can't outlive the consumer they are received from, so they need to
          // be owned in order to be sent to a separate thread.
          let owned_message = borrowed_message.detach();
          record_owned_message_receipt(&owned_message).await;
          tokio::spawn(async move {
            // The body of this block will be executed on the main thread pool,
            // but we perform `expensive_computation` on a separate thread pool
            // for CPU-intensive tasks via `tokio::task::spawn_blocking`.
            let computation_result =
              tokio::task::spawn_blocking(|| expensive_computation(owned_message))
                .await
                .expect("failed to wait for expensive computation");
            let produce_future = producer.send(
              FutureRecord::to(&output_topic).key("some key").payload(&computation_result),
              Duration::from_secs(0),
            );
            match produce_future.await {
              Ok(delivery) => println!("Sent: {:?}", delivery),
              Err((e, _)) => println!("Error: {:?}", e),
            }
          });
          Ok(())
        }
      });

      info!("Starting example loop");
      stream_processor.await.expect("stream processing failed");
      info!("Stream processing terminated");
    }

    async fn start() {
      let matches = App::new("Serai Coordinator")
        .version(option_env!("CARGO_PKG_VERSION").unwrap_or(""))
        .about("Coordinates various Serai components")
        .arg(
          Arg::with_name("brokers")
            .short("b")
            .long("brokers")
            .help("Broker list in kafka format")
            .takes_value(true)
            // Will need to reflect kubernetes value
            .default_value("127.0.0.1:9094"),
        )
        .arg(
          Arg::with_name("group-id")
            .short("g")
            .long("group-id")
            .help("Consumer group id")
            .takes_value(true)
            .default_value("1"),
        )
        .arg(
          Arg::with_name("log-conf")
            .long("log-conf")
            .help("Configure the logging format (example: 'rdkafka=trace')")
            .takes_value(true),
        )
        .arg(
          Arg::with_name("input-topic")
            .long("input-topic")
            .help("Input topic")
            .takes_value(true)
            .required(true),
        )
        .arg(
          Arg::with_name("output-topic")
            .long("output-topic")
            .help("Output topic")
            .takes_value(true)
            .required(true),
        )
        .arg(
          Arg::with_name("num-workers")
            .long("num-workers")
            .help("Number of workers")
            .takes_value(true)
            .default_value("1"),
        )
        .get_matches();

      setup_logger(true, matches.value_of("log-conf"));

      let brokers = matches.value_of("brokers").unwrap();
      let group_id = matches.value_of("group-id").unwrap();
      let input_topic = matches.value_of("input-topic").unwrap();
      let output_topic = matches.value_of("output-topic").unwrap();
      let num_workers = value_t!(matches, "num-workers", usize).unwrap();

      (0..num_workers)
        .map(|_| {
          tokio::spawn(run_async_processor(
            brokers.to_owned(),
            group_id.to_owned(),
            input_topic.to_owned(),
            output_topic.to_owned(),
          ))
        })
        .collect::<FuturesUnordered<_>>()
        .for_each(|_| async { () })
        .await
    }
  }
}
