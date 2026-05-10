#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../../README.md")]
#![deny(missing_docs)]

use zeroize::{Zeroize as _, Zeroizing};
use rand_core::OsRng;

use ciphersuite::{group::ff::PrimeField, WrappedGroup};
use dalek_ff_group::Ristretto;

use tokio::{
  io::{AsyncReadExt as _, AsyncWriteExt as _},
  net::TcpStream,
};

use serai_env as env;

pub use message_queue::*;

/// The client for the Message Queue.
pub struct Client {
  service: Service,
  private_key: Zeroizing<<Ristretto as WrappedGroup>::F>,
  url: String,
}

impl Client {
  /// Connect to the Message Queue.
  pub fn new(
    service: Service,
    mut url: String,
    private_key: Zeroizing<<Ristretto as WrappedGroup>::F>,
  ) -> Self {
    // Allow MESSAGE_QUEUE_RPC to either be a full URL or just a hostname
    if !url.contains(':') {
      url += ":2287";
    }

    Self { service, private_key, url }
  }

  /// Create a connection to the Message Queue via the definitions from `serai-env`.
  ///
  /// This MAY panic if the environment does not have the necessary variables.
  pub fn from_env(service: Service) -> Self {
    let url = env::var("MESSAGE_QUEUE_RPC").expect("message-queue RPC wasn't specified");

    let private_key: Zeroizing<<Ristretto as WrappedGroup>::F> = {
      let key_str =
        Zeroizing::new(env::var("MESSAGE_QUEUE_KEY").expect("message-queue key wasn't specified"));
      let key_bytes = Zeroizing::new(
        hex::decode(&key_str).expect("invalid message-queue key specified (wasn't hex)"),
      );
      let mut bytes = <<Ristretto as WrappedGroup>::F as PrimeField>::Repr::default();
      bytes.copy_from_slice(&key_bytes);
      let key = Zeroizing::new(
        Option::from(<<Ristretto as WrappedGroup>::F as PrimeField>::from_repr(bytes))
          .expect("invalid message-queue key specified"),
      );
      bytes.zeroize();
      key
    };

    Self::new(service, url, private_key)
  }

  async fn send(socket: &mut TcpStream, msg: Request) -> Result<(), String> {
    let msg = borsh::to_vec(&msg).unwrap();
    match socket.write_all(&u32::try_from(msg.len()).unwrap().to_le_bytes()).await {
      Ok(()) => {}
      Err(e) => Err(format!("couldn't send the message len: {e:?}"))?,
    }
    match socket.write_all(&msg).await {
      Ok(()) => {}
      Err(e) => Err(format!("couldn't write the message: {e:?}"))?,
    }
    Ok(())
  }

  /// Queue a message via the Message Queue.
  pub async fn queue(&self, metadata: Metadata, msg: Vec<u8>) -> Result<(), String> {
    let mut msg = Request::Queue { metadata, message: msg, signature: [0; 64] };
    msg.sign(&mut OsRng, &self.private_key);

    let mut socket = match TcpStream::connect(&self.url).await {
      Ok(socket) => socket,
      Err(e) => Err(format!("failed to connect to the message-queue service: {e:?}"))?,
    };
    Self::send(&mut socket, msg.clone()).await?;
    match socket.read_u8().await {
      Ok(1) => {}
      Ok(b) => Err(format!("message-queue didn't return for 1 for its ack, recieved: {b}"))?,
      Err(e) => Err(format!("failed to read the response from the message-queue service: {e:?}"))?,
    }
    Ok(())
  }

  /// Queue a message via the Message Queue.
  ///
  /// This future will run until the message is successfully queued.
  pub async fn queue_with_retry(&self, metadata: Metadata, msg: Vec<u8>) {
    let mut first = true;
    loop {
      // Sleep, so we don't hammer re-attempts
      if !first {
        tokio::time::sleep(core::time::Duration::from_secs(5)).await;
      }
      first = false;

      if self.queue(metadata.clone(), msg.clone()).await.is_ok() {
        break;
      }
    }
  }

  /// Fetch the next message from the Message Queue.
  pub async fn next(&self, from: Service) -> QueuedMessage {
    let mut msg = Request::Fetch { from, to: self.service };
    msg.sign(&mut OsRng, &self.private_key);

    let mut first = true;
    'outer: loop {
      if !first {
        tokio::time::sleep(core::time::Duration::from_secs(5)).await;
      }
      first = false;

      serai_env::trace!("opening socket to message-queue for next");
      let mut socket = match TcpStream::connect(&self.url).await {
        Ok(socket) => socket,
        Err(e) => {
          serai_env::warn!("couldn't connect to message-queue server: {e:?}");
          continue;
        }
      };
      serai_env::trace!("opened socket for next");

      loop {
        if Self::send(&mut socket, msg.clone()).await.is_err() {
          continue 'outer;
        }
        let status = match socket.read_u8().await {
          Ok(status) => status,
          Err(e) => {
            serai_env::warn!("couldn't read status u8: {e:?}");
            continue 'outer;
          }
        };
        // If there wasn't a message, check again in 1s
        // TODO: Use a notification system here
        if status == 0 {
          tokio::time::sleep(core::time::Duration::from_secs(1)).await;
          continue;
        }
        assert_eq!(status, 1);
        break;
      }

      // Timeout after 5 seconds in case there's an issue with the length handling
      let Ok(msg) = tokio::time::timeout(core::time::Duration::from_secs(5), async {
        // Read the message length
        let len = match socket.read_u32_le().await {
          Ok(len) => len,
          Err(e) => {
            serai_env::warn!("couldn't read len: {e:?}");
            return vec![];
          }
        };
        let mut buf = vec![0; usize::try_from(len).unwrap()];
        // Read the message
        let Ok(_) = socket.read_exact(&mut buf).await else {
          serai_env::warn!("couldn't read the message");
          return vec![];
        };
        buf
      })
      .await
      else {
        continue;
      };
      if msg.is_empty() {
        continue;
      }

      let msg: QueuedMessage = borsh::from_slice(msg.as_slice()).unwrap();

      // Verify the message
      // Verify the sender is sane
      if matches!(self.service, Service::Processor(_)) {
        assert_eq!(
          msg.metadata.from,
          Service::Coordinator,
          "non-coordinator sent us (a processor) a message"
        );
      } else {
        assert!(
          matches!(msg.metadata.from, Service::Processor(_)),
          "non-processor sent us (coordinator) a message"
        );
      }
      // TODO: Verify the sender's signature

      return msg;
    }
  }

  /// Acknowledge the next message from the Message Queue as handled.
  ///
  /// This will advance the next message in the queue, causing the message with `id` to no longer
  /// be yielded.
  pub async fn ack(&self, from: Service, id: u64) {
    let mut msg = Request::Acknowledge { from, to: self.service, id, signature: [0; 64] };
    msg.sign(&mut OsRng, &self.private_key);
    let mut first = true;
    loop {
      if !first {
        tokio::time::sleep(core::time::Duration::from_secs(5)).await;
      }
      first = false;

      let Ok(mut socket) = TcpStream::connect(&self.url).await else { continue };
      if Self::send(&mut socket, msg.clone()).await.is_err() {
        continue;
      }
      if socket.read_u8().await.ok() != Some(1) {
        continue;
      }
      break;
    }
  }
}
