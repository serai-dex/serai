use core::ops::Deref;

use zeroize::{Zeroize, Zeroizing};
use rand_core::OsRng;

use ciphersuite::{
  group::ff::{Field, PrimeField},
  Ciphersuite, Ristretto,
};
use schnorr_signatures::SchnorrSignature;

use tokio::{
  io::{AsyncReadExt, AsyncWriteExt},
  net::TcpStream,
};

use serai_env as env;

#[rustfmt::skip]
use crate::{Service, Metadata, QueuedMessage, MessageQueueRequest, message_challenge, ack_challenge};

pub struct MessageQueue {
  pub service: Service,
  priv_key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  pub_key: <Ristretto as Ciphersuite>::G,
  url: String,
}

impl MessageQueue {
  pub fn new(
    service: Service,
    mut url: String,
    priv_key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  ) -> MessageQueue {
    // Allow MESSAGE_QUEUE_RPC to either be a full URL or just a hostname
    // While we could stitch together multiple variables, our control over this service makes this
    // fine
    if !url.contains(':') {
      url += ":2287";
    }

    MessageQueue { service, pub_key: Ristretto::generator() * priv_key.deref(), priv_key, url }
  }

  pub fn from_env(service: Service) -> MessageQueue {
    let url = env::var("MESSAGE_QUEUE_RPC").expect("message-queue RPC wasn't specified");

    let priv_key: Zeroizing<<Ristretto as Ciphersuite>::F> = {
      let key_str =
        Zeroizing::new(env::var("MESSAGE_QUEUE_KEY").expect("message-queue key wasn't specified"));
      let key_bytes = Zeroizing::new(
        hex::decode(&key_str).expect("invalid message-queue key specified (wasn't hex)"),
      );
      let mut bytes = <<Ristretto as Ciphersuite>::F as PrimeField>::Repr::default();
      bytes.copy_from_slice(&key_bytes);
      let key = Zeroizing::new(
        Option::from(<<Ristretto as Ciphersuite>::F as PrimeField>::from_repr(bytes))
          .expect("invalid message-queue key specified"),
      );
      bytes.zeroize();
      key
    };

    Self::new(service, url, priv_key)
  }

  #[must_use]
  async fn send(socket: &mut TcpStream, msg: MessageQueueRequest) -> bool {
    let msg = borsh::to_vec(&msg).unwrap();
    let Ok(()) = socket.write_all(&u32::try_from(msg.len()).unwrap().to_le_bytes()).await else {
      log::warn!("couldn't send the message len");
      return false;
    };
    let Ok(()) = socket.write_all(&msg).await else {
      log::warn!("couldn't write the message");
      return false;
    };
    true
  }

  pub async fn queue(&self, metadata: Metadata, msg: Vec<u8>) {
    // TODO: Should this use OsRng? Deterministic or deterministic + random may be better.
    let nonce = Zeroizing::new(<Ristretto as Ciphersuite>::F::random(&mut OsRng));
    let nonce_pub = Ristretto::generator() * nonce.deref();
    let sig = SchnorrSignature::<Ristretto>::sign(
      &self.priv_key,
      nonce,
      message_challenge(
        metadata.from,
        self.pub_key,
        metadata.to,
        &metadata.intent,
        &msg,
        nonce_pub,
      ),
    )
    .serialize();

    let msg = MessageQueueRequest::Queue { meta: metadata, msg, sig };
    let mut first = true;
    loop {
      // Sleep, so we don't hammer re-attempts
      if !first {
        tokio::time::sleep(core::time::Duration::from_secs(5)).await;
      }
      first = false;

      let Ok(mut socket) = TcpStream::connect(&self.url).await else { continue };
      if !Self::send(&mut socket, msg.clone()).await {
        continue;
      }
      if socket.read_u8().await.ok() != Some(1) {
        continue;
      }
      break;
    }
  }

  pub async fn next(&self, from: Service) -> QueuedMessage {
    let msg = MessageQueueRequest::Next { from, to: self.service };
    let mut first = true;
    'outer: loop {
      if !first {
        tokio::time::sleep(core::time::Duration::from_secs(5)).await;
        continue;
      }
      first = false;

      let mut socket = match TcpStream::connect(&self.url).await {
        Ok(socket) => socket,
        Err(e) => {
          log::warn!("couldn't connect to message-queue server: {e:?}");
          continue;
        }
      };

      loop {
        if !Self::send(&mut socket, msg.clone()).await {
          continue 'outer;
        }
        let status = match socket.read_u8().await {
          Ok(status) => status,
          Err(e) => {
            log::warn!("couldn't read status u8: {e:?}");
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
            log::warn!("couldn't read len: {e:?}");
            return vec![];
          }
        };
        let mut buf = vec![0; usize::try_from(len).unwrap()];
        // Read the message
        let Ok(_) = socket.read_exact(&mut buf).await else {
          log::warn!("couldn't read the message");
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
          msg.from,
          Service::Coordinator,
          "non-coordinator sent us (a processor) a message"
        );
      } else {
        assert!(
          matches!(msg.from, Service::Processor(_)),
          "non-processor sent us (coordinator) a message"
        );
      }
      // TODO: Verify the sender's signature

      return msg;
    }
  }

  pub async fn ack(&self, from: Service, id: u64) {
    // TODO: Should this use OsRng? Deterministic or deterministic + random may be better.
    let nonce = Zeroizing::new(<Ristretto as Ciphersuite>::F::random(&mut OsRng));
    let nonce_pub = Ristretto::generator() * nonce.deref();
    let sig = SchnorrSignature::<Ristretto>::sign(
      &self.priv_key,
      nonce,
      ack_challenge(self.service, self.pub_key, from, id, nonce_pub),
    )
    .serialize();

    let msg = MessageQueueRequest::Ack { from, to: self.service, id, sig };
    let mut first = true;
    loop {
      if !first {
        tokio::time::sleep(core::time::Duration::from_secs(5)).await;
      }
      first = false;

      let Ok(mut socket) = TcpStream::connect(&self.url).await else { continue };
      if !Self::send(&mut socket, msg.clone()).await {
        continue;
      }
      if socket.read_u8().await.ok() != Some(1) {
        continue;
      }
      break;
    }
  }
}
