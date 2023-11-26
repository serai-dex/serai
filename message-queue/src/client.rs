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
  socket: Option<TcpStream>,
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

    MessageQueue {
      service,
      pub_key: Ristretto::generator() * priv_key.deref(),
      priv_key,
      socket: None,
      url,
    }
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

  async fn send(&mut self, msg: MessageQueueRequest) {
    loop {
      while self.socket.is_none() {
        // Sleep, so we don't hammer re-attempts
        tokio::time::sleep(core::time::Duration::from_secs(5)).await;
        self.socket = TcpStream::connect(&self.url).await.ok();
      }

      let socket = self.socket.as_mut().unwrap();
      let msg = borsh::to_vec(&msg).unwrap();
      let Ok(_) = socket.write_all(&u32::try_from(msg.len()).unwrap().to_le_bytes()).await else {
        self.socket = None;
        continue;
      };
      let Ok(_) = socket.write_all(&msg).await else {
        self.socket = None;
        continue;
      };
      break;
    }
  }

  pub async fn queue(&mut self, metadata: Metadata, msg: Vec<u8>) {
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
    loop {
      self.send(msg.clone()).await;
      if self.socket.as_mut().unwrap().read_u8().await.ok() != Some(1) {
        self.socket = None;
        continue;
      }
      break;
    }
  }

  pub async fn next(&mut self, from: Service) -> QueuedMessage {
    let msg = MessageQueueRequest::Next { from, to: self.service };
    loop {
      self.send(msg.clone()).await;

      // If there wasn't a message, check again in 1s
      let Ok(status) = self.socket.as_mut().unwrap().read_u8().await else {
        self.socket = None;
        continue;
      };
      if status == 0 {
        tokio::time::sleep(core::time::Duration::from_secs(1)).await;
        continue;
      }

      // Timeout after 5 seconds in case there's an issue with the length handling
      let Ok(msg) = tokio::time::timeout(core::time::Duration::from_secs(5), async {
        // Read the message length
        let Ok(len) = self.socket.as_mut().unwrap().read_u32_le().await else {
          self.socket = None;
          return vec![];
        };
        let mut buf = vec![0; usize::try_from(len).unwrap()];
        // Read the message
        let Ok(_) = self.socket.as_mut().unwrap().read_exact(&mut buf).await else {
          self.socket = None;
          return vec![];
        };
        buf
      })
      .await
      else {
        self.socket = None;
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

  pub async fn ack(&mut self, from: Service, id: u64) {
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
    loop {
      self.send(msg.clone()).await;
      if self.socket.as_mut().unwrap().read_u8().await.ok() != Some(1) {
        self.socket = None;
        continue;
      }
      break;
    }
  }
}
