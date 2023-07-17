use core::ops::Deref;
use std::{
  sync::{Arc, RwLock},
  collections::VecDeque,
};

use zeroize::Zeroizing;
use rand_core::OsRng;

use ciphersuite::{group::ff::Field, Ciphersuite, Ristretto};
use schnorr::SchnorrSignature;

use serde::{Serialize, Deserialize};

use messages::{ProcessorMessage, CoordinatorMessage};

use serai_client::primitives::NetworkId;
use message_queue::{Service, Metadata, QueuedMessage, message_challenge, ack_challenge};
use reqwest::Client;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Message {
  pub id: u64,
  pub msg: CoordinatorMessage,
}

#[async_trait::async_trait]
pub trait Coordinator {
  async fn send(&mut self, msg: ProcessorMessage);
  async fn recv(&mut self) -> Message;
  async fn ack(&mut self, msg: Message);
}

pub struct MessageQueue {
  network: NetworkId,
  priv_key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  pub_key: <Ristretto as Ciphersuite>::G,
  client: Client,
  message_queue_url: String,
}

impl MessageQueue {
  pub fn new(
    message_queue_url: String,
    network: NetworkId,
    priv_key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  ) -> MessageQueue {
    MessageQueue {
      network,
      pub_key: Ristretto::generator() * priv_key.deref(),
      priv_key,
      client: Client::new(),
      message_queue_url,
    }
  }

  async fn json_call(&self, method: &'static str, params: serde_json::Value) -> serde_json::Value {
    #[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
    struct JsonRpcRequest {
      version: &'static str,
      method: &'static str,
      params: serde_json::Value,
      id: u64,
    }

    let res = loop {
      // Make the request
      if let Ok(req) = self
        .client
        .post(&self.message_queue_url)
        .json(&JsonRpcRequest { version: "2.0", method, params: params.clone(), id: 0 })
        .send()
        .await
      {
        // Get the response
        if let Ok(res) = req.text().await {
          break res;
        }
      }

      // Sleep 5s before trying again
      tokio::time::sleep(core::time::Duration::from_secs(5)).await;
    };

    let json =
      serde_json::from_str::<serde_json::Value>(&res).expect("message-queue returned invalid JSON");
    if json.get("result").is_none() {
      panic!("call failed: {json}");
    }
    json
  }

  async fn queue(&self, metadata: Metadata, msg: Vec<u8>, sig: Vec<u8>) {
    let json = self.json_call("queue", serde_json::json!([metadata, msg, sig])).await;
    if json.get("result") != Some(&serde_json::Value::Bool(true)) {
      panic!("failed to queue message: {json}");
    }
  }

  async fn next(&self) -> Message {
    loop {
      // TODO: Use a proper expected next ID
      let json =
        self.json_call("next", serde_json::json!([Service::Processor(self.network), 0])).await;

      // Convert from a Value to a type via reserialization
      let msg: Option<QueuedMessage> = serde_json::from_str(
        &serde_json::to_string(
          &json.get("result").expect("successful JSON RPC call didn't have result"),
        )
        .unwrap(),
      )
      .expect("next didn't return an Option<QueuedMessage>");

      // If there wasn't a message, check again in 5s
      let Some(msg) = msg else {
        tokio::time::sleep(core::time::Duration::from_secs(5)).await;
        continue;
      };

      // Verify the message
      assert_eq!(msg.from, Service::Coordinator, "non-coordinator sent us message");
      // TODO: Verify the coordinator's signature
      // TODO: Check the ID is sane
      let id = msg.id;

      // Deserialize it into a CoordinatorMessage
      let msg: CoordinatorMessage =
        serde_json::from_slice(&msg.msg).expect("message wasn't a JSON-encoded CoordinatorMessage");
      return Message { id, msg };
    }
  }

  async fn ack(&self, id: u64, sig: Vec<u8>) {
    let json = self.json_call("ack", serde_json::json!([id, sig])).await;
    if json.get("result") != Some(&serde_json::Value::Bool(true)) {
      panic!("failed to ack message {id}: {json}");
    }
  }
}

#[async_trait::async_trait]
impl Coordinator for MessageQueue {
  async fn send(&mut self, msg: ProcessorMessage) {
    let metadata = Metadata {
      from: Service::Processor(self.network),
      to: Service::Coordinator,
      intent: msg.intent(),
    };
    let msg = serde_json::to_string(&msg).unwrap();

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
        msg.as_bytes(),
        nonce_pub,
      ),
    );
    self.queue(metadata, msg.into_bytes(), sig.serialize()).await;
  }

  async fn recv(&mut self) -> Message {
    self.next().await
  }

  async fn ack(&mut self, msg: Message) {
    // TODO: Should this use OsRng? Deterministic or deterministic + random may be better.
    let nonce = Zeroizing::new(<Ristretto as Ciphersuite>::F::random(&mut OsRng));
    let nonce_pub = Ristretto::generator() * nonce.deref();
    let sig = SchnorrSignature::<Ristretto>::sign(
      &self.priv_key,
      nonce,
      ack_challenge(Service::Processor(self.network), self.pub_key, msg.id, nonce_pub),
    );

    MessageQueue::ack(self, msg.id, sig.serialize()).await
  }
}

// TODO: Move this to tests
pub struct MemCoordinator(Arc<RwLock<VecDeque<Message>>>);
impl MemCoordinator {
  #[allow(clippy::new_without_default)]
  pub fn new() -> MemCoordinator {
    MemCoordinator(Arc::new(RwLock::new(VecDeque::new())))
  }
}

#[async_trait::async_trait]
impl Coordinator for MemCoordinator {
  async fn send(&mut self, _: ProcessorMessage) {
    todo!()
  }
  async fn recv(&mut self) -> Message {
    todo!()
  }
  async fn ack(&mut self, _: Message) {
    todo!()
  }
}
