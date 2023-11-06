use core::ops::Deref;

use zeroize::{Zeroize, Zeroizing};
use rand_core::OsRng;

use ciphersuite::{
  group::ff::{Field, PrimeField},
  Ciphersuite, Ristretto,
};
use schnorr_signatures::SchnorrSignature;

use serde::{Serialize, Deserialize};

use simple_request::{Request, Client};

use serai_env as env;

use crate::{Service, Metadata, QueuedMessage, message_challenge, ack_challenge};

pub struct MessageQueue {
  pub service: Service,
  priv_key: Zeroizing<<Ristretto as Ciphersuite>::F>,
  pub_key: <Ristretto as Ciphersuite>::G,
  client: Client,
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
    if !url.starts_with("http://") {
      url = "http://".to_string() + &url;
    }

    MessageQueue {
      service,
      pub_key: Ristretto::generator() * priv_key.deref(),
      priv_key,
      client: Client::with_connection_pool(),
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

  async fn json_call(&self, method: &'static str, params: serde_json::Value) -> serde_json::Value {
    #[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
    struct JsonRpcRequest {
      jsonrpc: &'static str,
      method: &'static str,
      params: serde_json::Value,
      id: u64,
    }

    let mut res = loop {
      // Make the request
      match self
        .client
        .request(
          Request::post(&self.url)
            .header("Content-Type", "application/json")
            .body(
              serde_json::to_vec(&JsonRpcRequest {
                jsonrpc: "2.0",
                method,
                params: params.clone(),
                id: 0,
              })
              .unwrap()
              .into(),
            )
            .unwrap(),
        )
        .await
      {
        Ok(req) => {
          // Get the response
          match req.body().await {
            Ok(res) => break res,
            Err(e) => {
              dbg!(e);
            }
          }
        }
        Err(e) => {
          dbg!(e);
        }
      }

      // Sleep for a second before trying again
      tokio::time::sleep(core::time::Duration::from_secs(1)).await;
    };

    let json: serde_json::Value =
      serde_json::from_reader(&mut res).expect("message-queue returned invalid JSON");
    if json.get("result").is_none() {
      panic!("call failed: {json}");
    }
    json
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

    let json = self.json_call("queue", serde_json::json!([metadata, msg, sig])).await;
    if json.get("result") != Some(&serde_json::Value::Bool(true)) {
      panic!("failed to queue message: {json}");
    }
  }

  pub async fn next(&self, from: Service) -> QueuedMessage {
    loop {
      let json = self.json_call("next", serde_json::json!([from, self.service])).await;

      // Convert from a Value to a type via reserialization
      let msg: Option<QueuedMessage> = serde_json::from_str(
        &serde_json::to_string(
          &json.get("result").expect("successful JSON RPC call didn't have result"),
        )
        .unwrap(),
      )
      .expect("next didn't return an Option<QueuedMessage>");

      // If there wasn't a message, check again in 1s
      let Some(msg) = msg else {
        tokio::time::sleep(core::time::Duration::from_secs(1)).await;
        continue;
      };

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

    let json = self.json_call("ack", serde_json::json!([from, self.service, id, sig])).await;
    if json.get("result") != Some(&serde_json::Value::Bool(true)) {
      panic!("failed to ack message {id}: {json}");
    }
  }
}
