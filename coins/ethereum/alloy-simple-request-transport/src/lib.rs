#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]

use core::task;
use std::io;

use alloy_json_rpc::{RequestPacket, ResponsePacket};
use alloy_transport::{TransportError, TransportErrorKind, TransportFut};

use simple_request::{hyper, Request, Client};

use tower::Service;

#[derive(Clone, Debug)]
pub struct SimpleRequest {
  client: Client,
  url: String,
}

impl SimpleRequest {
  pub fn new(url: String) -> Self {
    Self { client: Client::with_connection_pool(), url }
  }
}

impl Service<RequestPacket> for SimpleRequest {
  type Response = ResponsePacket;
  type Error = TransportError;
  type Future = TransportFut<'static>;

  #[inline]
  fn poll_ready(&mut self, _cx: &mut task::Context<'_>) -> task::Poll<Result<(), Self::Error>> {
    task::Poll::Ready(Ok(()))
  }

  #[inline]
  fn call(&mut self, req: RequestPacket) -> Self::Future {
    let inner = self.clone();
    Box::pin(async move {
      let packet = req.serialize().map_err(TransportError::SerError)?;
      let request = Request::from(
        hyper::Request::post(&inner.url)
          .header("Content-Type", "application/json")
          .body(serde_json::to_vec(&packet).map_err(TransportError::SerError)?.into())
          .unwrap(),
      );

      let mut res = inner
        .client
        .request(request)
        .await
        .map_err(|e| TransportErrorKind::custom(io::Error::other(format!("{e:?}"))))?
        .body()
        .await
        .map_err(|e| TransportErrorKind::custom(io::Error::other(format!("{e:?}"))))?;

      serde_json::from_reader(&mut res).map_err(|e| TransportError::deser_err(e, ""))
    })
  }
}
