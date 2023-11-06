#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]

use hyper_rustls::{HttpsConnectorBuilder, HttpsConnector};
use hyper::{header::HeaderValue, client::HttpConnector};
pub use hyper;

mod request;
pub use request::*;

mod response;
pub use response::*;

#[derive(Debug)]
pub enum Error {
  InvalidUri,
  Hyper(hyper::Error),
}

#[derive(Clone, Debug)]
enum Connection {
  ConnectionPool(hyper::Client<HttpsConnector<HttpConnector>>),
}

#[derive(Clone, Debug)]
pub struct Client {
  connection: Connection,
}

impl Client {
  fn https_builder() -> HttpsConnector<HttpConnector> {
    HttpsConnectorBuilder::new().with_native_roots().https_or_http().enable_http1().build()
  }

  pub fn with_connection_pool() -> Client {
    Client {
      connection: Connection::ConnectionPool(hyper::Client::builder().build(Self::https_builder())),
    }
  }

  /*
  fn without_connection_pool() -> Client {}
  */

  pub async fn request<R: Into<Request>>(&self, request: R) -> Result<Response, Error> {
    let request: Request = request.into();
    let mut request = request.0;
    if request.headers().get(hyper::header::HOST).is_none() {
      let host = request.uri().host().ok_or(Error::InvalidUri)?.to_string();
      request
        .headers_mut()
        .insert(hyper::header::HOST, HeaderValue::from_str(&host).map_err(|_| Error::InvalidUri)?);
    }

    Ok(Response(match &self.connection {
      Connection::ConnectionPool(client) => client.request(request).await.map_err(Error::Hyper)?,
    }))
  }
}
