#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]

use hyper_rustls::{HttpsConnectorBuilder, HttpsConnector};
use hyper::{
  StatusCode,
  header::{HeaderValue, HeaderMap},
  body::{Buf, Body},
  Response as HyperResponse,
  client::HttpConnector,
};
pub use hyper::{self, Request};

#[derive(Debug)]
pub struct Response(HyperResponse<Body>);
impl Response {
  pub fn status(&self) -> StatusCode {
    self.0.status()
  }
  pub fn headers(&self) -> &HeaderMap<HeaderValue> {
    self.0.headers()
  }
  pub async fn body(self) -> Result<impl std::io::Read, hyper::Error> {
    Ok(hyper::body::aggregate(self.0.into_body()).await?.reader())
  }
}

#[derive(Clone, Debug)]
enum Connection {
  ConnectionPool(hyper::Client<HttpsConnector<HttpConnector>>),
}

#[derive(Clone, Debug)]
pub struct Client {
  connection: Connection,
}

#[derive(Debug)]
pub enum Error {
  InvalidHost,
  Hyper(hyper::Error),
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

  pub async fn request(&self, mut request: Request<Body>) -> Result<Response, Error> {
    if request.headers().get(hyper::header::HOST).is_none() {
      let host = request.uri().host().ok_or(Error::InvalidHost)?.to_string();
      request
        .headers_mut()
        .insert(hyper::header::HOST, HeaderValue::from_str(&host).map_err(|_| Error::InvalidHost)?);
    }

    #[cfg(feature = "basic-auth")]
    if request.headers().get(hyper::header::AUTHORIZATION).is_none() {
      if let Some(authority) = request.uri().authority() {
        let authority = authority.as_str();
        if authority.contains('@') {
          // Decode the username and password from the URI
          let mut userpass = authority.split('@').next().unwrap().to_string();
          // If the password is "", the URI may omit :, yet the authentication will still expect it
          if !userpass.contains(':') {
            userpass.push(':');
          }

          use zeroize::Zeroize;
          use base64ct::{Encoding, Base64};

          let mut encoded = Base64::encode_string(userpass.as_bytes());
          userpass.zeroize();
          request.headers_mut().insert(
            hyper::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
          );
          encoded.zeroize();
        }
      }
    }

    Ok(Response(match &self.connection {
      Connection::ConnectionPool(client) => client.request(request).await.map_err(Error::Hyper)?,
    }))
  }
}
