#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]

use std::sync::Arc;

use tokio::sync::Mutex;

use hyper_rustls::{HttpsConnectorBuilder, HttpsConnector};
use hyper::{
  Uri,
  header::HeaderValue,
  body::Body,
  service::Service,
  client::{HttpConnector, conn::http1::SendRequest},
};
pub use hyper;

mod request;
pub use request::*;

mod response;
pub use response::*;

#[derive(Debug)]
pub enum Error {
  InvalidUri,
  MissingHost,
  InconsistentHost,
  SslError,
  Hyper(hyper::Error),
}

#[derive(Clone, Debug)]
enum Connection {
  ConnectionPool(hyper::Client<HttpsConnector<HttpConnector>>),
  Connection {
    https_builder: HttpsConnector<HttpConnector>,
    host: Uri,
    connection: Arc<Mutex<Option<SendRequest<Body>>>>,
  },
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

  pub fn without_connection_pool(host: String) -> Result<Client, Error> {
    Ok(Client {
      connection: Connection::Connection {
        https_builder: HttpsConnectorBuilder::new()
          .with_native_roots()
          .https_or_http()
          .enable_http1()
          .build(),
        host: {
          let uri: Uri = host.parse().map_err(|_| Error::InvalidUri)?;
          if uri.host().is_none() {
            Err(Error::MissingHost)?;
          };
          uri
        },
        connection: Arc::new(Mutex::new(None)),
      },
    })
  }

  pub async fn request<R: Into<Request>>(&self, request: R) -> Result<Response, Error> {
    let request: Request = request.into();
    let mut request = request.0;
    if let Some(header_host) = request.headers().get(hyper::header::HOST) {
      match &self.connection {
        Connection::ConnectionPool(_) => {}
        Connection::Connection { host, .. } => {
          if header_host.to_str().map_err(|_| Error::InvalidUri)? != host.host().unwrap() {
            Err(Error::InconsistentHost)?;
          }
        }
      }
    } else {
      let host = match &self.connection {
        Connection::ConnectionPool(_) => {
          request.uri().host().ok_or(Error::MissingHost)?.to_string()
        }
        Connection::Connection { host, .. } => {
          let host_str = host.host().unwrap();
          if let Some(uri_host) = request.uri().host() {
            if host_str != uri_host {
              Err(Error::InconsistentHost)?;
            }
          }
          host_str.to_string()
        }
      };
      request
        .headers_mut()
        .insert(hyper::header::HOST, HeaderValue::from_str(&host).map_err(|_| Error::InvalidUri)?);
    }

    Ok(Response(match &self.connection {
      Connection::ConnectionPool(client) => client.request(request).await.map_err(Error::Hyper)?,
      Connection::Connection { https_builder, host, connection } => {
        let mut connection_lock = connection.lock().await;

        // If there's not a connection...
        if connection_lock.is_none() {
          let (requester, connection) = hyper::client::conn::http1::handshake(
            https_builder.clone().call(host.clone()).await.map_err(|_| Error::SslError)?,
          )
          .await
          .map_err(Error::Hyper)?;
          // This will die when we drop the requester, so we don't need to track an AbortHandle for
          // it
          tokio::spawn(connection);
          *connection_lock = Some(requester);
        }

        let connection = connection_lock.as_mut().unwrap();
        let mut err = connection.ready().await.err();
        if err.is_none() {
          // Send the request
          let res = connection.send_request(request).await;
          if let Ok(res) = res {
            return Ok(Response(res));
          }
          err = res.err();
        }
        // Since this connection has been put into an error state, drop it
        *connection_lock = None;
        Err(Error::Hyper(err.unwrap()))?
      }
    }))
  }
}
