#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use core::{pin::Pin, future::Future};
extern crate alloc;
use alloc::sync::Arc;

use futures_util::FutureExt as _;
use ::tokio::sync::Mutex;

use tower_service::Service as _;
use hyper::{Uri, header::HeaderValue, body::Bytes, client::conn::http1::SendRequest, rt::Executor};
pub use hyper;

use hyper_util::client::legacy::{Client as HyperClient, connect::HttpConnector};

#[cfg(feature = "tls")]
use hyper_rustls::{HttpsConnectorBuilder, HttpsConnector};

mod request;
pub use request::*;

mod response;
pub use response::*;

/// An error with an HTTP connection/request/response.
// TODO: Diversify based on context?
#[derive(Debug)]
pub enum Error {
  /// The URI was invalid.
  InvalidUri,
  /// The URI lacked a host.
  MissingHost,
  /// THe request's host was inconsistent with the client's.
  InconsistentHost,
  /// An error with the connection occurred.
  ConnectionError(Box<dyn Send + Sync + core::error::Error>),
  /// An error propagated from `hyper`.
  Hyper(hyper::Error),
  /// An error propagated from `hyper-util`.
  HyperUtil(hyper_util::client::legacy::Error),
}

#[cfg(not(feature = "tls"))]
type Connector = HttpConnector;
#[cfg(feature = "tls")]
type Connector = HttpsConnector<HttpConnector>;

#[derive(Clone, Debug)]
enum Connection<E> {
  ConnectionPool(HyperClient<Connector, Full<Bytes>>),
  Connection {
    executor: E,
    connector: Connector,
    host: Uri,
    connection: Arc<Mutex<Option<SendRequest<Full<Bytes>>>>>,
  },
}

/// An HTTP client.
#[derive(Clone, Debug)]
pub struct Client<E> {
  connection: Connection<E>,
}

impl<E: Executor<Pin<Box<dyn Send + Future<Output = ()>>>>> Client<E> {
  #[cfg_attr(
    not(all(feature = "tls", not(feature = "webpki-roots"))),
    expect(clippy::unnecessary_wraps)
  )]
  fn connector() -> Result<Connector, Error> {
    let mut res = HttpConnector::new();
    res.set_keepalive(Some(core::time::Duration::from_secs(60)));
    res.set_nodelay(true);
    res.set_reuse_address(true);

    #[cfg(feature = "tls")]
    res.enforce_http(false);
    #[cfg(feature = "tls")]
    let https = HttpsConnectorBuilder::new().with_native_roots();
    #[cfg(all(feature = "tls", not(feature = "webpki-roots")))]
    let https = https.map_err(|e| {
      Error::ConnectionError(
        format!("couldn't load system's SSL root certificates and webpki-roots unavilable: {e:?}")
          .into(),
      )
    })?;
    // Fallback to `webpki-roots` if present
    #[cfg(all(feature = "tls", feature = "webpki-roots"))]
    let https = https.unwrap_or(HttpsConnectorBuilder::new().with_webpki_roots());
    #[cfg(feature = "tls")]
    let res = https.https_or_http().enable_http1().wrap_connector(res);

    Ok(res)
  }

  /// Create a new connection-pooling client over an async executor.
  pub fn with_executor_and_connection_pool(executor: E) -> Result<Client<E>, Error>
  where
    E: 'static + Send + Sync + Clone,
  {
    Ok(Client {
      connection: Connection::ConnectionPool(
        HyperClient::builder(executor)
          .pool_idle_timeout(core::time::Duration::from_secs(60))
          .build(Self::connector()?),
      ),
    })
  }

  /// Create a new connection over an async executor.
  pub fn with_executor_and_without_connection_pool(
    executor: E,
    host: &str,
  ) -> Result<Client<E>, Error> {
    Ok(Client {
      connection: Connection::Connection {
        executor,
        connector: Self::connector()?,
        host: {
          let uri: Uri = host.parse().map_err(|_| Error::InvalidUri)?;
          if uri.host().is_none() {
            Err(Error::MissingHost)?;
          }
          uri
        },
        connection: Arc::new(Mutex::new(None)),
      },
    })
  }

  /// Make an HTTP request.
  pub async fn request<R: Into<Request>>(&self, request: R) -> Result<Response<'_, E>, Error> {
    let request: Request = request.into();
    let Request { mut request, response_size_limit } = request;
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
        Connection::ConnectionPool(_) => request.uri().host().ok_or(Error::MissingHost)?.to_owned(),
        Connection::Connection { host, .. } => {
          let host_str = host.host().unwrap();
          if let Some(uri_host) = request.uri().host() {
            if host_str != uri_host {
              Err(Error::InconsistentHost)?;
            }
          }
          host_str.to_owned()
        }
      };
      request
        .headers_mut()
        .insert(hyper::header::HOST, HeaderValue::from_str(&host).map_err(|_| Error::InvalidUri)?);
    }

    let response = match &self.connection {
      Connection::ConnectionPool(client) => {
        client.request(request).await.map_err(Error::HyperUtil)?
      }
      Connection::Connection { executor, connector, host, connection } => {
        let mut connection_lock = connection.lock().await;

        // If there's not a connection...
        if connection_lock.is_none() {
          let call_res = connector.clone().call(host.clone()).await;
          #[cfg(not(feature = "tls"))]
          let call_res = call_res.map_err(|e| Error::ConnectionError(format!("{e:?}").into()));
          #[cfg(feature = "tls")]
          let call_res = call_res.map_err(Error::ConnectionError);
          let (requester, connection) =
            hyper::client::conn::http1::handshake(call_res?).await.map_err(Error::Hyper)?;
          // This task will die when we drop the requester
          executor.execute(Box::pin(connection.map(|_| ())));
          *connection_lock = Some(requester);
        }

        let connection = connection_lock.as_mut().expect("lock over the connection was poisoned");
        let mut err = connection.ready().await.err();
        if err.is_none() {
          // Send the request
          let response = connection.send_request(request).await;
          if let Ok(response) = response {
            return Ok(Response { response, size_limit: response_size_limit, client: self });
          }
          err = response.err();
        }
        // Since this connection has been put into an error state, drop it
        *connection_lock = None;
        Err(Error::Hyper(err.expect("only here if `err` is some yet no error")))?
      }
    };

    Ok(Response { response, size_limit: response_size_limit, client: self })
  }
}

#[cfg(feature = "tokio")]
mod tokio {
  use hyper_util::rt::tokio::TokioExecutor;
  use super::*;

  /// A [`Client`] which uses [`tokio`](https://docs.rs/tokio) for the executor.
  pub type TokioClient = Client<TokioExecutor>;
  impl Client<TokioExecutor> {
    /// Create a new connection-pooling client over an async executor.
    pub fn with_connection_pool() -> Result<Self, Error> {
      Self::with_executor_and_connection_pool(TokioExecutor::new())
    }

    /// Create a new connection over an async executor.
    pub fn without_connection_pool(host: &str) -> Result<Self, Error> {
      Self::with_executor_and_without_connection_pool(TokioExecutor::new(), host)
    }
  }
}
#[cfg(feature = "tokio")]
pub use tokio::TokioClient;
