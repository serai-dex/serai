use async_trait::async_trait;

use digest_auth::AuthContext;
use hyper::{header::HeaderValue, Request, service::Service, client::connect::HttpConnector, Client};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};

use crate::rpc::{RpcError, RpcConnection, Rpc};

#[derive(Clone, Debug)]
enum Authentication {
  // If unauthenticated, reuse a single client
  Unauthenticated(Client<HttpsConnector<HttpConnector>>),
  // If authenticated, don't reuse clients so that each connection makes its own connection
  // This ensures that if a nonce is requested, another caller doesn't make a request invalidating
  // it
  // We could acquire a mutex over the client, yet creating a new client is preferred for the
  // possibility of parallelism
  Authenticated(HttpsConnector<HttpConnector>, String, String),
}

/// An HTTP(S) transport for the RPC.
///
/// Requires tokio.
#[derive(Clone, Debug)]
pub struct HttpRpc {
  authentication: Authentication,
  url: String,
}

impl HttpRpc {
  /// Create a new HTTP(S) RPC connection.
  ///
  /// A daemon requiring authentication can be used via including the username and password in the
  /// URL.
  pub fn new(mut url: String) -> Result<Rpc<HttpRpc>, RpcError> {
    let https_builder =
      HttpsConnectorBuilder::new().with_native_roots().https_or_http().enable_http1().build();

    let authentication = if url.contains('@') {
      // Parse out the username and password
      let url_clone = url;
      let split_url = url_clone.split('@').collect::<Vec<_>>();
      if split_url.len() != 2 {
        Err(RpcError::ConnectionError)?;
      }
      let mut userpass = split_url[0];
      url = split_url[1].to_string();

      // If there was additionally a protocol string, restore that to the daemon URL
      if userpass.contains("://") {
        let split_userpass = userpass.split("://").collect::<Vec<_>>();
        if split_userpass.len() != 2 {
          Err(RpcError::ConnectionError)?;
        }
        url = split_userpass[0].to_string() + "://" + &url;
        userpass = split_userpass[1];
      }

      let split_userpass = userpass.split(':').collect::<Vec<_>>();
      if split_userpass.len() != 2 {
        Err(RpcError::ConnectionError)?;
      }
      Authentication::Authenticated(
        https_builder,
        split_userpass[0].to_string(),
        split_userpass[1].to_string(),
      )
    } else {
      Authentication::Unauthenticated(Client::builder().build(https_builder))
    };

    Ok(Rpc(HttpRpc { authentication, url }))
  }
}

impl HttpRpc {
  async fn inner_post(&self, route: &str, body: Vec<u8>) -> Result<Vec<u8>, RpcError> {
    let request = |uri| {
      Request::post(uri)
        .header(hyper::header::HOST, {
          let mut host = self.url.clone();
          if let Some(protocol_pos) = host.find("://") {
            host.drain(0 .. (protocol_pos + 3));
          }
          host
        })
        .body(body.clone().into())
        .unwrap()
    };

    let mut connection_task_handle = None;
    let response = match &self.authentication {
      Authentication::Unauthenticated(client) => client
        .request(request(self.url.clone() + "/" + route))
        .await
        .map_err(|_| RpcError::ConnectionError)?,
      Authentication::Authenticated(https_builder, user, pass) => {
        let connection = https_builder
          .clone()
          .call(self.url.parse().map_err(|_| RpcError::ConnectionError)?)
          .await
          .map_err(|_| RpcError::ConnectionError)?;
        let (mut requester, connection) = hyper::client::conn::http1::handshake(connection)
          .await
          .map_err(|_| RpcError::ConnectionError)?;
        let connection_task = tokio::spawn(connection);
        connection_task_handle = Some(connection_task.abort_handle());

        let mut response = requester
          .send_request(request("/".to_string() + route))
          .await
          .map_err(|_| RpcError::ConnectionError)?;
        // Only provide authentication if this daemon actually expects it
        if let Some(header) = response.headers().get("www-authenticate") {
          let mut request = request("/".to_string() + route);
          request.headers_mut().insert(
            "Authorization",
            HeaderValue::from_str(
              &digest_auth::parse(
                header
                  .to_str()
                  .map_err(|_| RpcError::InvalidNode("www-authenticate header wasn't a string"))?,
              )
              .map_err(|_| RpcError::InvalidNode("invalid digest-auth response"))?
              .respond(&AuthContext::new_post::<_, _, _, &[u8]>(
                user,
                pass,
                "/".to_string() + route,
                None,
              ))
              .map_err(|_| RpcError::InvalidNode("couldn't respond to digest-auth challenge"))?
              .to_header_string(),
            )
            .unwrap(),
          );

          // Wait for the connection to be ready again
          requester.ready().await.map_err(|_| RpcError::ConnectionError)?;

          // Make the request with the response challenge
          response =
            requester.send_request(request).await.map_err(|_| RpcError::ConnectionError)?;
        }

        response
      }
    };

    /*
    let length = usize::try_from(
      response
        .headers()
        .get("content-length")
        .ok_or(RpcError::InvalidNode("no content-length header"))?
        .to_str()
        .map_err(|_| RpcError::InvalidNode("non-ascii content-length value"))?
        .parse::<u32>()
        .map_err(|_| RpcError::InvalidNode("non-u32 content-length value"))?,
    )
    .unwrap();
    // Only pre-allocate 1 MB so a malicious node which claims a content-length of 1 GB actually
    // has to send 1 GB of data to cause a 1 GB allocation
    let mut res = Vec::with_capacity(length.max(1024 * 1024));
    let mut body = response.into_body();
    while res.len() < length {
      let Some(data) = body.data().await else { break };
      res.extend(data.map_err(|_| RpcError::ConnectionError)?.as_ref());
    }
    */

    let res = hyper::body::to_bytes(response.into_body())
      .await
      .map_err(|_| RpcError::ConnectionError)?
      .to_vec();

    if let Some(connection_task) = connection_task_handle {
      // Clean up the connection task
      connection_task.abort();
    }

    Ok(res)
  }
}

#[async_trait]
impl RpcConnection for HttpRpc {
  async fn post(&self, route: &str, body: Vec<u8>) -> Result<Vec<u8>, RpcError> {
    // TODO: Make this timeout configurable
    tokio::time::timeout(core::time::Duration::from_secs(30), self.inner_post(route, body))
      .await
      .map_err(|_| RpcError::ConnectionError)?
  }
}
