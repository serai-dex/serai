use std::io::Read;

use async_trait::async_trait;

use digest_auth::AuthContext;
use simple_request::{
  hyper::{header::HeaderValue, Request},
  Client,
};

use crate::rpc::{RpcError, RpcConnection, Rpc};

#[derive(Clone, Debug)]
enum Authentication {
  // If unauthenticated, reuse a single client
  Unauthenticated(Client),
  // If authenticated, don't reuse clients so that each connection makes its own connection
  // This ensures that if a nonce is requested, another caller doesn't make a request invalidating
  // it
  // We could acquire a mutex over the client, yet creating a new client is preferred for the
  // possibility of parallelism
  Authenticated { username: String, password: String },
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
    let authentication = if url.contains('@') {
      // Parse out the username and password
      let url_clone = url;
      let split_url = url_clone.split('@').collect::<Vec<_>>();
      if split_url.len() != 2 {
        Err(RpcError::ConnectionError("invalid amount of login specifications".to_string()))?;
      }
      let mut userpass = split_url[0];
      url = split_url[1].to_string();

      // If there was additionally a protocol string, restore that to the daemon URL
      if userpass.contains("://") {
        let split_userpass = userpass.split("://").collect::<Vec<_>>();
        if split_userpass.len() != 2 {
          Err(RpcError::ConnectionError("invalid amount of protocol specifications".to_string()))?;
        }
        url = split_userpass[0].to_string() + "://" + &url;
        userpass = split_userpass[1];
      }

      let split_userpass = userpass.split(':').collect::<Vec<_>>();
      if split_userpass.len() > 2 {
        Err(RpcError::ConnectionError("invalid amount of passwords".to_string()))?;
      }
      Authentication::Authenticated {
        username: split_userpass[0].to_string(),
        password: split_userpass.get(1).unwrap_or(&"").to_string(),
      }
    } else {
      Authentication::Unauthenticated(Client::with_connection_pool())
    };

    Ok(Rpc(HttpRpc { authentication, url }))
  }
}

impl HttpRpc {
  async fn inner_post(&self, route: &str, body: Vec<u8>) -> Result<Vec<u8>, RpcError> {
    let request = |uri| Request::post(uri).body(body.clone().into()).unwrap();

    let mut connection = None;
    let response = match &self.authentication {
      Authentication::Unauthenticated(client) => client
        .request(request(self.url.clone() + "/" + route))
        .await
        .map_err(|e| RpcError::ConnectionError(format!("{e:?}")))?,
      Authentication::Authenticated { username, password } => {
        // This Client will drop and replace its connection on error, when monero-serai requires
        // a single socket for the lifetime of this function
        // Since dropping the connection will raise an error, and this function aborts on any
        // error, this is fine
        let client = Client::without_connection_pool(self.url.clone())
          .map_err(|_| RpcError::ConnectionError("invalid URL".to_string()))?;
        let mut response = client
          .request(request("/".to_string() + route))
          .await
          .map_err(|e| RpcError::ConnectionError(format!("{e:?}")))?;

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
                username,
                password,
                "/".to_string() + route,
                None,
              ))
              .map_err(|_| RpcError::InvalidNode("couldn't respond to digest-auth challenge"))?
              .to_header_string(),
            )
            .unwrap(),
          );

          // Make the request with the response challenge
          response = client
            .request(request)
            .await
            .map_err(|e| RpcError::ConnectionError(format!("{e:?}")))?;
        }

        // Store the client so it's not dropped yet
        connection = Some(client);

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
      res.extend(data.map_err(|e| RpcError::ConnectionError(format!("{e:?}")))?.as_ref());
    }
    */

    let mut res = Vec::with_capacity(128);
    response
      .body()
      .await
      .map_err(|e| RpcError::ConnectionError(format!("{e:?}")))?
      .read_to_end(&mut res)
      .unwrap();

    drop(connection);

    Ok(res)
  }
}

#[async_trait]
impl RpcConnection for HttpRpc {
  async fn post(&self, route: &str, body: Vec<u8>) -> Result<Vec<u8>, RpcError> {
    // TODO: Make this timeout configurable
    tokio::time::timeout(core::time::Duration::from_secs(30), self.inner_post(route, body))
      .await
      .map_err(|e| RpcError::ConnectionError(format!("{e:?}")))?
  }
}
