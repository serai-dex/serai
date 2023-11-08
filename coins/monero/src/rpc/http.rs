use std::{sync::Arc, io::Read};

use async_trait::async_trait;

use tokio::sync::Mutex;

use digest_auth::{WwwAuthenticateHeader, AuthContext};
use simple_request::{
  hyper::{StatusCode, header::HeaderValue, Request},
  Response, Client,
};

use crate::rpc::{RpcError, RpcConnection, Rpc};

#[derive(Clone, Debug)]
enum Authentication {
  // If unauthenticated, use a single client
  Unauthenticated(Client),
  // If authenticated, use a single client which supports being locked and tracks its nonce
  // This ensures that if a nonce is requested, another caller doesn't make a request invalidating
  // it
  Authenticated {
    username: String,
    password: String,
    #[allow(clippy::type_complexity)]
    connection: Arc<Mutex<(Option<(WwwAuthenticateHeader, u64)>, Client)>>,
  },
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
  fn digest_auth_challenge(
    response: &Response,
  ) -> Result<Option<(WwwAuthenticateHeader, u64)>, RpcError> {
    Ok(if let Some(header) = response.headers().get("www-authenticate") {
      Some((
        digest_auth::parse(
          header
            .to_str()
            .map_err(|_| RpcError::InvalidNode("www-authenticate header wasn't a string"))?,
        )
        .map_err(|_| RpcError::InvalidNode("invalid digest-auth response"))?,
        0,
      ))
    } else {
      None
    })
  }

  /// Create a new HTTP(S) RPC connection.
  ///
  /// A daemon requiring authentication can be used via including the username and password in the
  /// URL.
  pub async fn new(mut url: String) -> Result<Rpc<HttpRpc>, RpcError> {
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

      let client = Client::without_connection_pool(url.clone())
        .map_err(|_| RpcError::ConnectionError("invalid URL".to_string()))?;
      // Obtain the initial challenge, which also somewhat validates this connection
      let challenge = Self::digest_auth_challenge(
        &client
          .request(
            Request::post(url.clone())
              .body(vec![].into())
              .map_err(|e| RpcError::ConnectionError(format!("couldn't make request: {e:?}")))?,
          )
          .await
          .map_err(|e| RpcError::ConnectionError(format!("{e:?}")))?,
      )?;
      Authentication::Authenticated {
        username: split_userpass[0].to_string(),
        password: split_userpass.get(1).unwrap_or(&"").to_string(),
        connection: Arc::new(Mutex::new((challenge, client))),
      }
    } else {
      Authentication::Unauthenticated(Client::with_connection_pool())
    };

    Ok(Rpc(HttpRpc { authentication, url }))
  }
}

impl HttpRpc {
  async fn inner_post(&self, route: &str, body: Vec<u8>) -> Result<Vec<u8>, RpcError> {
    let request_fn = |uri| {
      Request::post(uri)
        .body(body.clone().into())
        .map_err(|e| RpcError::ConnectionError(format!("couldn't make request: {e:?}")))
    };

    for attempt in 0 .. 2 {
      let response = match &self.authentication {
        Authentication::Unauthenticated(client) => client
          .request(request_fn(self.url.clone() + "/" + route)?)
          .await
          .map_err(|e| RpcError::ConnectionError(format!("{e:?}")))?,
        Authentication::Authenticated { username, password, connection } => {
          let mut connection_lock = connection.lock().await;

          let mut request = request_fn("/".to_string() + route)?;

          // If we don't have an auth challenge, obtain one
          if connection_lock.0.is_none() {
            connection_lock.0 = Self::digest_auth_challenge(
              &connection_lock
                .1
                .request(request)
                .await
                .map_err(|e| RpcError::ConnectionError(format!("{e:?}")))?,
            )?;
            request = request_fn("/".to_string() + route)?;
          }

          // Insert the challenge response, if we have a challenge
          if let Some((challenge, cnonce)) = connection_lock.0.as_mut() {
            // Update the cnonce
            // Overflow isn't a concern as this is a u64
            *cnonce += 1;

            let mut context = AuthContext::new_post::<_, _, _, &[u8]>(
              username,
              password,
              "/".to_string() + route,
              None,
            );
            context.set_custom_cnonce(hex::encode(cnonce.to_le_bytes()));

            request.headers_mut().insert(
              "Authorization",
              HeaderValue::from_str(
                &challenge
                  .respond(&context)
                  .map_err(|_| RpcError::InvalidNode("couldn't respond to digest-auth challenge"))?
                  .to_header_string(),
              )
              .unwrap(),
            );
          }

          let response_result = connection_lock
            .1
            .request(request)
            .await
            .map_err(|e| RpcError::ConnectionError(format!("{e:?}")));

          // If the connection entered an error state, drop the cached challenge as challenges are
          // per-connection
          // We don't need to create a new connection as simple-request will for us
          if response_result.is_err() {
            connection_lock.0 = None;
          }

          // If we're not already on our second attempt and:
          // A) We had a connection error
          // B) We need to re-auth due to this token being stale
          // Move to the next loop iteration (retrying all of this)
          if (attempt == 0) &&
            (response_result.is_err() || {
              let response = response_result.as_ref().unwrap();
              if response.status() == StatusCode::UNAUTHORIZED {
                if let Some(header) = response.headers().get("www-authenticate") {
                  header
                    .to_str()
                    .map_err(|_| RpcError::InvalidNode("www-authenticate header wasn't a string"))?
                    .contains("stale")
                } else {
                  false
                }
              } else {
                false
              }
            })
          {
            // Drop the cached authentication before we do
            connection_lock.0 = None;
            continue;
          }

          response_result?
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

      return Ok(res);
    }

    unreachable!()
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
