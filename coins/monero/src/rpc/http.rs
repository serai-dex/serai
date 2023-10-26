use async_trait::async_trait;

use digest_auth::AuthContext;
use reqwest::Client;

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
  Authenticated(String, String),
}

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
        Err(RpcError::InvalidNode)?;
      }
      let mut userpass = split_url[0];
      url = split_url[1].to_string();

      // If there was additionally a protocol string, restore that to the daemon URL
      if userpass.contains("://") {
        let split_userpass = userpass.split("://").collect::<Vec<_>>();
        if split_userpass.len() != 2 {
          Err(RpcError::InvalidNode)?;
        }
        url = split_userpass[0].to_string() + "://" + &url;
        userpass = split_userpass[1];
      }

      let split_userpass = userpass.split(':').collect::<Vec<_>>();
      if split_userpass.len() != 2 {
        Err(RpcError::InvalidNode)?;
      }
      Authentication::Authenticated(split_userpass[0].to_string(), split_userpass[1].to_string())
    } else {
      Authentication::Unauthenticated(Client::new())
    };

    Ok(Rpc(HttpRpc { authentication, url }))
  }
}

#[async_trait]
impl RpcConnection for HttpRpc {
  async fn post(&self, route: &str, body: Vec<u8>) -> Result<Vec<u8>, RpcError> {
    #[allow(unused_assignments)] // False positive
    let mut client_storage = None;
    let client = match &self.authentication {
      Authentication::Unauthenticated(client) => client,
      Authentication::Authenticated(_, _) => {
        client_storage = Some(Client::new());
        client_storage.as_ref().unwrap()
      }
    };

    let mut builder = client.post(self.url.clone() + "/" + route).body(body);
    if let Authentication::Authenticated(user, pass) = &self.authentication {
      let req = client.post(&self.url).send().await.map_err(|_| RpcError::InvalidNode)?;
      // Only provide authentication if this daemon actually expects it
      if let Some(header) = req.headers().get("www-authenticate") {
        builder = builder.header(
          "Authorization",
          digest_auth::parse(header.to_str().map_err(|_| RpcError::InvalidNode)?)
            .map_err(|_| RpcError::InvalidNode)?
            .respond(&AuthContext::new_post::<_, _, _, &[u8]>(
              user,
              pass,
              "/".to_string() + route,
              None,
            ))
            .map_err(|_| RpcError::InvalidNode)?
            .to_header_string(),
        );
      }
    }

    Ok(
      builder
        .send()
        .await
        .map_err(|_| RpcError::ConnectionError)?
        .bytes()
        .await
        .map_err(|_| RpcError::ConnectionError)?
        .slice(..)
        .to_vec(),
    )
  }
}
