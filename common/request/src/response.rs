use core::{pin::Pin, future::Future};
use std::io;

use hyper::{
  StatusCode,
  header::{HeaderValue, HeaderMap},
  body::Incoming,
  rt::Executor,
};
use http_body_util::BodyExt as _;

use futures_util::{Stream as _, StreamExt as _};

use crate::{Client, Error};

/// An HTTP response.
#[derive(Debug)]
pub struct Response<'client, E> {
  pub(crate) response: hyper::Response<Incoming>,
  pub(crate) size_limit: Option<usize>,
  // Borrows the client so its async task lives as long as this response exists.
  #[expect(dead_code)]
  pub(crate) client: &'client Client<E>,
}

// TODO: Relax `Send` bound
impl<E: Executor<Pin<Box<dyn Send + Future<Output = ()>>>>> Response<'_, E> {
  /// The HTTP status of this response.
  pub fn status(&self) -> StatusCode {
    self.response.status()
  }

  /// This response's headers.
  pub fn headers(&self) -> &HeaderMap<HeaderValue> {
    self.response.headers()
  }

  /// This response's body.
  // TODO: Return an async read?
  pub async fn body(self) -> Result<impl std::io::Read, Error> {
    let mut body = self.response.into_body().into_data_stream();
    let mut res: Vec<u8> = vec![];
    loop {
      if let Some(size_limit) = self.size_limit {
        let (lower, upper) = body.size_hint();
        if res.len().saturating_add(upper.unwrap_or(lower)) > size_limit.min(usize::MAX - 1) {
          Err(Error::ConnectionError("response exceeded size limit".into()))?;
        }
      }

      let Some(part) = body.next().await else { break };
      let part = part.map_err(Error::Hyper)?;
      res.extend(part.as_ref());
    }
    Ok(io::Cursor::new(res))
  }
}
