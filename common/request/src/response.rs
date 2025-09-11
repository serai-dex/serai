use std::io;

use hyper::{
  StatusCode,
  header::{HeaderValue, HeaderMap},
  body::Incoming,
};
use http_body_util::BodyExt;

use futures_util::{Stream, StreamExt};

use crate::{Client, Error};

// Borrows the client so its async task lives as long as this response exists.
#[allow(dead_code)]
#[derive(Debug)]
pub struct Response<'a> {
  pub(crate) response: hyper::Response<Incoming>,
  pub(crate) size_limit: Option<usize>,
  pub(crate) client: &'a Client,
}

impl Response<'_> {
  pub fn status(&self) -> StatusCode {
    self.response.status()
  }
  pub fn headers(&self) -> &HeaderMap<HeaderValue> {
    self.response.headers()
  }
  pub async fn body(self) -> Result<impl std::io::Read, Error> {
    let mut body = self.response.into_body().into_data_stream();
    let mut res: Vec<u8> = vec![];
    loop {
      if let Some(size_limit) = self.size_limit {
        let (lower, upper) = body.size_hint();
        if res.len().wrapping_add(upper.unwrap_or(lower)) > size_limit.min(usize::MAX - 1) {
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
