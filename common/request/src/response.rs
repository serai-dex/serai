use core::{pin::Pin, future::Future};
use std::io;

use hyper::{
  StatusCode,
  header::{HeaderValue, HeaderMap},
  body::Incoming,
  rt::Executor,
};
use http_body_util::BodyExt;

use futures_util::{Stream, StreamExt};

use crate::{Client, Error};

#[derive(Debug)]
pub struct Response<
  'client,
  E: 'static + Send + Sync + Clone + Executor<Pin<Box<dyn Send + Future<Output = ()>>>>,
> {
  pub(crate) response: hyper::Response<Incoming>,
  pub(crate) size_limit: Option<usize>,
  // Borrows the client so its async task lives as long as this response exists.
  #[expect(dead_code)]
  pub(crate) client: &'client Client<E>,
}

impl<E: 'static + Send + Sync + Clone + Executor<Pin<Box<dyn Send + Future<Output = ()>>>>>
  Response<'_, E>
{
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
