use hyper::{
  StatusCode,
  header::{HeaderValue, HeaderMap},
  body::{Buf, Incoming},
};
use http_body_util::BodyExt;

use crate::Error;

// Borrows the client so its async task lives as long as this response exists.
#[derive(Debug)]
pub struct Response(pub(crate) hyper::Response<Incoming>);
impl Response {
  pub fn status(&self) -> StatusCode {
    self.0.status()
  }
  pub fn headers(&self) -> &HeaderMap<HeaderValue> {
    self.0.headers()
  }
  pub async fn body(self) -> Result<impl std::io::Read, Error> {
    self
      .0
      .into_body()
      .collect()
      .await
      .map_err(Error::Hyper)
      .map(|collected| Buf::reader(collected.aggregate()))
  }
}
