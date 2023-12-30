use hyper::{
  StatusCode,
  header::{HeaderValue, HeaderMap},
  body::{HttpBody, Buf, Body},
};

use crate::{Client, Error};

// Borrows the client so its async task lives as long as this response exists.
#[derive(Debug)]
pub struct Response<'a>(pub(crate) hyper::Response<Body>, pub(crate) &'a Client);
impl<'a> Response<'a> {
  pub fn status(&self) -> StatusCode {
    self.0.status()
  }
  pub fn headers(&self) -> &HeaderMap<HeaderValue> {
    self.0.headers()
  }
  pub async fn body(self) -> Result<impl std::io::Read, Error> {
    Ok(self.0.into_body().collect().await.map_err(Error::Hyper)?.aggregate().reader())
  }
}
