use hyper::{
  StatusCode,
  header::{HeaderValue, HeaderMap},
  body::{Buf, Body},
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
    hyper::body::aggregate(self.0.into_body()).await.map(Buf::reader).map_err(Error::Hyper)
  }
}
