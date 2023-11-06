use hyper::{
  StatusCode,
  header::{HeaderValue, HeaderMap},
  body::{Buf, Body},
};

use crate::Error;

#[derive(Debug)]
pub struct Response(pub(crate) hyper::Response<Body>);
impl Response {
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
