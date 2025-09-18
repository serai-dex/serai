pub use simple_request::{hyper, Error, Request, Response};

#[derive(Clone, Debug)]
pub struct Client(simple_request::Client);

impl Client {
  pub fn with_connection_pool() -> Client {
    Self(simple_request::Client::with_connection_pool().unwrap())
  }

  pub fn without_connection_pool(host: &str) -> Result<Client, Error> {
    simple_request::Client::without_connection_pool(host).map(Self)
  }

  pub async fn request<R: Into<Request>>(&self, request: R) -> Result<Response<'_>, Error> {
    self.0.request(request).await
  }
}
