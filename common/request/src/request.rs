use hyper::body::Body;
#[cfg(feature = "basic-auth")]
use hyper::header::HeaderValue;

#[cfg(feature = "basic-auth")]
use crate::Error;

#[derive(Debug)]
pub struct Request(pub(crate) hyper::Request<Body>);
impl Request {
  #[cfg(feature = "basic-auth")]
  fn username_password_from_uri(&self) -> Result<(String, String), Error> {
    if let Some(authority) = self.0.uri().authority() {
      let authority = authority.as_str();
      if authority.contains('@') {
        // Decode the username and password from the URI
        let mut userpass = authority.split('@').next().unwrap().to_string();

        let mut userpass_iter = userpass.split(':');
        let username = userpass_iter.next().unwrap().to_string();
        let password = userpass_iter.next().map(str::to_string).unwrap_or_else(String::new);
        zeroize::Zeroize::zeroize(&mut userpass);

        return Ok((username, password));
      }
    }
    Err(Error::InvalidUri)
  }

  #[cfg(feature = "basic-auth")]
  pub fn basic_auth(&mut self, username: &str, password: &str) {
    use zeroize::Zeroize;
    use base64ct::{Encoding, Base64};

    let mut formatted = format!("{username}:{password}");
    let mut encoded = Base64::encode_string(formatted.as_bytes());
    formatted.zeroize();
    self.0.headers_mut().insert(
      hyper::header::AUTHORIZATION,
      HeaderValue::from_str(&format!("Basic {encoded}")).unwrap(),
    );
    encoded.zeroize();
  }

  #[cfg(feature = "basic-auth")]
  pub fn basic_auth_from_uri(&mut self) -> Result<(), Error> {
    let (mut username, mut password) = self.username_password_from_uri()?;
    self.basic_auth(&username, &password);

    use zeroize::Zeroize;
    username.zeroize();
    password.zeroize();

    Ok(())
  }

  #[cfg(feature = "basic-auth")]
  pub fn with_basic_auth(&mut self) {
    let _ = self.basic_auth_from_uri();
  }
}
impl From<hyper::Request<Body>> for Request {
  fn from(request: hyper::Request<Body>) -> Request {
    Request(request)
  }
}
