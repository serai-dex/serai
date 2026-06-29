use hyper::body::Bytes;
#[cfg(feature = "basic-auth")]
use hyper::header::HeaderValue;
pub use http_body_util::Full;

#[cfg(feature = "basic-auth")]
use crate::Error;

/// An HTTP request.
#[derive(Debug)]
pub struct Request<B = Full<Bytes>> {
  pub(crate) request: hyper::Request<B>,
  pub(crate) response_size_limit: Option<usize>,
}

impl Request {
  #[cfg(feature = "basic-auth")]
  fn username_password_from_uri(&self) -> Result<(String, String), Error> {
    if let Some(authority) = self.request.uri().authority() {
      let authority = authority.as_str();
      if authority.contains('@') {
        // Decode the username and password from the URI
        let mut userpass = authority.split('@').next().unwrap().to_owned();

        let mut userpass_iter = userpass.split(':');
        let username = userpass_iter.next().unwrap().to_owned();
        let password = userpass_iter.next().map(str::to_owned).unwrap_or_else(String::new);
        zeroize::Zeroize::zeroize(&mut userpass);

        return Ok((username, password));
      }
    }
    Err(Error::InvalidUri)
  }

  /// Use basic authentication with this request.
  ///
  /// This assumes `username`, `password` to be valid for this scheme.
  // TODO: Cite an RFC
  #[cfg(feature = "basic-auth")]
  pub fn basic_auth(&mut self, username: &str, password: &str) {
    use zeroize::Zeroize as _;
    use base64ct::{Encoding as _, Base64};

    let mut formatted = format!("{username}:{password}");
    let mut encoded = Base64::encode_string(formatted.as_bytes());
    formatted.zeroize();
    self.request.headers_mut().insert(
      hyper::header::AUTHORIZATION,
      HeaderValue::from_str(&format!("Basic {encoded}"))
        .expect("couldn't form header from base64-encoded string"),
    );
    encoded.zeroize();
  }

  /// Use basic authentication with this request, as parsed from the URI.
  ///
  /// Note: The URI parsing in this crate is basic and may or may not be correct/complete.
  // TODO: Properly support URI decoding
  #[cfg(feature = "basic-auth")]
  pub fn basic_auth_from_uri(&mut self) -> Result<(), Error> {
    let (mut username, mut password) = self.username_password_from_uri()?;
    self.basic_auth(&username, &password);

    use zeroize::Zeroize as _;
    username.zeroize();
    password.zeroize();

    Ok(())
  }

  /// Enable support for basic authentication, without explicitly using/requiring it.
  ///
  /// Please see [`Request::basic_auth_from_uri`]  for more information.
  #[cfg(feature = "basic-auth")]
  pub fn with_basic_auth(&mut self) {
    match self.basic_auth_from_uri() {
      Ok(()) | Err(_) => {}
    }
  }

  /// Set a size limit for the response.
  ///
  /// This may not perfectly applied when receiving the response. For example, an over-estimated
  /// upper bound on the remainder of the stream may prematurely trigger this size limit, or this
  /// may be exceeded by a single HTTP frame. It is solely for limiting responses to prevent
  /// Denial-of-Service attacks, not for absolute correctness.
  pub fn set_response_size_limit(&mut self, response_size_limit: Option<usize>) {
    self.response_size_limit = response_size_limit;
  }
}

impl<B> From<hyper::Request<B>> for Request<B> {
  fn from(request: hyper::Request<B>) -> Self {
    Request { request, response_size_limit: None }
  }
}
