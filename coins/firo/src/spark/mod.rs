use lazy_static::lazy_static;

use sha2::{Digest, Sha256};

use group::GroupEncoding;
use k256::{ProjectivePoint, CompressedPoint};

pub mod chaum;

#[cfg(feature = "frost")]
pub(crate) mod frost;

// Extremely basic hash to curve, which should not be used, yet which offers the needed generators
fn generator(letter: u8) -> ProjectivePoint {
  let mut point = [2; 33];
  let mut g = b"Generator ".to_vec();

  let mut res;
  while {
    g.push(letter);
    point[1..].copy_from_slice(&Sha256::digest(&g));
    res = ProjectivePoint::from_bytes(&CompressedPoint::from(point));
    res.is_none().into()
  } {}
  res.unwrap()
}

lazy_static! {
  pub static ref F: ProjectivePoint = generator(b'F');
  pub static ref G: ProjectivePoint = generator(b'G');
  pub static ref H: ProjectivePoint = generator(b'H');
  pub static ref U: ProjectivePoint = generator(b'U');
  pub static ref GENERATORS_TRANSCRIPT: Vec<u8> = {
    let mut transcript = Vec::with_capacity(4 * 33);
    transcript.extend(&F.to_bytes());
    transcript.extend(&G.to_bytes());
    transcript.extend(&H.to_bytes());
    transcript.extend(&U.to_bytes());
    transcript
  };
}
