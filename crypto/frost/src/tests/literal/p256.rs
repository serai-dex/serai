use core::convert::TryInto;

use rand::rngs::OsRng;

use ff::{Field, PrimeField};
use group::GroupEncoding;

use sha2::{digest::Update, Digest, Sha256};

use p256::{elliptic_curve::bigint::{Encoding, U384}, Scalar, ProjectivePoint};

use crate::{
  CurveError, Curve,
  algorithm::Hram,
  tests::{curve::test_curve, vectors::{Vectors, vectors}}
};

const CONTEXT_STRING: &[u8] = b"FROST-P256-SHA256-v5";

fn expand_message_xmd_sha256(dst: &[u8], msg: &[u8], len: u16) -> Option<Vec<u8>> {
  const OUTPUT_SIZE: u16 = 32;
  const BLOCK_SIZE: u16 = 64;

  let blocks = ((len + OUTPUT_SIZE) - 1) / OUTPUT_SIZE;
  if blocks > 255 {
    return None;
  }
  let blocks = blocks as u8;

  let mut dst = dst;
  let oversize = Sha256::digest([b"H2C-OVERSIZE-DST-", dst].concat());
  if dst.len() > 255 {
    dst = &oversize;
  }
  let dst_prime = &[dst, &[dst.len() as u8]].concat();

  let mut msg_prime = vec![0; BLOCK_SIZE.into()];
  msg_prime.extend(msg);
  msg_prime.extend(len.to_be_bytes());
  msg_prime.push(0);
  msg_prime.extend(dst_prime);

  let mut b = vec![Sha256::digest(&msg_prime).to_vec()];

  {
    let mut b1 = b[0].clone();
    b1.push(1);
    b1.extend(dst_prime);
    b.push(Sha256::digest(&b1).to_vec());
  }

  for i in 2 ..= blocks {
    let mut msg = b[0]
      .iter().zip(b[usize::from(i) - 1].iter())
      .map(|(a, b)| *a ^ b).collect::<Vec<_>>();
    msg.push(i);
    msg.extend(dst_prime);
    b.push(Sha256::digest(msg).to_vec());
  }

  Some(b[1 ..].concat()[.. usize::from(len)].to_vec())
}

#[test]
fn test_xmd_sha256() {
  assert_eq!(
    hex::encode(expand_message_xmd_sha256(b"QUUX-V01-CS02-with-expander", b"", 0x80).unwrap()),
    (
      "8bcffd1a3cae24cf9cd7ab85628fd111bb17e3739d3b53f8".to_owned() +
      "9580d217aa79526f1708354a76a402d3569d6a9d19ef3de4d0b991" +
      "e4f54b9f20dcde9b95a66824cbdf6c1a963a1913d43fd7ac443a02" +
      "fc5d9d8d77e2071b86ab114a9f34150954a7531da568a1ea8c7608" +
      "61c0cde2005afc2c114042ee7b5848f5303f0611cf297f"
    )
  );
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct P256;
impl Curve for P256 {
  type F = Scalar;
  type G = ProjectivePoint;
  type T = ProjectivePoint;

  fn id_len() -> u8 {
    u8::try_from(Self::id().len()).unwrap()
  }

  fn id() -> &'static [u8] {
    b"P-256"
  }

  fn generator() -> Self::G {
    Self::G::GENERATOR
  }

  fn generator_table() -> Self::T {
    Self::G::GENERATOR
  }

  fn little_endian() -> bool {
    false
  }

  fn hash_msg(msg: &[u8]) -> Vec<u8> {
    (&Sha256::new()
      .chain(CONTEXT_STRING)
      .chain(b"digest")
      .chain(msg)
      .finalize()
    ).to_vec()
  }

  fn hash_binding_factor(binding: &[u8]) -> Self::F {
    Self::hash_to_F(&[CONTEXT_STRING, b"rho"].concat(), binding)
  }

  fn hash_to_F(dst: &[u8], msg: &[u8]) -> Self::F {
    let mut modulus = vec![0; 16];
    modulus.extend(&(Scalar::zero() - Scalar::one()).to_repr());
    let modulus = U384::from_be_slice(&modulus).wrapping_add(&U384::ONE);
    Self::F_from_slice(
      &U384::from_be_slice(
        &expand_message_xmd_sha256(dst, msg, 48).unwrap()
      ).reduce(&modulus).unwrap().to_be_bytes()[16 ..]
    ).unwrap()
  }

  fn F_len() -> usize {
    32
  }

  fn G_len() -> usize {
    33
  }

  fn F_from_slice(slice: &[u8]) -> Result<Self::F, CurveError> {
    let bytes: [u8; 32] = slice.try_into()
      .map_err(|_| CurveError::InvalidLength(32, slice.len()))?;

    let scalar = Scalar::from_repr(bytes.into());
    if scalar.is_none().into() {
      Err(CurveError::InvalidScalar)?;
    }

    Ok(scalar.unwrap())
  }

  fn G_from_slice(slice: &[u8]) -> Result<Self::G, CurveError> {
    let bytes: [u8; 33] = slice.try_into()
      .map_err(|_| CurveError::InvalidLength(33, slice.len()))?;

    let point = ProjectivePoint::from_bytes(&bytes.into());
    if point.is_none().into() {
      Err(CurveError::InvalidPoint)?;
    }

    Ok(point.unwrap())
  }

  fn F_to_bytes(f: &Self::F) -> Vec<u8> {
    (&f.to_bytes()).to_vec()
  }

  fn G_to_bytes(g: &Self::G) -> Vec<u8> {
    (&g.to_bytes()).to_vec()
  }
}

#[test]
fn p256_curve() {
  test_curve::<_, P256>(&mut OsRng);
}

#[allow(non_snake_case)]
#[derive(Clone)]
pub struct IetfP256Hram {}
impl Hram<P256> for IetfP256Hram {
  #[allow(non_snake_case)]
  fn hram(R: &ProjectivePoint, A: &ProjectivePoint, m: &[u8]) -> Scalar {
    P256::hash_to_F(
      &[CONTEXT_STRING, b"chal"].concat(),
      &[&P256::G_to_bytes(R), &P256::G_to_bytes(A), m].concat()
    )
  }
}

#[test]
fn p256_vectors() {
  vectors::<P256, IetfP256Hram>(
    Vectors {
      threshold: 2,
      shares: &[
        "0c9c1a0fe806c184add50bbdcac913dda73e482daf95dcb9f35dbb0d8a9f7731",
        "8d8e787bef0ff6c2f494ca45f4dad198c6bee01212d6c84067159c52e1863ad5",
        "0e80d6e8f6192c003b5488ce1eec8f5429587d48cf001541e713b2d53c09d928"
      ],
      group_secret: "8ba9bba2e0fd8c4767154d35a0b7562244a4aaf6f36c8fb8735fa48b301bd8de",
      group_key: "023a309ad94e9fe8a7ba45dfc58f38bf091959d3c99cfbd02b4dc00585ec45ab70",

      msg: "74657374",
      included: &[1, 3],
      nonces: &[
        [
          "081617b24375e069b39f649d4c4ce2fba6e38b73e7c16759de0b6079a22c4c7e",
          "4de5fb77d99f03a2491a83a6a4cb91ca3c82a3f34ce94cec939174f47c9f95dd"
        ],
        [
          "d186ea92593f83ea83181b184d41aa93493301ac2bc5b4b1767e94d2db943e38",
          "486e2ee25a3fbc8e6399d748b077a2755fde99fa85cc24fa647ea4ebf5811a15"
        ]
      ],
      binding: "cf7ffe4b8ad6edb6237efaa8cbfb2dfb2fd08d163b6ad9063720f14779a9e143",
      sig_shares: &[
        "9e4d8865faf8c7b3193a3b35eda3d9e12118447114b1e7d5b4809ea28067f8a9",
        "b7d094eab6305ae74daeed1acd31abba9ab81f638d38b72c132cb25a5dfae1fc"
      ],
      sig: "0342c14c77f9d4ef9b8bd64fb0d7bbfdb9f8216a44e5f7bbe6ac0f3ed5e1a57367".to_owned() +
        "561e1d51b129229966e92850bad5859bfee96926fad3007cd3f38639e1ffb554"
    }
  );
}
