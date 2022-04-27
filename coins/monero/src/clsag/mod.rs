use rand_core::{RngCore, CryptoRng};

use blake2::{Digest, Blake2b512};

use curve25519_dalek::{
  constants::ED25519_BASEPOINT_TABLE,
  scalar::Scalar,
  traits::VartimePrecomputedMultiscalarMul,
  edwards::{EdwardsPoint, VartimeEdwardsPrecomputation}
};

use monero::{
  consensus::Encodable,
  util::ringct::{Key, Clsag}
};

use crate::{SignError, c_verify_clsag, random_scalar, commitment, hash_to_scalar, hash_to_point};

#[cfg(feature = "multisig")]
mod multisig;
#[cfg(feature = "multisig")]
pub use multisig::Multisig;

// Ring with both the index we're signing for and the data needed to rebuild its commitment
#[derive(Clone, PartialEq, Eq, Debug)]
pub(crate) struct SemiSignableRing {
  ring: Vec<[EdwardsPoint; 2]>,
  i: usize,
  randomness: Scalar,
  amount: u64
}

pub(crate) fn validate_sign_args(
  ring: Vec<[EdwardsPoint; 2]>,
  i: u8,
  private_key: Option<&Scalar>, // Option as multisig won't have access to this
  randomness: &Scalar,
  amount: u64
) -> Result<SemiSignableRing, SignError> {
  let n = ring.len();
  if n > u8::MAX.into() {
    Err(SignError::InternalError("max ring size in this library is u8 max".to_string()))?;
  }
  if i >= (n as u8) {
    Err(SignError::InvalidRingMember(i, n as u8))?;
  }
  let i: usize = i.into();

  // Validate the secrets match these ring members
  if private_key.is_some() && (ring[i][0] != (private_key.unwrap() * &ED25519_BASEPOINT_TABLE)) {
    Err(SignError::InvalidSecret(0))?;
  }
  if ring[i][1] != commitment(&randomness, amount) {
    Err(SignError::InvalidSecret(1))?;
  }

  Ok(SemiSignableRing { ring, i, randomness: *randomness, amount })
}

#[allow(non_snake_case)]
pub(crate) fn sign_core(
  rand_source: [u8; 64],
  image: EdwardsPoint,
  ssr: &SemiSignableRing,
  msg: &[u8; 32],
  A: EdwardsPoint,
  AH: EdwardsPoint
) -> (Clsag, Scalar, Scalar, Scalar, Scalar, EdwardsPoint) {
  let n = ssr.ring.len();
  let i: usize = ssr.i.into();

  let C_out;

  let mut P = vec![];
  P.reserve_exact(n);
  let mut C = vec![];
  C.reserve_exact(n);
  let mut C_non_zero = vec![];
  C_non_zero.reserve_exact(n);

  let z;

  let mut next_rand = rand_source;
  next_rand = Blake2b512::digest(&next_rand).as_slice().try_into().unwrap();
  {
    let a = Scalar::from_bytes_mod_order_wide(&next_rand);
    next_rand = Blake2b512::digest(&next_rand).as_slice().try_into().unwrap();
    C_out = commitment(&a, ssr.amount);

    for member in &ssr.ring {
      P.push(member[0]);
      C_non_zero.push(member[1]);
      C.push(C_non_zero[C_non_zero.len() - 1] - C_out);
    }

    z = ssr.randomness - a;
  }

  let H = hash_to_point(&P[i]);
  let mut D = H * z;

  // Doesn't use a constant time table as dalek takes longer to generate those then they save
  let images_precomp = VartimeEdwardsPrecomputation::new(&[image, D]);
  D = Scalar::from(8 as u8).invert() * D;

  let mut to_hash = vec![];
  to_hash.reserve_exact(((2 * n) + 4) * 32);
  const PREFIX: &str = "CLSAG_";
  const AGG_0: &str =  "CLSAG_agg_0";
  const ROUND: &str =        "round";
  to_hash.extend(AGG_0.bytes());
  to_hash.extend([0; 32 - AGG_0.len()]);

  for j in 0 .. n {
    to_hash.extend(P[j].compress().to_bytes());
  }

  for j in 0 .. n {
    to_hash.extend(C_non_zero[j].compress().to_bytes());
  }

  to_hash.extend(image.compress().to_bytes());
  let D_bytes = D.compress().to_bytes();
  to_hash.extend(D_bytes);
  to_hash.extend(C_out.compress().to_bytes());
  let mu_P = hash_to_scalar(&to_hash);
  to_hash[AGG_0.len() - 1] = '1' as u8;
  let mu_C = hash_to_scalar(&to_hash);

  to_hash.truncate(((2 * n) + 1) * 32);
  to_hash.reserve_exact(((2 * n) + 5) * 32);
  for j in 0 .. ROUND.len() {
    to_hash[PREFIX.len() + j] = ROUND.as_bytes()[j] as u8;
  }
  to_hash.extend(C_out.compress().to_bytes());
  to_hash.extend(msg);
  to_hash.extend(A.compress().to_bytes());
  to_hash.extend(AH.compress().to_bytes());
  let mut c = hash_to_scalar(&to_hash);

  let mut c1 = Scalar::zero();
  let mut j = (i + 1) % n;
  if j == 0 {
    c1 = c;
  }

  let mut s = vec![];
  s.resize(n, Scalar::zero());
  while j != i {
    s[j] = Scalar::from_bytes_mod_order_wide(&next_rand);
    next_rand = Blake2b512::digest(&next_rand).as_slice().try_into().unwrap();
    let c_p = mu_P * c;
    let c_c = mu_C * c;

    let L = (&s[j] * &ED25519_BASEPOINT_TABLE) + (c_p * P[j]) + (c_c * C[j]);
    let PH = hash_to_point(&P[j]);
    // Shouldn't be an issue as all of the variables in this vartime statement are public
    let R = (s[j] * PH) + images_precomp.vartime_multiscalar_mul(&[c_p, c_c]);

    to_hash.truncate(((2 * n) + 3) * 32);
    to_hash.extend(L.compress().to_bytes());
    to_hash.extend(R.compress().to_bytes());
    c = hash_to_scalar(&to_hash);

    j = (j + 1) % n;
    if j == 0 {
      c1 = c;
    }
  }

  (
    Clsag {
      s: s.iter().map(|s| Key { key: s.to_bytes() }).collect(),
      c1: Key { key: c1.to_bytes() },
      D: Key { key: D_bytes }
    },
    c, mu_C, z, mu_P,
    C_out
  )
}

#[allow(non_snake_case)]
pub fn sign<R: RngCore + CryptoRng>(
  rng: &mut R,
  image: EdwardsPoint,
  msg: [u8; 32],
  ring: Vec<[EdwardsPoint; 2]>,
  i: u8,
  private_key: &Scalar,
  randomness: &Scalar,
  amount: u64
) -> Result<(Clsag, EdwardsPoint), SignError> {
  let ssr = validate_sign_args(ring, i, Some(private_key), randomness, amount)?;
  let a = random_scalar(rng);
  let mut rand_source = [0; 64];
  rng.fill_bytes(&mut rand_source);
  let (mut clsag, c, mu_C, z, mu_P, C_out) = sign_core(
    rand_source,
    image,
    &ssr,
    &msg,
    &a * &ED25519_BASEPOINT_TABLE, a * hash_to_point(&ssr.ring[ssr.i][0])
  );
  clsag.s[i as usize] = Key { key: (a - (c * ((mu_C * z) + (mu_P * private_key)))).to_bytes() };

  Ok((clsag, C_out))
}

// Uses Monero's C verification function to ensure compatibility with Monero
pub fn verify(
  clsag: &Clsag,
  image: EdwardsPoint,
  msg: &[u8; 32],
  ring: &[[EdwardsPoint; 2]],
  pseudo_out: EdwardsPoint
) -> Result<(), SignError> {
  // Workaround for the fact monero-rs doesn't include the length of clsag.s in clsag encoding
  // despite it being part of clsag encoding. Reason for the patch version pin
  let mut serialized = vec![clsag.s.len() as u8];
  clsag.consensus_encode(&mut serialized).unwrap();

  let image_bytes = image.compress().to_bytes();

  let mut ring_bytes = vec![];
  for member in ring {
    ring_bytes.extend(&member[0].compress().to_bytes());
    ring_bytes.extend(&member[1].compress().to_bytes());
  }

  let pseudo_out_bytes = pseudo_out.compress().to_bytes();

  let success;
  unsafe {
    success = c_verify_clsag(
      serialized.len(), serialized.as_ptr(), image_bytes.as_ptr(),
      ring.len() as u8, ring_bytes.as_ptr(), msg.as_ptr(), pseudo_out_bytes.as_ptr()
    );
  }

  if success { Ok(()) } else { Err(SignError::InvalidSignature) }
}
