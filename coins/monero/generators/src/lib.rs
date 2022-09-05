use lazy_static::lazy_static;

use tiny_keccak::{Hasher, Keccak};

use curve25519_dalek::{
  constants::ED25519_BASEPOINT_POINT,
  edwards::{EdwardsPoint as DalekPoint, CompressedEdwardsY},
};

use group::Group;
use dalek_ff_group::EdwardsPoint;

mod varint;
use varint::write_varint;

mod hash_to_point;
pub use hash_to_point::hash_to_point;

fn hash(data: &[u8]) -> [u8; 32] {
  let mut keccak = Keccak::v256();
  keccak.update(data);
  let mut res = [0; 32];
  keccak.finalize(&mut res);
  res
}

lazy_static! {
  pub static ref H: DalekPoint =
    CompressedEdwardsY(hash(&ED25519_BASEPOINT_POINT.compress().to_bytes()))
      .decompress()
      .unwrap()
      .mul_by_cofactor();
}

const MAX_M: usize = 16;
const N: usize = 64;
const MAX_MN: usize = MAX_M * N;

#[allow(non_snake_case)]
pub struct Generators {
  pub G: [EdwardsPoint; MAX_MN],
  pub H: [EdwardsPoint; MAX_MN],
}

pub fn bulletproofs_generators(prefix: &'static [u8]) -> Generators {
  let mut res =
    Generators { G: [EdwardsPoint::identity(); MAX_MN], H: [EdwardsPoint::identity(); MAX_MN] };
  for i in 0 .. MAX_MN {
    let i = 2 * i;

    let mut even = H.compress().to_bytes().to_vec();
    even.extend(prefix);
    let mut odd = even.clone();

    write_varint(&i.try_into().unwrap(), &mut even).unwrap();
    write_varint(&(i + 1).try_into().unwrap(), &mut odd).unwrap();
    res.H[i / 2] = EdwardsPoint(hash_to_point(hash(&even)));
    res.G[i / 2] = EdwardsPoint(hash_to_point(hash(&odd)));
  }
  res
}
