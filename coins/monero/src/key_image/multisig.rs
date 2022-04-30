use rand_core::{RngCore, CryptoRng};

use curve25519_dalek::edwards::{EdwardsPoint, CompressedEdwardsY};
use frost::MultisigView;

use crate::{hash_to_point, frost::{MultisigError, Ed25519, DLEqProof}};

#[allow(non_snake_case)]
pub fn generate_share<R: RngCore + CryptoRng>(
  rng: &mut R,
  view: &MultisigView<Ed25519>
) -> (EdwardsPoint, Vec<u8>) {
  let H = hash_to_point(&view.group_key().0);
  let image = view.secret_share().0 * H;
  // Includes a proof. Since:
  // sum(lagranged_secrets) = group_private
  // group_private * G = output_key
  // group_private * H = key_image
  // Then sum(lagranged_secrets * H) = key_image
  // lagranged_secret * G is known. lagranged_secret * H is being sent
  // Any discrete log equality proof confirms the same secret was used,
  // forming a valid key_image share
  (image, DLEqProof::prove(rng, &view.secret_share().0, &H, &image).serialize())
}

pub fn verify_share(
  view: &MultisigView<Ed25519>,
  l: usize,
  share: &[u8]
) -> Result<(EdwardsPoint, Vec<u8>), MultisigError> {
  if share.len() < 96 {
    Err(MultisigError::InvalidDLEqProof)?;
  }
  let image = CompressedEdwardsY(
    share[0 .. 32].try_into().unwrap()
  ).decompress().ok_or(MultisigError::InvalidKeyImage(l))?;
  let proof = DLEqProof::deserialize(
    &share[(share.len() - 64) .. share.len()]
  ).ok_or(MultisigError::InvalidDLEqProof)?;
  proof.verify(
    &hash_to_point(&view.group_key().0),
    &view.verification_share(l),
    &image
  ).map_err(|_| MultisigError::InvalidKeyImage(l))?;

  Ok((image, share[32 .. (share.len() - 64)].to_vec()))
}
