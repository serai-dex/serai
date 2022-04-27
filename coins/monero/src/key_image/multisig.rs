use rand_core::{RngCore, CryptoRng};

use curve25519_dalek::edwards::EdwardsPoint;
use dalek_ff_group::Scalar;
use frost::{MultisigKeys, sign::lagrange};

use crate::{SignError, hash_to_point, frost::{Ed25519, DLEqProof}};

#[derive(Clone)]
#[allow(non_snake_case)]
pub struct Package {
  // Don't serialize
  H: EdwardsPoint,
  i: usize,

  // Serialize
  image: EdwardsPoint,
  proof: DLEqProof
}

#[allow(non_snake_case)]
pub fn multisig<R: RngCore + CryptoRng>(
  rng: &mut R,
  keys: &MultisigKeys<Ed25519>,
  included: &[usize]
) -> Package {
  let i = keys.params().i();
  let secret = (keys.secret_share() * lagrange::<Scalar>(i, included)).0;

  let H = hash_to_point(&keys.group_key().0);
  let image = secret * H;
  // Includes a proof. Since:
  // sum(lagranged_secrets) = group_private
  // group_private * G = output_key
  // group_private * H = key_image
  // Then sum(lagranged_secrets * H) = key_image
  // lagranged_secret * G is known. lagranged_secret * H is being sent
  // Any discrete log equality proof confirms the same secret was used,
  // forming a valid key_image share
  Package { H, i, image, proof: DLEqProof::prove(rng, &secret, &H, &image) }
}

#[allow(non_snake_case)]
impl Package {
  pub fn resolve(
    self,
    shares: Vec<Option<(EdwardsPoint, Package)>>
  ) -> Result<EdwardsPoint, SignError> {
    let mut included = vec![self.i];
    for i in 1 .. shares.len() {
      if shares[i].is_some() {
        included.push(i);
      }
    }

    let mut image = self.image;
    for i in 0 .. shares.len() {
      if shares[i].is_none() {
        continue;
      }

      let (other, shares) = shares[i].as_ref().unwrap();
      let other = other * lagrange::<Scalar>(i, &included).0;

      // Verify their proof
      let share = shares.image;
      shares.proof.verify(&self.H, &other, &share).map_err(|_| SignError::InvalidKeyImage(i))?;

      // Add their share to the image
      image += share;
    }

    Ok(image)
  }
}
