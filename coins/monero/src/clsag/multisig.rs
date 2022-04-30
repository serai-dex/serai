use core::fmt::Debug;

use rand_core::{RngCore, CryptoRng, SeedableRng};
use rand_chacha::ChaCha12Rng;

use blake2::{Digest, Blake2b512};

use curve25519_dalek::{
  constants::ED25519_BASEPOINT_TABLE,
  traits::Identity,
  scalar::Scalar,
  edwards::EdwardsPoint
};

use group::Group;
use dalek_ff_group as dfg;
use frost::{Curve, FrostError, algorithm::Algorithm, sign::ParamsView};

use monero::util::ringct::{Key, Clsag};

use crate::{
  hash_to_point,
  frost::{MultisigError, Ed25519, DLEqProof},
  key_image,
  clsag::{Input, sign_core, verify}
};

pub trait TransactionData: Clone + Debug {
  fn msg(&self) -> [u8; 32];
  fn mask_sum(&self) -> Scalar;
}

#[allow(non_snake_case)]
#[derive(Clone, Debug)]
struct ClsagSignInterim {
  c: Scalar,
  s: Scalar,

  clsag: Clsag,
  C_out: EdwardsPoint
}

#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct Multisig<D: TransactionData> {
  entropy: Vec<u8>,
  AH: (dfg::EdwardsPoint, dfg::EdwardsPoint),

  input: Input,

  image: EdwardsPoint,
  data: D,

  interim: Option<ClsagSignInterim>
}

impl<D: TransactionData> Multisig<D> {
  pub fn new(
    input: Input,
    data: D
  ) -> Result<Multisig<D>, MultisigError> {
    Ok(
      Multisig {
        entropy: vec![],
        AH: (dfg::EdwardsPoint::identity(), dfg::EdwardsPoint::identity()),

        input,

        image: EdwardsPoint::identity(),
        data,

        interim: None
      }
    )
  }
}

impl<D: TransactionData> Algorithm<Ed25519> for Multisig<D> {
  type Signature = (Clsag, EdwardsPoint);

  // We arguably don't have to commit to the nonces at all thanks to xG and yG being committed to,
  // both of those being proven to have the same scalar as xH and yH, yet it doesn't hurt
  // As for the image, that should be committed to by the msg from TransactionData, yet putting it
  // here as well ensures the security bounds of this
  fn addendum_commit_len() -> usize {
    3 * 32
  }

  fn preprocess_addendum<R: RngCore + CryptoRng>(
    rng: &mut R,
    view: &ParamsView<Ed25519>,
    nonces: &[dfg::Scalar; 2]
  ) -> Vec<u8> {
    let (mut serialized, proof) = key_image::generate_share(rng, view);

    #[allow(non_snake_case)]
    let H = hash_to_point(&view.group_key().0);
    #[allow(non_snake_case)]
    let nH = (nonces[0].0 * H, nonces[1].0 * H);

    serialized.reserve_exact(3 * (32 + 64));
    serialized.extend(nH.0.compress().to_bytes());
    serialized.extend(nH.1.compress().to_bytes());
    serialized.extend(&DLEqProof::prove(rng, &nonces[0].0, &H, &nH.0).serialize());
    serialized.extend(&DLEqProof::prove(rng, &nonces[1].0, &H, &nH.1).serialize());
    serialized.extend(proof);
    serialized
  }

  fn process_addendum(
    &mut self,
    view: &ParamsView<Ed25519>,
    l: usize,
    commitments: &[dfg::EdwardsPoint; 2],
    serialized: &[u8]
  ) -> Result<(), FrostError> {
    if serialized.len() != (3 * (32 + 64)) {
      // Not an optimal error but...
      Err(FrostError::InvalidCommitmentQuantity(l, 9, serialized.len() / 32))?;
    }

    // Use everyone's commitments to derive a random source all signers can agree upon
    // Cannot be manipulated to effect and all signers must, and will, know this
    self.entropy.extend(&l.to_le_bytes());
    self.entropy.extend(&serialized[0 .. (3 * 32)]);

    let (share, serialized) = key_image::verify_share(view, l, serialized).map_err(|_| FrostError::InvalidShare(l))?;
    self.image += share;

    let alt = &hash_to_point(&self.input.ring[self.input.i][0]);

    #[allow(non_snake_case)]
    let H = (
      <Ed25519 as Curve>::G_from_slice(&serialized[0 .. 32]).map_err(|_| FrostError::InvalidCommitment(l))?,
      <Ed25519 as Curve>::G_from_slice(&serialized[32 .. 64]).map_err(|_| FrostError::InvalidCommitment(l))?
    );

    DLEqProof::deserialize(&serialized[64 .. 128]).ok_or(FrostError::InvalidCommitment(l))?.verify(
      &alt,
      &commitments[0],
      &H.0
    ).map_err(|_| FrostError::InvalidCommitment(l))?;

    DLEqProof::deserialize(&serialized[128 .. 192]).ok_or(FrostError::InvalidCommitment(l))?.verify(
      &alt,
      &commitments[1],
      &H.1
    ).map_err(|_| FrostError::InvalidCommitment(l))?;

    self.AH.0 += H.0;
    self.AH.1 += H.1;

    Ok(())
  }

  fn context(&self) -> Vec<u8> {
    let mut context = vec![];
    // This should be redundant as the image should be in the addendum if using Multisig and in msg
    // if signing a Transaction, yet this ensures CLSAG takes responsibility for its own security
    // boundaries
    context.extend(&self.image.compress().to_bytes());
    context.extend(&self.data.msg());
    context.extend(&self.input.context());
    context
  }

  fn sign_share(
    &mut self,
    view: &ParamsView<Ed25519>,
    nonce_sum: dfg::EdwardsPoint,
    b: dfg::Scalar,
    nonce: dfg::Scalar,
    _: &[u8]
  ) -> dfg::Scalar {
    // Apply the binding factor to the H variant of the nonce
    self.AH.0 += self.AH.1 * b;

    // Use the context with the entropy to prevent passive observers of messages from being able to
    // break privacy, as the context includes the index of the output in the ring, which can only
    // be known if you have the view key and know which of the wallet's TXOs is being spent
    let mut seed = b"CLSAG_randomness".to_vec();
    seed.extend(&self.context());
    seed.extend(&self.entropy);
    let mut rng = ChaCha12Rng::from_seed(Blake2b512::digest(seed)[0 .. 32].try_into().unwrap());

    #[allow(non_snake_case)]
    let (clsag, c, mu_C, z, mu_P, C_out) = sign_core(
      &mut rng,
      &self.data.msg(),
      &self.input,
      &self.image,
      self.data.mask_sum(),
      nonce_sum.0,
      self.AH.0.0
    );
    self.interim = Some(ClsagSignInterim { c: c * mu_P, s: c * mu_C * z, clsag, C_out });

    let share = dfg::Scalar(nonce.0 - (c * mu_P * view.secret_share().0));

    share
  }

  fn verify(
    &self,
    _: dfg::EdwardsPoint,
    _: dfg::EdwardsPoint,
    sum: dfg::Scalar
  ) -> Option<Self::Signature> {
    let interim = self.interim.as_ref().unwrap();

    let mut clsag = interim.clsag.clone();
    clsag.s[self.input.i] = Key { key: (sum.0 - interim.s).to_bytes() };
    if verify(&clsag, &self.data.msg(), self.image, &self.input.ring, interim.C_out) {
      return Some((clsag, interim.C_out));
    }
    return None;
  }

  fn verify_share(
    &self,
    verification_share: dfg::EdwardsPoint,
    nonce: dfg::EdwardsPoint,
    share: dfg::Scalar,
  ) -> bool {
    let interim = self.interim.as_ref().unwrap();
    return (&share.0 * &ED25519_BASEPOINT_TABLE) == (
      nonce.0 - (interim.c * verification_share.0)
    );
  }
}
