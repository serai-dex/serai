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
  random_scalar,
  hash_to_point,
  frost::{MultisigError, Ed25519, DLEqProof},
  key_image,
  clsag::{Input, sign_core, verify}
};

pub trait Msg: Clone + Debug {
  fn msg(&self, image: EdwardsPoint) -> [u8; 32];
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
pub struct Multisig<M: Msg> {
  b: Vec<u8>,
  AH: (dfg::EdwardsPoint, dfg::EdwardsPoint),

  input: Input,

  image: Option<EdwardsPoint>,
  msg: M,

  interim: Option<ClsagSignInterim>
}

impl<M: Msg> Multisig<M> {
  pub fn new(
    input: Input,
    msg: M
  ) -> Result<Multisig<M>, MultisigError> {
    Ok(
      Multisig {
        b: vec![],
        AH: (dfg::EdwardsPoint::identity(), dfg::EdwardsPoint::identity()),

        input,

        image: None,
        msg,
        interim: None
      }
    )
  }

  pub fn set_image(&mut self, image: EdwardsPoint) {
    self.image = Some(image);
  }
}

impl<M: Msg> Algorithm<Ed25519> for Multisig<M> {
  type Signature = (Clsag, EdwardsPoint);

  // We arguably don't have to commit to at all thanks to xG and yG being committed to, both of
  // those being proven to have the same scalar as xH and yH, yet it doesn't hurt
  fn addendum_commit_len() -> usize {
    64
  }

  fn preprocess_addendum<R: RngCore + CryptoRng>(
    rng: &mut R,
    view: &ParamsView<Ed25519>,
    nonces: &[dfg::Scalar; 2]
  ) -> Vec<u8> {
    #[allow(non_snake_case)]
    let H = hash_to_point(&view.group_key().0);
    let h0 = nonces[0].0 * H;
    let h1 = nonces[1].0 * H;
    let mut serialized = Vec::with_capacity(32 + 32 + 64 + 64);
    serialized.extend(h0.compress().to_bytes());
    serialized.extend(h1.compress().to_bytes());
    serialized.extend(&DLEqProof::prove(rng, &nonces[0].0, &H, &h0).serialize());
    serialized.extend(&DLEqProof::prove(rng, &nonces[1].0, &H, &h1).serialize());
    serialized
  }

  fn process_addendum(
    &mut self,
    _: &ParamsView<Ed25519>,
    l: usize,
    commitments: &[dfg::EdwardsPoint; 2],
    serialized: &[u8]
  ) -> Result<(), FrostError> {
    if serialized.len() != 192 {
      // Not an optimal error but...
      Err(FrostError::InvalidCommitmentQuantity(l, 6, serialized.len() / 32))?;
    }

    let alt = &hash_to_point(&self.input.ring[self.input.i][0]);

    let h0 = <Ed25519 as Curve>::G_from_slice(&serialized[0 .. 32]).map_err(|_| FrostError::InvalidCommitment(l))?;
    DLEqProof::deserialize(&serialized[64 .. 128]).ok_or(FrostError::InvalidCommitment(l))?.verify(
      &alt,
      &commitments[0],
      &h0
    ).map_err(|_| FrostError::InvalidCommitment(l))?;

    let h1 = <Ed25519 as Curve>::G_from_slice(&serialized[32 .. 64]).map_err(|_| FrostError::InvalidCommitment(l))?;
    DLEqProof::deserialize(&serialized[128 .. 192]).ok_or(FrostError::InvalidCommitment(l))?.verify(
      &alt,
      &commitments[1],
      &h1
    ).map_err(|_| FrostError::InvalidCommitment(l))?;

    self.b.extend(&l.to_le_bytes());
    self.b.extend(&serialized[0 .. 64]);
    self.AH.0 += h0;
    self.AH.1 += h1;

    Ok(())
  }

  fn context(&self) -> Vec<u8> {
    let mut context = vec![];
    // This should be redundant as the image should be in the addendum if using InputMultisig and
    // in msg if signing a Transaction, yet this ensures CLSAG takes responsibility for its own
    // security boundaries
    context.extend(&self.image.unwrap().compress().to_bytes());
    context.extend(&self.msg.msg(self.image.unwrap()));
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

    // Use everyone's commitments to derive a random source all signers can agree upon
    // Cannot be manipulated to effect and all signers must, and will, know this
    // Uses the context as well to prevent passive observers of messages from being able to break
    // privacy, as the context includes the index of the output in the ring, which can only be
    // known if you have the view key and know which of the wallet's TXOs is being spent
    let mut seed = b"CLSAG_randomness".to_vec();
    seed.extend(&self.context());
    seed.extend(&self.b);
    let mut rng = ChaCha12Rng::from_seed(Blake2b512::digest(seed)[0 .. 32].try_into().unwrap());
    let mask = random_scalar(&mut rng);

    #[allow(non_snake_case)]
    let (clsag, c, mu_C, z, mu_P, C_out) = sign_core(
      &mut rng,
      &self.msg.msg(self.image.unwrap()),
      &self.input,
      &self.image.unwrap(),
      mask,
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
    if verify(&clsag, &self.msg.msg(self.image.unwrap()), self.image.unwrap(), &self.input.ring, interim.C_out) {
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

#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct InputMultisig<M: Msg>(EdwardsPoint, Multisig<M>);

impl<M: Msg> InputMultisig<M> {
  pub fn new(
    input: Input,
    msg: M
  ) -> Result<InputMultisig<M>, MultisigError> {
    Ok(InputMultisig(EdwardsPoint::identity(), Multisig::new(input, msg)?))
  }

  pub fn image(&self) -> EdwardsPoint {
    self.0
  }
}

impl<M: Msg> Algorithm<Ed25519> for InputMultisig<M> {
  type Signature = (Clsag, EdwardsPoint);

  fn addendum_commit_len() -> usize {
    32 + Multisig::<M>::addendum_commit_len()
  }

  fn preprocess_addendum<R: RngCore + CryptoRng>(
    rng: &mut R,
    view: &ParamsView<Ed25519>,
    nonces: &[dfg::Scalar; 2]
  ) -> Vec<u8> {
    let (mut serialized, end) = key_image::generate_share(rng, view);
    serialized.extend(Multisig::<M>::preprocess_addendum(rng, view, nonces));
    serialized.extend(end);
    serialized
  }

  fn process_addendum(
    &mut self,
    view: &ParamsView<Ed25519>,
    l: usize,
    commitments: &[dfg::EdwardsPoint; 2],
    serialized: &[u8]
  ) -> Result<(), FrostError> {
    let (image, serialized) = key_image::verify_share(view, l, serialized).map_err(|_| FrostError::InvalidShare(l))?;
    self.0 += image;
    if l == *view.included().last().unwrap() {
      self.1.set_image(self.0);
    }
    self.1.process_addendum(view, l, commitments, &serialized)
  }

  fn context(&self) -> Vec<u8> {
    self.1.context()
  }

  fn sign_share(
    &mut self,
    view: &ParamsView<Ed25519>,
    nonce_sum: dfg::EdwardsPoint,
    b: dfg::Scalar,
    nonce: dfg::Scalar,
    msg: &[u8]
  ) -> dfg::Scalar {
    self.1.sign_share(view, nonce_sum, b, nonce, msg)
  }

  fn verify(
    &self,
    group_key: dfg::EdwardsPoint,
    nonce: dfg::EdwardsPoint,
    sum: dfg::Scalar
  ) -> Option<Self::Signature> {
    self.1.verify(group_key, nonce, sum)
  }

  fn verify_share(
    &self,
    verification_share: dfg::EdwardsPoint,
    nonce: dfg::EdwardsPoint,
    share: dfg::Scalar,
  ) -> bool {
    self.1.verify_share(verification_share, nonce, share)
  }
}
