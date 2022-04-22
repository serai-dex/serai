use core::{convert::{TryFrom, TryInto}, cmp::min, fmt};
use std::rc::Rc;

use rand_core::{RngCore, CryptoRng};
use blake2::{Digest, Blake2b};

use ff::{Field, PrimeField};
use group::Group;

use crate::{Curve, MultisigParams, MultisigKeys, FrostError, algorithm::Algorithm};

// Matches ZCash's FROST Jubjub implementation
const BINDING_DST: &'static [u8; 9] = b"FROST_rho";
// Doesn't match ZCash except for their desire for messages to be hashed in advance before used
// here and domain separated
const BINDING_MESSAGE_DST: &'static [u8; 17] = b"FROST_rho_message";

/// Calculate the lagrange coefficient
pub fn lagrange<F: PrimeField>(
  i: usize,
  included: &[usize],
) -> F {
  let mut num = F::one();
  let mut denom = F::one();
  for l in included {
    if i == *l {
      continue;
    }

    let share = F::from(u64::try_from(*l).unwrap());
    num *= share;
    denom *= share - F::from(u64::try_from(i).unwrap());
  }

  // Safe as this will only be 0 if we're part of the above loop
  // (which we have an if case to avoid)
  num * denom.invert().unwrap()
}

// View of params passable to algorithm implementations
#[derive(Clone)]
pub struct ParamsView<C: Curve> {
  group_key: C::G,
  included: Vec<usize>,
  secret_share: C::F,
  verification_shares: Vec<C::G>,
}

impl<C: Curve> ParamsView<C> {
  pub fn group_key(&self) -> C::G {
    self.group_key
  }

  pub fn included(&self) -> Vec<usize> {
    self.included.clone()
  }

  pub fn secret_share(&self) -> C::F {
    self.secret_share
  }

  pub fn verification_share(&self, l: usize) -> C::G {
    self.verification_shares[l]
  }
}

/// Pairing of an Algorithm with a MultisigKeys instance and this specific signing set
#[derive(Clone)]
pub struct Params<C: Curve, A: Algorithm<C>> {
  algorithm: A,
  keys: Rc<MultisigKeys<C>>,
  view: ParamsView<C>,
}

impl<C: Curve, A: Algorithm<C>> Params<C, A> {
  pub fn new(
    algorithm: A,
    keys: Rc<MultisigKeys<C>>,
    included: &[usize],
) -> Result<Params<C, A>, FrostError> {
    let mut included = included.to_vec();
    (&mut included).sort_unstable();

    // included < threshold
    if included.len() < keys.params.t {
      Err(FrostError::InvalidSigningSet("not enough signers".to_string()))?;
    }
    // Invalid index
    if included[0] == 0 {
      Err(FrostError::InvalidParticipantIndex(included[0], keys.params.n))?;
    }
    // OOB index
    if included[included.len() - 1] > keys.params.n {
      Err(FrostError::InvalidParticipantIndex(included[included.len() - 1], keys.params.n))?;
    }
    // Same signer included multiple times
    for i in 0 .. included.len() - 1 {
      if included[i] == included[i + 1] {
        Err(FrostError::DuplicatedIndex(included[i]))?;
      }
    }
    // Not included
    if !included.contains(&keys.params.i) {
      Err(FrostError::InvalidSigningSet("signing despite not being included".to_string()))?;
    }

    let secret_share = keys.secret_share * lagrange::<C::F>(keys.params.i, &included);
    let (offset, offset_share) = if keys.offset.is_some() {
      let offset = keys.offset.unwrap();
      (offset, offset * C::F::from(included.len().try_into().unwrap()).invert().unwrap())
    } else {
      (C::F::zero(), C::F::zero())
    };

    Ok(
      Params {
        algorithm,
        // Out of order arguments to prevent additional cloning
        view: ParamsView {
          group_key: keys.group_key + (C::generator_table() * offset),
          secret_share: secret_share + offset_share,
          verification_shares: keys.verification_shares.clone().iter().enumerate().map(
            |(l, share)| (*share * lagrange::<C::F>(l, &included)) +
                           (C::generator_table() * offset_share)
          ).collect(),
          included: included,
        },
        keys
      }
    )
  }

  pub fn multisig_params(&self) -> MultisigParams {
    self.keys.params
  }
}

struct PreprocessPackage<C: Curve> {
  nonces: [C::F; 2],
  commitments: [C::G; 2],
  serialized: Vec<u8>,
}

// This library unifies the preprocessing step with signing due to security concerns and to provide
// a simpler UX
fn preprocess<R: RngCore + CryptoRng, C: Curve, A: Algorithm<C>>(
  rng: &mut R,
  params: &Params<C, A>,
) -> PreprocessPackage<C> {
  let nonces = [C::F::random(&mut *rng), C::F::random(&mut *rng)];
  let commitments = [C::generator_table() * nonces[0], C::generator_table() * nonces[1]];
  let mut serialized = C::G_to_bytes(&commitments[0]);
  serialized.extend(&C::G_to_bytes(&commitments[1]));

  serialized.extend(
    &A::preprocess_addendum(
      rng,
      &params.view,
      &nonces
    )
  );

  PreprocessPackage { nonces, commitments, serialized }
}

#[allow(non_snake_case)]
struct Package<C: Curve> {
  Ris: Vec<C::G>,
  R: C::G,
  share: C::F
}

// Has every signer perform the role of the signature aggregator
// Step 1 was already deprecated by performing nonce generation as needed
// Step 2 is simply the broadcast round from step 1
fn sign_with_share<C: Curve, A: Algorithm<C>>(
  params: &mut Params<C, A>,
  our_preprocess: PreprocessPackage<C>,
  commitments: &[Option<Vec<u8>>],
  msg: &[u8],
) -> Result<(Package<C>, Vec<u8>), FrostError> {
  let multisig_params = params.multisig_params();
  if commitments.len() != (multisig_params.n + 1) {
    Err(
      FrostError::InvalidParticipantQuantity(
        multisig_params.n,
        commitments.len() - min(1, commitments.len())
      )
    )?;
  }

  if commitments[0].is_some() {
   Err(FrostError::NonEmptyParticipantZero)?;
  }

  let commitments_len = C::G_len() * 2;
  let commit_len = commitments_len + A::addendum_commit_len();
  #[allow(non_snake_case)]
  let mut B = Vec::with_capacity(multisig_params.n + 1);
  B.push(None);
  let mut b: Vec<u8> = vec![];
  for l in 1 ..= multisig_params.n {
    if l == multisig_params.i {
      if commitments[l].is_some() {
        Err(FrostError::DuplicatedIndex(l))?;
      }

      B.push(Some(our_preprocess.commitments));
      // Slightly more robust
      b.extend(&u64::try_from(l).unwrap().to_le_bytes());
      b.extend(&our_preprocess.serialized[0 .. commit_len]);
      continue;
    }

    let included = params.view.included.contains(&l);
    if commitments[l].is_some() && (!included) {
      Err(FrostError::InvalidCommitmentQuantity(l, 0, commitments.len() / C::G_len()))?;
    }

    if commitments[l].is_none() {
      if included {
        Err(FrostError::InvalidCommitmentQuantity(l, 2, 0))?;
      }
      B.push(None);
      continue;
    }

    let commitments = commitments[l].as_ref().unwrap();
    if commitments.len() < commitments_len {
      Err(FrostError::InvalidCommitmentQuantity(l, 2, commitments.len() / C::G_len()))?;
    }

    #[allow(non_snake_case)]
    let D = C::G_from_slice(&commitments[0 .. C::G_len()])
      .map_err(|_| FrostError::InvalidCommitment(l))?;
    #[allow(non_snake_case)]
    let E = C::G_from_slice(&commitments[C::G_len() .. commitments_len])
      .map_err(|_| FrostError::InvalidCommitment(l))?;
    B.push(Some([D, E]));
    b.extend(&u64::try_from(l).unwrap().to_le_bytes());
    b.extend(&commitments[0 .. commit_len]);
  }

  let context = params.algorithm.context();
  let mut p = Vec::with_capacity(multisig_params.t);
  let mut pi = C::F::zero();
  for l in &params.view.included {
    p.push(
      C::F_from_bytes_wide(
        Blake2b::new()
          .chain(BINDING_DST)
          .chain(u64::try_from(*l).unwrap().to_le_bytes())
          .chain(Blake2b::new().chain(BINDING_MESSAGE_DST).chain(msg).finalize())
          .chain(&context)
          .chain(&b)
          .finalize()
          .as_slice()
          .try_into()
          .expect("couldn't convert a 64-byte hash to a 64-byte array")
      )
    );

    let view = &params.view;
    params.algorithm.process_addendum(
      view,
      *l,
      B[*l].as_ref().unwrap(),
      &p[p.len() - 1],
      if *l == multisig_params.i {
        pi = p[p.len() - 1];
        &our_preprocess.serialized[commitments_len .. our_preprocess.serialized.len()]
      } else {
        &commitments[*l].as_ref().unwrap()[commitments_len .. commitments[*l].as_ref().unwrap().len()]
      }
    )?;
  }

  #[allow(non_snake_case)]
  let mut Ris = vec![];
  #[allow(non_snake_case)]
  let mut R = C::G::identity();
  for i in 0 .. params.view.included.len() {
    let commitments = B[params.view.included[i]].unwrap();
    #[allow(non_snake_case)]
    let this_R = commitments[0] + (commitments[1] * p[i]);
    Ris.push(this_R);
    R += this_R;
  }

  let view = &params.view;
  let share = params.algorithm.sign_share(
    view,
    R,
    our_preprocess.nonces[0] + (our_preprocess.nonces[1] * pi),
    msg
  );
  Ok((Package { Ris, R, share }, C::F_to_le_bytes(&share)))
}

// This doesn't check the signing set is as expected and unexpected changes can cause false blames
// if legitimate participants are still using the original, expected, signing set. This library
// could be made more robust in that regard
fn complete<C: Curve, A: Algorithm<C>>(
  sign_params: &Params<C, A>,
  sign: Package<C>,
  serialized: &[Option<Vec<u8>>],
) -> Result<A::Signature, FrostError> {
  let params = sign_params.multisig_params();
  if serialized.len() != (params.n + 1) {
    Err(
      FrostError::InvalidParticipantQuantity(params.n, serialized.len() - min(1, serialized.len()))
    )?;
  }

  if serialized[0].is_some() {
    Err(FrostError::NonEmptyParticipantZero)?;
  }

  let mut responses = Vec::with_capacity(params.t);
  let mut sum = sign.share;
  for i in 0 .. sign_params.view.included.len() {
    let l = sign_params.view.included[i];
    if l == params.i {
      responses.push(None);
      continue;
    }

    // Make sure they actually provided a share
    if serialized[l].is_none() {
      Err(FrostError::InvalidShare(l))?;
    }

    let part = C::F_from_le_slice(serialized[l].as_ref().unwrap())
      .map_err(|_| FrostError::InvalidShare(l))?;
    sum += part;
    responses.push(Some(part));
  }

  // Perform signature validation instead of individual share validation
  // For the success route, which should be much more frequent, this should be faster
  // It also acts as an integrity check of this library's signing function
  let res = sign_params.algorithm.verify(sign_params.view.group_key, sign.R, sum);
  if res.is_some() {
    return Ok(res.unwrap());
  }

  // Find out who misbehaved
  for i in 0 .. sign_params.view.included.len() {
    match responses[i] {
      Some(part) => {
        let l = sign_params.view.included[i];
        if !sign_params.algorithm.verify_share(
          sign_params.view.verification_share(l),
          sign.Ris[i],
          part
        ) {
          Err(FrostError::InvalidShare(l))?;
        }
      },

      // Happens when l == i
      None => {}
    }
  }

  // If everyone has a valid share and there were enough participants, this should've worked
  Err(
    FrostError::InternalError(
      "everyone had a valid share yet the signature was still invalid".to_string()
    )
  )
}

/// State of a Sign machine
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
  Fresh,
  Preprocessed,
  Signed,
  Complete,
}

impl fmt::Display for State {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{:?}", self)
  }
}

/// State machine which manages signing
#[allow(non_snake_case)]
pub struct StateMachine<C: Curve, A: Algorithm<C>> {
  params: Params<C, A>,
  state: State,
  preprocess: Option<PreprocessPackage<C>>,
  sign: Option<Package<C>>,
}

impl<C: Curve, A: Algorithm<C>> StateMachine<C, A> {
  /// Creates a new machine to generate a key for the specified curve in the specified multisig
  pub fn new(params: Params<C, A>) -> StateMachine<C, A> {
    StateMachine {
      params,
      state: State::Fresh,
      preprocess: None,
      sign: None,
    }
  }

  /// Perform the preprocessing round required in order to sign
  /// Returns a byte vector which must be transmitted to all parties selected for this signing
  /// process, over an authenticated channel
  pub fn preprocess<R: RngCore + CryptoRng>(
    &mut self,
    rng: &mut R
  ) -> Result<Vec<u8>, FrostError> {
    if self.state != State::Fresh {
      Err(FrostError::InvalidSignTransition(State::Fresh, self.state))?;
    }
    let preprocess = preprocess::<R, C, A>(rng, &self.params);
    let serialized = preprocess.serialized.clone();
    self.preprocess = Some(preprocess);
    self.state = State::Preprocessed;
    Ok(serialized)
  }

  /// Sign a message
  /// Takes in the participant's commitments, which are expected to be in a Vec where participant
  /// index = Vec index. None is expected at index 0 to allow for this. None is also expected at
  /// index i which is locally handled. Returns a byte vector representing a share of the signature
  /// for every other participant to receive, over an authenticated channel
  pub fn sign(
    &mut self,
    commitments: &[Option<Vec<u8>>],
    msg: &[u8],
  ) -> Result<Vec<u8>, FrostError> {
    if self.state != State::Preprocessed {
      Err(FrostError::InvalidSignTransition(State::Preprocessed, self.state))?;
    }

    let (sign, serialized) = sign_with_share(
      &mut self.params,
      self.preprocess.take().unwrap(),
      commitments,
      msg,
    )?;

    self.sign = Some(sign);
    self.state = State::Signed;
    Ok(serialized)
  }

  /// Complete signing
  /// Takes in everyone elses' shares submitted to us as a Vec, expecting participant index =
  /// Vec index with None at index 0 and index i. Returns a byte vector representing the serialized
  /// signature
  pub fn complete(&mut self, shares: &[Option<Vec<u8>>]) -> Result<A::Signature, FrostError> {
    if self.state != State::Signed {
      Err(FrostError::InvalidSignTransition(State::Signed, self.state))?;
    }

    let signature = complete(
      &self.params,
      self.sign.take().unwrap(),
      shares,
    )?;

    self.state = State::Complete;
    Ok(signature)
  }

  pub fn multisig_params(&self) -> MultisigParams {
    self.params.multisig_params().clone()
  }

  pub fn state(&self) -> State {
    self.state
  }
}
