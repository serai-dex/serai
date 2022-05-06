use core::{convert::TryFrom, cmp::min, fmt};
use std::rc::Rc;

use rand_core::{RngCore, CryptoRng};

use ff::{Field, PrimeField};
use group::Group;

use transcript::Transcript;

use crate::{Curve, FrostError, MultisigParams, MultisigKeys, MultisigView, algorithm::Algorithm};

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

/// Pairing of an Algorithm with a MultisigKeys instance and this specific signing set
#[derive(Clone)]
pub struct Params<C: Curve, A: Algorithm<C>> {
  algorithm: A,
  keys: Rc<MultisigKeys<C>>,
  view: MultisigView<C>,
}

// Currently public to enable more complex operations as desired, yet solely used in testing
impl<C: Curve, A: Algorithm<C>> Params<C, A> {
  pub fn new(
    algorithm: A,
    keys: Rc<MultisigKeys<C>>,
    included: &[usize],
  ) -> Result<Params<C, A>, FrostError> {
    let mut included = included.to_vec();
    (&mut included).sort_unstable();

    // Included < threshold
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

    // Out of order arguments to prevent additional cloning
    Ok(Params { algorithm, view: keys.view(&included).unwrap(), keys })
  }

  pub fn multisig_params(&self) -> MultisigParams {
    self.keys.params
  }

  pub fn view(&self) -> MultisigView<C> {
    self.view.clone()
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
  params: &mut Params<C, A>,
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

  // Domain separate FROST
  {
    let transcript = params.algorithm.transcript();
    transcript.domain_separate(b"FROST");
    if params.keys.offset.is_some() {
      transcript.append_message(b"offset", &C::F_to_le_bytes(&params.keys.offset.unwrap()));
    }
  }

  #[allow(non_snake_case)]
  let mut B = Vec::with_capacity(multisig_params.n + 1);
  B.push(None);

  // Commitments + a presumed 32-byte hash of the message
  let commitments_len = 2 * C::G_len();

  // Parse the commitments and prepare the binding factor
  for l in 1 ..= multisig_params.n {
    if l == multisig_params.i {
      if commitments[l].is_some() {
        Err(FrostError::DuplicatedIndex(l))?;
      }

      B.push(Some(our_preprocess.commitments));
      {
        let transcript = params.algorithm.transcript();
        transcript.append_message(b"participant", &u16::try_from(l).unwrap().to_le_bytes());
        transcript.append_message(
          b"commitments",
          &our_preprocess.serialized[0 .. (C::G_len() * 2)]
        );
      }
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
    {
      let transcript = params.algorithm.transcript();
      transcript.append_message(b"participant", &u16::try_from(l).unwrap().to_le_bytes());
      transcript.append_message(b"commitments", &commitments[0 .. commitments_len]);
    }
  }

  // Add the message to the binding factor
  let binding = {
    let transcript = params.algorithm.transcript();
    transcript.append_message(b"message", &C::hash_msg(&msg));
    C::hash_to_F(&transcript.challenge(b"binding"))
  };

  // Process the commitments and addendums
  let view = &params.view;
  for l in &params.view.included {
    params.algorithm.process_addendum(
      view,
      *l,
      B[*l].as_ref().unwrap(),
      if *l == multisig_params.i {
        &our_preprocess.serialized[commitments_len .. our_preprocess.serialized.len()]
      } else {
        &commitments[*l].as_ref().unwrap()[
          commitments_len .. commitments[*l].as_ref().unwrap().len()
        ]
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
    let this_R = commitments[0] + (commitments[1] * binding);
    Ris.push(this_R);
    R += this_R;
  }

  let view = &params.view;
  let share = params.algorithm.sign_share(
    view,
    R,
    binding,
    our_preprocess.nonces[0] + (our_preprocess.nonces[1] * binding),
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

pub trait StateMachine {
  type Signature;

  /// Perform the preprocessing round required in order to sign
  /// Returns a byte vector which must be transmitted to all parties selected for this signing
  /// process, over an authenticated channel
  fn preprocess<R: RngCore + CryptoRng>(
    &mut self,
    rng: &mut R
  ) -> Result<Vec<u8>, FrostError>;

  /// Sign a message
  /// Takes in the participant's commitments, which are expected to be in a Vec where participant
  /// index = Vec index. None is expected at index 0 to allow for this. None is also expected at
  /// index i which is locally handled. Returns a byte vector representing a share of the signature
  /// for every other participant to receive, over an authenticated channel
  fn sign(
    &mut self,
    commitments: &[Option<Vec<u8>>],
    msg: &[u8],
  ) -> Result<Vec<u8>, FrostError>;

  /// Complete signing
  /// Takes in everyone elses' shares submitted to us as a Vec, expecting participant index =
  /// Vec index with None at index 0 and index i. Returns a byte vector representing the serialized
  /// signature
  fn complete(&mut self, shares: &[Option<Vec<u8>>]) -> Result<Self::Signature, FrostError>;

  fn multisig_params(&self) -> MultisigParams;

  fn state(&self) -> State;
}

/// State machine which manages signing for an arbitrary signature algorithm
#[allow(non_snake_case)]
pub struct AlgorithmMachine<C: Curve, A: Algorithm<C>> {
  params: Params<C, A>,
  state: State,
  preprocess: Option<PreprocessPackage<C>>,
  sign: Option<Package<C>>,
}

impl<C: Curve, A: Algorithm<C>> AlgorithmMachine<C, A> {
  /// Creates a new machine to generate a key for the specified curve in the specified multisig
  pub fn new(
    algorithm: A,
    keys: Rc<MultisigKeys<C>>,
    included: &[usize],
  ) -> Result<AlgorithmMachine<C, A>, FrostError> {
    Ok(
      AlgorithmMachine {
        params: Params::new(algorithm, keys, included)?,
        state: State::Fresh,
        preprocess: None,
        sign: None,
      }
    )
  }
}

impl<C: Curve, A: Algorithm<C>> StateMachine for AlgorithmMachine<C, A> {
  type Signature = A::Signature;

  fn preprocess<R: RngCore + CryptoRng>(
    &mut self,
    rng: &mut R
  ) -> Result<Vec<u8>, FrostError> {
    if self.state != State::Fresh {
      Err(FrostError::InvalidSignTransition(State::Fresh, self.state))?;
    }
    let preprocess = preprocess::<R, C, A>(rng, &mut self.params);
    let serialized = preprocess.serialized.clone();
    self.preprocess = Some(preprocess);
    self.state = State::Preprocessed;
    Ok(serialized)
  }

  fn sign(
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

  fn complete(&mut self, shares: &[Option<Vec<u8>>]) -> Result<A::Signature, FrostError> {
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

  fn multisig_params(&self) -> MultisigParams {
    self.params.multisig_params().clone()
  }

  fn state(&self) -> State {
    self.state
  }
}
