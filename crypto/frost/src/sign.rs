use core::fmt;
use std::{rc::Rc, collections::HashMap};

use rand_core::{RngCore, CryptoRng};

use ff::Field;
use group::Group;

use transcript::Transcript;

use crate::{
  Curve,
  FrostError,
  MultisigParams, MultisigKeys, MultisigView,
  algorithm::Algorithm,
  validate_map
};

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
    included: &[u16],
  ) -> Result<Params<C, A>, FrostError> {
    let mut included = included.to_vec();
    (&mut included).sort_unstable();

    // Included < threshold
    if included.len() < usize::from(keys.params.t) {
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
        Err(FrostError::DuplicatedIndex(included[i].into()))?;
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
    &params.algorithm.preprocess_addendum(
      rng,
      &params.view,
      &nonces
    )
  );

  PreprocessPackage { nonces, serialized }
}

#[allow(non_snake_case)]
struct Package<C: Curve> {
  Ris: HashMap<u16, C::G>,
  R: C::G,
  share: Vec<u8>
}

// Has every signer perform the role of the signature aggregator
// Step 1 was already deprecated by performing nonce generation as needed
// Step 2 is simply the broadcast round from step 1
fn sign_with_share<C: Curve, A: Algorithm<C>>(
  params: &mut Params<C, A>,
  our_preprocess: PreprocessPackage<C>,
  mut commitments: HashMap<u16, Vec<u8>>,
  msg: &[u8],
) -> Result<(Package<C>, Vec<u8>), FrostError> {
  let multisig_params = params.multisig_params();
  validate_map(
    &mut commitments,
    &params.view.included,
    (multisig_params.i, our_preprocess.serialized)
  )?;

  {
    let transcript = params.algorithm.transcript();
    // Domain separate FROST
    transcript.domain_separate(b"FROST");
    // Include the offset, if one exists
    if let Some(offset) = params.keys.offset {
      transcript.append_message(b"offset", &C::F_to_bytes(&offset));
    }
  }

  #[allow(non_snake_case)]
  let mut B = HashMap::<u16, _>::with_capacity(params.view.included.len());

  // Get the binding factor
  let mut addendums = HashMap::new();
  let binding = {
    let transcript = params.algorithm.transcript();
    // Parse the commitments
    for l in &params.view.included {
      transcript.append_message(b"participant", &l.to_be_bytes());

      let commitments = commitments.remove(l).unwrap();
      let mut read_commitment = |c, label| {
        let commitment = &commitments[c .. c + C::G_len()];
        transcript.append_message(label, commitment);
        C::G_from_slice(commitment).map_err(|_| FrostError::InvalidCommitment(*l))
      };

      #[allow(non_snake_case)]
      let mut read_D_E = || Ok(
        [read_commitment(0, b"commitment_D")?, read_commitment(C::G_len(), b"commitment_E")?]
      );

      B.insert(*l, read_D_E()?);
      addendums.insert(*l, commitments[(C::G_len() * 2) ..].to_vec());
    }

    // Append the message to the transcript
    transcript.append_message(b"message", &C::hash_msg(&msg));

    // Calculate the binding factor
    C::hash_to_F(&transcript.challenge(b"binding"))
  };

  // Process the addendums
  for l in &params.view.included {
    params.algorithm.process_addendum(&params.view, *l, &B[l], &addendums[l])?;
  }

  #[allow(non_snake_case)]
  let mut Ris = HashMap::with_capacity(params.view.included.len());
  #[allow(non_snake_case)]
  let mut R = C::G::identity();
  for l in &params.view.included {
    #[allow(non_snake_case)]
    let this_R = B[l][0] + (B[l][1] * binding);
    Ris.insert(*l, this_R);
    R += this_R;
  }

  let share = C::F_to_bytes(
    &params.algorithm.sign_share(
      &params.view,
      R,
      binding,
      our_preprocess.nonces[0] + (our_preprocess.nonces[1] * binding),
      msg
    )
  );

  Ok((Package { Ris, R, share: share.clone() }, share))
}

// This doesn't check the signing set is as expected and unexpected changes can cause false blames
// if legitimate participants are still using the original, expected, signing set. This library
// could be made more robust in that regard
fn complete<C: Curve, A: Algorithm<C>>(
  sign_params: &Params<C, A>,
  sign: Package<C>,
  mut shares: HashMap<u16, Vec<u8>>,
) -> Result<A::Signature, FrostError> {
  let params = sign_params.multisig_params();
  validate_map(&mut shares, &sign_params.view.included, (params.i(), sign.share))?;

  let mut responses = HashMap::new();
  let mut sum = C::F::zero();
  for l in &sign_params.view.included {
    let part = C::F_from_slice(&shares[l]).map_err(|_| FrostError::InvalidShare(*l))?;
    sum += part;
    responses.insert(*l, part);
  }

  // Perform signature validation instead of individual share validation
  // For the success route, which should be much more frequent, this should be faster
  // It also acts as an integrity check of this library's signing function
  let res = sign_params.algorithm.verify(sign_params.view.group_key, sign.R, sum);
  if let Some(res) = res {
    return Ok(res);
  }

  // Find out who misbehaved
  for l in &sign_params.view.included {
    if !sign_params.algorithm.verify_share(
      sign_params.view.verification_share(*l),
      sign.Ris[l],
      responses[l]
    ) {
      Err(FrostError::InvalidShare(*l))?;
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
    commitments: HashMap<u16, Vec<u8>>,
    msg: &[u8],
  ) -> Result<Vec<u8>, FrostError>;

  /// Complete signing
  /// Takes in everyone elses' shares submitted to us as a Vec, expecting participant index =
  /// Vec index with None at index 0 and index i. Returns a byte vector representing the serialized
  /// signature
  fn complete(&mut self, shares: HashMap<u16, Vec<u8>>) -> Result<Self::Signature, FrostError>;

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
    included: &[u16],
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
    commitments: HashMap<u16, Vec<u8>>,
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

  fn complete(&mut self, shares: HashMap<u16, Vec<u8>>) -> Result<A::Signature, FrostError> {
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
