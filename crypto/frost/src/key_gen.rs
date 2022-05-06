use core::{convert::TryFrom, cmp::min, fmt};

use rand_core::{RngCore, CryptoRng};

use ff::{Field, PrimeField};
use group::Group;

use crate::{Curve, MultisigParams, MultisigKeys, FrostError};

#[allow(non_snake_case)]
fn challenge<C: Curve>(l: usize, context: &str, R: &[u8], Am: &[u8]) -> C::F {
  let mut c = Vec::with_capacity(2 + context.len() + R.len() + Am.len());
  c.extend(&u16::try_from(l).unwrap().to_be_bytes());
  c.extend(context.as_bytes());
  c.extend(R);  // R
  c.extend(Am); // A of the first commitment, which is what we're proving we have the private key
                // for
                // m of the rest of the commitments, authenticating them
  C::hash_to_F(&c)
}

// Implements steps 1 through 3 of round 1 of FROST DKG. Returns the coefficients, commitments, and
// the serialized commitments to be broadcasted over an authenticated channel to all parties
// TODO: This potentially could return a much more robust serialized message, including a signature
// of its entirety. The issue is it can't use its own key as it has no chain of custody behind it.
// While we could ask for a key to be passed in, explicitly declaring the needed for authenticated
// communications in the API itself, systems will likely already provide a authenticated
// communication method making this redundant. It also doesn't guarantee the system which passed
// the key is correctly using it, meaning we can only minimize risk so much
// One notable improvement would be to include the index in the message. While the system must
// still track this to determine if it's ready for the next step, and to remove duplicates, it
// would ensure no counterparties presume the same index and this system didn't mislabel a
// counterparty
fn generate_key_r1<R: RngCore + CryptoRng, C: Curve>(
  rng: &mut R,
  params: &MultisigParams,
  context: &str,
) -> (Vec<C::F>, Vec<C::G>, Vec<u8>) {
  let mut coefficients = Vec::with_capacity(params.t);
  let mut commitments = Vec::with_capacity(params.t);
  let mut serialized = Vec::with_capacity((C::G_len() * params.t) + C::G_len() + C::F_len());
  for j in 0 .. params.t {
    // Step 1: Generate t random values to form a polynomial with
    coefficients.push(C::F::random(&mut *rng));
    // Step 3: Generate public commitments
    commitments.push(C::generator_table() * coefficients[j]);
    // Serialize them for publication
    serialized.extend(&C::G_to_bytes(&commitments[j]));
  }

  // Step 2: Provide a proof of knowledge
  // This can be deterministic as the PoK is a singleton never opened up to cooperative discussion
  // There's also no reason to spend the time and effort to make this deterministic besides a
  // general obsession with canonicity and determinism
  let k = C::F::random(rng);
  #[allow(non_snake_case)]
  let R = C::generator_table() * k;
  let c = challenge::<C>(params.i, context, &C::G_to_bytes(&R), &serialized);
  let s = k + (coefficients[0] * c);

  serialized.extend(&C::G_to_bytes(&R));
  serialized.extend(&C::F_to_bytes(&s));

  // Step 4: Broadcast
  (coefficients, commitments, serialized)
}

// Verify the received data from the first round of key generation
fn verify_r1<R: RngCore + CryptoRng, C: Curve>(
  rng: &mut R,
  params: &MultisigParams,
  context: &str,
  our_commitments: Vec<C::G>,
  serialized: &[Vec<u8>],
) -> Result<Vec<Vec<C::G>>, FrostError> {
  // Deserialize all of the commitments, validating the input buffers as needed
  if serialized.len() != (params.n + 1) {
    Err(
      // Prevents a panic if serialized.len() == 0
      FrostError::InvalidParticipantQuantity(params.n, serialized.len() - min(1, serialized.len()))
    )?;
  }

  // Expect a null set of commitments for index 0 so the vector is guaranteed to line up with
  // actual indexes. Even if we did the offset internally, the system would need to write the vec
  // with the same offset in mind. Therefore, this trick which is probably slightly less efficient
  // yet keeps everything simple is preferred
  if serialized[0] != vec![] {
    Err(FrostError::NonEmptyParticipantZero)?;
  }

  let commitments_len = params.t * C::G_len();
  let mut commitments = Vec::with_capacity(params.n + 1);
  commitments.push(vec![]);

  let signature_len = C::G_len() + C::F_len();
  let mut first = true;
  let mut scalars = Vec::with_capacity((params.n - 1) * 3);
  let mut points = Vec::with_capacity((params.n - 1) * 3);
  for l in 1 ..= params.n {
    if l == params.i {
      if serialized[l].len() != 0 {
        Err(FrostError::DuplicatedIndex(l))?;
      }
      commitments.push(vec![]);
      continue;
    }

    if serialized[l].len() != (commitments_len + signature_len) {
      // Return an error with an approximation for how many commitments were included
      // Prevents errors if not even the signature was included
      if serialized[l].len() < signature_len {
        Err(FrostError::InvalidCommitmentQuantity(l, params.t, 0))?;
      }

      Err(
        FrostError::InvalidCommitmentQuantity(
          l,
          params.t,
          // Could technically be x.y despite this returning x, yet any y is negligible
          // It could help with debugging to know a partial piece of data was read but this error
          // alone should be enough
          (serialized[l].len() - signature_len) / C::G_len()
        )
      )?;
    }

    commitments.push(Vec::with_capacity(params.t));
    for o in 0 .. params.t {
      commitments[l].push(
        C::G_from_slice(
          &serialized[l][(o * C::G_len()) .. ((o + 1) * C::G_len())]
        ).map_err(|_| FrostError::InvalidCommitment(l))?
      );
    }

    // Step 5: Validate each proof of knowledge (prep)
    let mut u = C::F::one();
    if !first {
      u = C::F::random(&mut *rng);
    }

    scalars.push(u);
    points.push(
      C::G_from_slice(
        &serialized[l][commitments_len .. commitments_len + C::G_len()]
      ).map_err(|_| FrostError::InvalidProofOfKnowledge(l))?
    );

    scalars.push(
      -C::F_from_slice(
        &serialized[l][commitments_len + C::G_len() .. serialized[l].len()]
      ).map_err(|_| FrostError::InvalidProofOfKnowledge(l))? * u
    );
    points.push(C::generator());

    let c = challenge::<C>(
      l,
      context,
      &serialized[l][commitments_len .. commitments_len + C::G_len()],
      &serialized[l][0 .. commitments_len]
    );

    if first {
      scalars.push(c);
      first = false;
    } else {
      scalars.push(c * u);
    }
    points.push(commitments[l][0]);
  }

  // Step 5: Implementation
  // Uses batch verification to optimize the success case dramatically
  // On failure, the cost is now this + blame, yet that should happen infrequently
  if C::multiexp_vartime(&scalars, &points) != C::G::identity() {
    for l in 1 ..= params.n {
      if l == params.i {
        continue;
      }

      #[allow(non_snake_case)]
      let R = C::G_from_slice(
        &serialized[l][commitments_len .. commitments_len + C::G_len()]
      ).map_err(|_| FrostError::InvalidProofOfKnowledge(l))?;

      let s = C::F_from_slice(
        &serialized[l][commitments_len + C::G_len() .. serialized[l].len()]
      ).map_err(|_| FrostError::InvalidProofOfKnowledge(l))?;

      let c = challenge::<C>(
        l,
        context,
        &serialized[l][commitments_len .. commitments_len + C::G_len()],
        &serialized[l][0 .. commitments_len]
      );

      if R != ((C::generator_table() * s) + (commitments[l][0] * (C::F::zero() - &c))) {
        Err(FrostError::InvalidProofOfKnowledge(l))?;
      }
    }

    Err(FrostError::InternalError("batch validation is broken".to_string()))?;
  }

  // Write in our own commitments
  commitments[params.i] = our_commitments;

  Ok(commitments)
}

fn polynomial<F: PrimeField>(
  coefficients: &[F],
  i: usize
) -> F {
  let i = F::from(u64::try_from(i).unwrap());
  let mut share = F::zero();
  for (idx, coefficient) in coefficients.iter().rev().enumerate() {
    share += coefficient;
    if idx != (coefficients.len() - 1) {
      share *= i;
    }
  }
  share
}

// Implements round 1, step 5 and round 2, step 1 of FROST key generation
// Returns our secret share part, commitments for the next step, and a vector for each
// counterparty to receive
fn generate_key_r2<R: RngCore + CryptoRng, C: Curve>(
  rng: &mut R,
  params: &MultisigParams,
  context: &str,
  coefficients: Vec<C::F>,
  our_commitments: Vec<C::G>,
  commitments: &[Vec<u8>],
) -> Result<(C::F, Vec<Vec<C::G>>, Vec<Vec<u8>>), FrostError> {
  let commitments = verify_r1::<R, C>(rng, params, context, our_commitments, commitments)?;

  // Step 1: Generate secret shares for all other parties
  let mut res = Vec::with_capacity(params.n + 1);
  res.push(vec![]);
  for i in 1 ..= params.n {
    // Don't push our own to the byte buffer which is meant to be sent around
    // An app developer could accidentally send it. Best to keep this black boxed
    if i == params.i {
      res.push(vec![]);
      continue
    }

    res.push(C::F_to_bytes(&polynomial(&coefficients, i)));
  }

  // Calculate our own share
  let share = polynomial(&coefficients, params.i);

  // The secret shares are discarded here, not cleared. While any system which leaves its memory
  // accessible is likely totally lost already, making the distinction meaningless when the key gen
  // system acts as the signer system and therefore actively holds the signing key anyways, it
  // should be overwritten with /dev/urandom in the name of security (which still doesn't meet
  // requirements for secure data deletion yet those requirements expect hardware access which is
  // far past what this library can reasonably counter)
  // TODO: Zero out the coefficients

  Ok((share, commitments, res))
}

/// Finishes round 2 and returns both the secret share and the serialized public key.
/// This key is not usable until all parties confirm they have completed the protocol without
/// issue, yet simply confirming protocol completion without issue is enough to confirm the same
/// key was generated as long as a lack of duplicated commitments was also confirmed when they were
/// broadcasted initially
fn complete_r2<C: Curve>(
  params: MultisigParams,
  share: C::F,
  commitments: &[Vec<C::G>],
  // Vec to preserve ownership
  serialized: Vec<Vec<u8>>,
) -> Result<MultisigKeys<C>, FrostError> {
  // Step 2. Verify each share
  if serialized.len() != (params.n + 1) {
    Err(
      FrostError::InvalidParticipantQuantity(params.n, serialized.len() - min(1, serialized.len()))
    )?;
  }

  if (commitments[0].len() != 0) || (serialized[0].len() != 0) {
    Err(FrostError::NonEmptyParticipantZero)?;
  }

  // Deserialize them
  let mut shares: Vec<C::F> = vec![C::F::zero()];
  for i in 1 .. serialized.len() {
    if i == params.i {
      if serialized[i].len() != 0 {
        Err(FrostError::DuplicatedIndex(i))?;
      }
      shares.push(C::F::zero());
      continue;
    }
    shares.push(C::F_from_slice(&serialized[i]).map_err(|_| FrostError::InvalidShare(i))?);
  }


  for l in 1 ..= params.n {
    if l == params.i {
      continue;
    }

    let i_scalar = C::F::from(u64::try_from(params.i).unwrap());
    let mut exp = C::F::one();
    let mut exps = Vec::with_capacity(params.t);
    for _ in 0 .. params.t {
      exps.push(exp);
      exp *= i_scalar;
    }

    // Doesn't use multiexp_vartime with -shares[l] due to not being able to push to commitments
    if C::multiexp_vartime(&exps, &commitments[l]) != (C::generator_table() * shares[l]) {
      Err(FrostError::InvalidCommitment(l))?;
    }
  }

  // TODO: Clear the original share

  let mut secret_share = share;
  for remote_share in shares {
    secret_share += remote_share;
  }

  let mut verification_shares = vec![C::G::identity()];
  for i in 1 ..= params.n {
    let mut exps = vec![];
    let mut cs = vec![];
    for j in 1 ..= params.n {
      for k in 0 .. params.t {
        let mut exp = C::F::one();
        for _ in 0 .. k {
          exp *= C::F::from(u64::try_from(i).unwrap());
        }
        exps.push(exp);
        cs.push(commitments[j][k]);
      }
    }
    verification_shares.push(C::multiexp_vartime(&exps, &cs));
  }

  debug_assert_eq!(
    C::generator_table() * secret_share,
    verification_shares[params.i]
  );

  let mut group_key = C::G::identity();
  for j in 1 ..= params.n {
    group_key += commitments[j][0];
  }

  // TODO: Clear serialized and shares

  Ok(MultisigKeys { params, secret_share, group_key, verification_shares, offset: None } )
}

/// State of a Key Generation machine
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
  Fresh,
  GeneratedCoefficients,
  GeneratedSecretShares,
  Complete,
}

impl fmt::Display for State {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "{:?}", self)
  }
}

/// State machine which manages key generation
#[allow(non_snake_case)]
pub struct StateMachine<C: Curve> {
  params: MultisigParams,
  context: String,
  state: State,
  coefficients: Option<Vec<C::F>>,
  our_commitments: Option<Vec<C::G>>,
  secret: Option<C::F>,
  commitments: Option<Vec<Vec<C::G>>>
}

impl<C: Curve> StateMachine<C> {
  /// Creates a new machine to generate a key for the specified curve in the specified multisig
  // The context string must be unique among multisigs
  pub fn new(params: MultisigParams, context: String) -> StateMachine<C> {
    StateMachine {
      params,
      context,
      state: State::Fresh,
      coefficients: None,
      our_commitments: None,
      secret: None,
      commitments: None
    }
  }

  /// Start generating a key according to the FROST DKG spec
  /// Returns a serialized list of commitments to be sent to all parties over an authenticated
  /// channel. If any party submits multiple sets of commitments, they MUST be treated as malicious
  pub fn generate_coefficients<R: RngCore + CryptoRng>(
    &mut self,
    rng: &mut R
  ) -> Result<Vec<u8>, FrostError> {
    if self.state != State::Fresh {
      Err(FrostError::InvalidKeyGenTransition(State::Fresh, self.state))?;
    }

    let (coefficients, commitments, serialized) = generate_key_r1::<R, C>(
      rng,
      &self.params,
      &self.context,
    );

    self.coefficients = Some(coefficients);
    self.our_commitments = Some(commitments);
    self.state = State::GeneratedCoefficients;
    Ok(serialized)
  }

  /// Continue generating a key
  /// Takes in everyone else's commitments, which are expected to be in a Vec where participant
  /// index = Vec index. An empty vector is expected at index 0 to allow for this. An empty vector
  /// is also expected at index i which is locally handled. Returns a byte vector representing a
  /// secret share for each other participant which should be encrypted before sending
  pub fn generate_secret_shares<R: RngCore + CryptoRng>(
    &mut self,
    rng: &mut R,
    commitments: Vec<Vec<u8>>,
  ) -> Result<Vec<Vec<u8>>, FrostError> {
    if self.state != State::GeneratedCoefficients {
      Err(FrostError::InvalidKeyGenTransition(State::GeneratedCoefficients, self.state))?;
    }

    let (secret, commitments, shares) = generate_key_r2::<R, C>(
      rng,
      &self.params,
      &self.context,
      self.coefficients.take().unwrap(),
      self.our_commitments.take().unwrap(),
      &commitments,
    )?;

    self.secret = Some(secret);
    self.commitments = Some(commitments);
    self.state = State::GeneratedSecretShares;
    Ok(shares)
  }

  /// Complete key generation
  /// Takes in everyone elses' shares submitted to us as a Vec, expecting participant index =
  /// Vec index with an empty vector at index 0 and index i. Returns a byte vector representing the
  /// group's public key, while setting a valid secret share inside the machine. > t participants
  /// must report completion without issue before this key can be considered usable, yet you should
  /// wait for all participants to report as such
  pub fn complete(
    &mut self,
    shares: Vec<Vec<u8>>,
) -> Result<MultisigKeys<C>, FrostError> {
    if self.state != State::GeneratedSecretShares {
      Err(FrostError::InvalidKeyGenTransition(State::GeneratedSecretShares, self.state))?;
    }

    let keys = complete_r2(
      self.params,
      self.secret.take().unwrap(),
      &self.commitments.take().unwrap(),
      shares,
    )?;

    self.state = State::Complete;
    Ok(keys)
  }

  pub fn params(&self) -> MultisigParams {
    self.params.clone()
  }

  pub fn state(&self) -> State {
    self.state
  }
}
