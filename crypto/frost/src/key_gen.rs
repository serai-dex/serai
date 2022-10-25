use std::{
  marker::PhantomData,
  io::{self, Read, Write},
  collections::HashMap,
};

use rand_core::{RngCore, CryptoRng};

use zeroize::{Zeroize, ZeroizeOnDrop};

use group::{
  ff::{Field, PrimeField},
  GroupEncoding,
};

use multiexp::{multiexp_vartime, BatchVerifier};

use crate::{
  curve::Curve,
  FrostError, FrostParams, FrostCore,
  schnorr::{self, SchnorrSignature},
  validate_map,
};

#[allow(non_snake_case)]
fn challenge<C: Curve>(context: &str, l: u16, R: &[u8], Am: &[u8]) -> C::F {
  const DST: &[u8] = b"FROST Schnorr Proof of Knowledge";

  // Uses hash_msg to get a fixed size value out of the context string
  let mut transcript = C::hash_msg(context.as_bytes());
  transcript.extend(l.to_be_bytes());
  transcript.extend(R);
  transcript.extend(Am);
  C::hash_to_F(DST, &transcript)
}

/// Commitments message to be broadcast to all other parties.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Commitments<C: Curve>(Vec<C::G>, Vec<u8>, SchnorrSignature<C>);
impl<C: Curve> Commitments<C> {
  pub fn read<R: Read>(reader: &mut R, params: FrostParams) -> io::Result<Self> {
    let mut commitments = Vec::with_capacity(params.t().into());
    let mut serialized = Vec::with_capacity(usize::from(params.t()) * C::G_len());
    for _ in 0 .. params.t() {
      let mut buf = <C::G as GroupEncoding>::Repr::default();
      reader.read_exact(buf.as_mut())?;

      commitments.push(C::read_G(&mut buf.as_ref())?);
      serialized.extend(buf.as_ref());
    }

    Ok(Commitments(commitments, serialized, SchnorrSignature::read(reader)?))
  }

  pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(&self.1)?;
    self.2.write(writer)
  }
}

// Implements steps 1 through 3 of round 1 of FROST DKG. Returns the coefficients, commitments, and
// the commitments to be broadcasted over an authenticated channel to all parties
fn generate_key_r1<R: RngCore + CryptoRng, C: Curve>(
  rng: &mut R,
  params: &FrostParams,
  context: &str,
) -> (Vec<C::F>, Vec<C::G>, Commitments<C>) {
  let t = usize::from(params.t);
  let mut coefficients = Vec::with_capacity(t);
  let mut commitments = Vec::with_capacity(t);
  let mut serialized = Vec::with_capacity(t * C::G_len());

  for i in 0 .. t {
    // Step 1: Generate t random values to form a polynomial with
    coefficients.push(C::random_F(&mut *rng));
    // Step 3: Generate public commitments
    commitments.push(C::generator() * coefficients[i]);
    serialized.extend(commitments[i].to_bytes().as_ref());
  }

  // Step 2: Provide a proof of knowledge
  let mut r = C::random_F(rng);
  let sig = schnorr::sign::<C>(
    coefficients[0],
    // This could be deterministic as the PoK is a singleton never opened up to cooperative
    // discussion
    // There's no reason to spend the time and effort to make this deterministic besides a
    // general obsession with canonicity and determinism though
    r,
    challenge::<C>(context, params.i(), (C::generator() * r).to_bytes().as_ref(), &serialized),
  );
  r.zeroize();

  // Step 4: Broadcast
  (coefficients, commitments.clone(), Commitments(commitments, serialized, sig))
}

// Verify the received data from the first round of key generation
fn verify_r1<R: RngCore + CryptoRng, C: Curve>(
  rng: &mut R,
  params: &FrostParams,
  context: &str,
  our_commitments: Vec<C::G>,
  mut msgs: HashMap<u16, Commitments<C>>,
) -> Result<HashMap<u16, Vec<C::G>>, FrostError> {
  validate_map(&msgs, &(1 ..= params.n()).collect::<Vec<_>>(), params.i())?;

  let mut signatures = Vec::with_capacity(usize::from(params.n() - 1));
  let mut commitments = msgs
    .drain()
    .map(|(l, msg)| {
      // Step 5: Validate each proof of knowledge
      // This is solely the prep step for the latter batch verification
      signatures.push((
        l,
        msg.0[0],
        challenge::<C>(context, l, msg.2.R.to_bytes().as_ref(), &msg.1),
        msg.2,
      ));

      (l, msg.0)
    })
    .collect::<HashMap<_, _>>();

  schnorr::batch_verify(rng, &signatures).map_err(FrostError::InvalidProofOfKnowledge)?;

  commitments.insert(params.i, our_commitments);
  Ok(commitments)
}

fn polynomial<F: PrimeField>(coefficients: &[F], l: u16) -> F {
  let l = F::from(u64::from(l));
  let mut share = F::zero();
  for (idx, coefficient) in coefficients.iter().rev().enumerate() {
    share += coefficient;
    if idx != (coefficients.len() - 1) {
      share *= l;
    }
  }
  share
}

/// Secret share, to be sent only to the party it's intended for, over an encrypted and
/// authenticated channel.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct SecretShare<C: Curve>(C::F);
impl<C: Curve> SecretShare<C> {
  pub fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
    Ok(SecretShare(C::read_F(reader)?))
  }

  pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(self.0.to_repr().as_ref())
  }
}

impl<C: Curve> Drop for SecretShare<C> {
  fn drop(&mut self) {
    self.zeroize();
  }
}
impl<C: Curve> ZeroizeOnDrop for SecretShare<C> {}

// Calls round 1, step 5 and implements round 2, step 1 of FROST key generation
// Returns our secret share part, commitments for the next step, and a vector for each
// counterparty to receive
fn generate_key_r2<R: RngCore + CryptoRng, C: Curve>(
  rng: &mut R,
  params: &FrostParams,
  context: &str,
  coefficients: &mut Vec<C::F>,
  our_commitments: Vec<C::G>,
  msgs: HashMap<u16, Commitments<C>>,
) -> Result<(C::F, HashMap<u16, Vec<C::G>>, HashMap<u16, SecretShare<C>>), FrostError> {
  let commitments = verify_r1::<_, C>(rng, params, context, our_commitments, msgs)?;

  // Step 1: Generate secret shares for all other parties
  let mut res = HashMap::new();
  for l in 1 ..= params.n() {
    // Don't insert our own shares to the byte buffer which is meant to be sent around
    // An app developer could accidentally send it. Best to keep this black boxed
    if l == params.i() {
      continue;
    }

    res.insert(l, SecretShare(polynomial(coefficients, l)));
  }

  // Calculate our own share
  let share = polynomial(coefficients, params.i());

  coefficients.zeroize();

  Ok((share, commitments, res))
}

/// Finishes round 2 and returns both the secret share and the serialized public key.
/// This key MUST NOT be considered usable until all parties confirm they have completed the
/// protocol without issue.
fn complete_r2<R: RngCore + CryptoRng, C: Curve>(
  rng: &mut R,
  params: FrostParams,
  mut secret_share: C::F,
  commitments: &mut HashMap<u16, Vec<C::G>>,
  mut shares: HashMap<u16, SecretShare<C>>,
) -> Result<FrostCore<C>, FrostError> {
  validate_map(&shares, &(1 ..= params.n()).collect::<Vec<_>>(), params.i())?;

  // Calculate the exponent for a given participant and apply it to a series of commitments
  // Initially used with the actual commitments to verify the secret share, later used with stripes
  // to generate the verification shares
  let exponential = |i: u16, values: &[_]| {
    let i = C::F::from(i.into());
    let mut res = Vec::with_capacity(params.t().into());
    (0 .. usize::from(params.t())).into_iter().fold(C::F::one(), |exp, l| {
      res.push((exp, values[l]));
      exp * i
    });
    res
  };

  let mut batch = BatchVerifier::new(shares.len());
  for (l, mut share) in shares.drain() {
    secret_share += share.0;

    // This can be insecurely linearized from n * t to just n using the below sums for a given
    // stripe. Doing so uses naive addition which is subject to malleability. The only way to
    // ensure that malleability isn't present is to use this n * t algorithm, which runs
    // per sender and not as an aggregate of all senders, which also enables blame
    let mut values = exponential(params.i, &commitments[&l]);
    values.push((-share.0, C::generator()));
    share.zeroize();

    batch.queue(rng, l, values);
  }
  batch.verify_with_vartime_blame().map_err(FrostError::InvalidCommitment)?;

  // Stripe commitments per t and sum them in advance. Calculating verification shares relies on
  // these sums so preprocessing them is a massive speedup
  // If these weren't just sums, yet the tables used in multiexp, this would be further optimized
  // As of right now, each multiexp will regenerate them
  let mut stripes = Vec::with_capacity(usize::from(params.t()));
  for t in 0 .. usize::from(params.t()) {
    stripes.push(commitments.values().map(|commitments| commitments[t]).sum());
  }

  // Calculate each user's verification share
  let mut verification_shares = HashMap::new();
  for i in 1 ..= params.n() {
    verification_shares.insert(i, multiexp_vartime(&exponential(i, &stripes)));
  }
  // Removing this check would enable optimizing the above from t + (n * t) to t + ((n - 1) * t)
  debug_assert_eq!(C::generator() * secret_share, verification_shares[&params.i()]);

  Ok(FrostCore { params, secret_share, group_key: stripes[0], verification_shares })
}

/// State machine to begin the key generation protocol.
pub struct KeyGenMachine<C: Curve> {
  params: FrostParams,
  context: String,
  _curve: PhantomData<C>,
}

/// Advancement of the key generation state machine.
#[derive(Zeroize)]
pub struct SecretShareMachine<C: Curve> {
  #[zeroize(skip)]
  params: FrostParams,
  context: String,
  coefficients: Vec<C::F>,
  #[zeroize(skip)]
  our_commitments: Vec<C::G>,
}

impl<C: Curve> Drop for SecretShareMachine<C> {
  fn drop(&mut self) {
    self.zeroize()
  }
}
impl<C: Curve> ZeroizeOnDrop for SecretShareMachine<C> {}

/// Final step of the key generation protocol.
#[derive(Zeroize)]
pub struct KeyMachine<C: Curve> {
  #[zeroize(skip)]
  params: FrostParams,
  secret: C::F,
  #[zeroize(skip)]
  commitments: HashMap<u16, Vec<C::G>>,
}

impl<C: Curve> Drop for KeyMachine<C> {
  fn drop(&mut self) {
    self.zeroize()
  }
}
impl<C: Curve> ZeroizeOnDrop for KeyMachine<C> {}

impl<C: Curve> KeyGenMachine<C> {
  /// Creates a new machine to generate a key for the specified curve in the specified multisig.
  // The context string should be unique among multisigs.
  pub fn new(params: FrostParams, context: String) -> KeyGenMachine<C> {
    KeyGenMachine { params, context, _curve: PhantomData }
  }

  /// Start generating a key according to the FROST DKG spec.
  /// Returns a commitments message to be sent to all parties over an authenticated
  /// channel. If any party submits multiple sets of commitments, they MUST be treated as
  /// malicious.
  pub fn generate_coefficients<R: RngCore + CryptoRng>(
    self,
    rng: &mut R,
  ) -> (SecretShareMachine<C>, Commitments<C>) {
    let (coefficients, our_commitments, commitments) =
      generate_key_r1::<_, C>(rng, &self.params, &self.context);

    (
      SecretShareMachine {
        params: self.params,
        context: self.context,
        coefficients,
        our_commitments,
      },
      commitments,
    )
  }
}

impl<C: Curve> SecretShareMachine<C> {
  /// Continue generating a key.
  /// Takes in everyone else's commitments. Returns a HashMap of byte vectors representing secret
  /// shares. These MUST be encrypted and only then sent to their respective participants.
  pub fn generate_secret_shares<R: RngCore + CryptoRng>(
    mut self,
    rng: &mut R,
    commitments: HashMap<u16, Commitments<C>>,
  ) -> Result<(KeyMachine<C>, HashMap<u16, SecretShare<C>>), FrostError> {
    let (secret, commitments, shares) = generate_key_r2::<_, C>(
      rng,
      &self.params,
      &self.context,
      &mut self.coefficients,
      self.our_commitments.clone(),
      commitments,
    )?;
    Ok((KeyMachine { params: self.params, secret, commitments }, shares))
  }
}

impl<C: Curve> KeyMachine<C> {
  /// Complete key generation.
  /// Takes in everyone elses' shares submitted to us. Returns a FrostCore object representing the
  /// generated keys. Successful protocol completion MUST be confirmed by all parties before these
  /// keys may be safely used.
  pub fn complete<R: RngCore + CryptoRng>(
    mut self,
    rng: &mut R,
    shares: HashMap<u16, SecretShare<C>>,
  ) -> Result<FrostCore<C>, FrostError> {
    complete_r2(rng, self.params, self.secret, &mut self.commitments, shares)
  }
}
