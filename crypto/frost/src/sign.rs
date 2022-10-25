use core::fmt;
use std::{
  io::{self, Read, Write},
  collections::HashMap,
};

use rand_core::{RngCore, CryptoRng};

use zeroize::{Zeroize, ZeroizeOnDrop};

use transcript::Transcript;

use group::{ff::PrimeField, GroupEncoding};

use crate::{
  curve::Curve,
  FrostError, FrostParams, FrostKeys, FrostView,
  algorithm::{AddendumSerialize, Addendum, Algorithm},
  validate_map,
};

pub(crate) use crate::nonce::*;

/// Trait enabling reading signature shares.
pub trait Readable: Sized {
  fn read<R: Read>(reader: &mut R) -> io::Result<Self>;
}

/// Trait enabling writing preprocesses and signature shares.
pub trait Writable {
  fn write<W: Write>(&self, writer: &mut W) -> io::Result<()>;
}

/// Pairing of an Algorithm with a FrostKeys instance and this specific signing set.
#[derive(Clone)]
pub struct Params<C: Curve, A: Algorithm<C>> {
  algorithm: A,
  keys: FrostKeys<C>,
  view: FrostView<C>,
}

impl<C: Curve, A: Algorithm<C>> Params<C, A> {
  pub fn new(
    algorithm: A,
    keys: FrostKeys<C>,
    included: &[u16],
  ) -> Result<Params<C, A>, FrostError> {
    let params = keys.params();

    let mut included = included.to_vec();
    included.sort_unstable();

    // Included < threshold
    if included.len() < usize::from(params.t) {
      Err(FrostError::InvalidSigningSet("not enough signers"))?;
    }
    // Invalid index
    if included[0] == 0 {
      Err(FrostError::InvalidParticipantIndex(included[0], params.n))?;
    }
    // OOB index
    if included[included.len() - 1] > params.n {
      Err(FrostError::InvalidParticipantIndex(included[included.len() - 1], params.n))?;
    }
    // Same signer included multiple times
    for i in 0 .. (included.len() - 1) {
      if included[i] == included[i + 1] {
        Err(FrostError::DuplicatedIndex(included[i]))?;
      }
    }
    // Not included
    if !included.contains(&params.i) {
      Err(FrostError::InvalidSigningSet("signing despite not being included"))?;
    }

    // Out of order arguments to prevent additional cloning
    Ok(Params { algorithm, view: keys.view(&included).unwrap(), keys })
  }

  pub fn multisig_params(&self) -> FrostParams {
    self.keys.params()
  }

  pub fn view(&self) -> FrostView<C> {
    self.view.clone()
  }
}

#[derive(Clone, PartialEq, Eq, Zeroize)]
pub struct Preprocess<C: Curve, A: Addendum> {
  pub(crate) commitments: Commitments<C>,
  pub(crate) addendum: A,
}

impl<C: Curve, A: Addendum> Writable for Preprocess<C, A> {
  fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    self.commitments.write(writer)?;
    self.addendum.write(writer)
  }
}

#[derive(Zeroize)]
pub(crate) struct PreprocessData<C: Curve, A: Addendum> {
  pub(crate) nonces: Vec<Nonce<C>>,
  pub(crate) preprocess: Preprocess<C, A>,
}

impl<C: Curve, A: Addendum> Drop for PreprocessData<C, A> {
  fn drop(&mut self) {
    self.zeroize()
  }
}
impl<C: Curve, A: Addendum> ZeroizeOnDrop for PreprocessData<C, A> {}

fn preprocess<R: RngCore + CryptoRng, C: Curve, A: Algorithm<C>>(
  rng: &mut R,
  params: &mut Params<C, A>,
) -> (PreprocessData<C, A::Addendum>, Preprocess<C, A::Addendum>) {
  let mut serialized = Vec::with_capacity(2 * C::G_len());
  let (nonces, commitments) = Commitments::new::<_, A::Transcript>(
    &mut *rng,
    params.view().secret_share(),
    &params.algorithm.nonces(),
  );

  let addendum = params.algorithm.preprocess_addendum(rng, &params.view);
  addendum.write(&mut serialized).unwrap();

  let preprocess = Preprocess { commitments, addendum };
  (PreprocessData { nonces, preprocess: preprocess.clone() }, preprocess)
}

#[allow(non_snake_case)]
struct SignData<C: Curve> {
  B: BindingFactor<C>,
  Rs: Vec<Vec<C::G>>,
  share: C::F,
}

#[derive(Clone, PartialEq, Eq, Zeroize)]
pub struct SignatureShare<C: Curve>(C::F);
impl<C: Curve> Readable for SignatureShare<C> {
  fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
    Ok(SignatureShare(C::read_F(reader)?))
  }
}
impl<C: Curve> Writable for SignatureShare<C> {
  fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(self.0.to_repr().as_ref())
  }
}

// Has every signer perform the role of the signature aggregator
// Step 1 was already deprecated by performing nonce generation as needed
// Step 2 is simply the broadcast round from step 1
fn sign_with_share<C: Curve, A: Algorithm<C>>(
  params: &mut Params<C, A>,
  mut our_preprocess: PreprocessData<C, A::Addendum>,
  mut preprocesses: HashMap<u16, Preprocess<C, A::Addendum>>,
  msg: &[u8],
) -> Result<(SignData<C>, SignatureShare<C>), FrostError> {
  let multisig_params = params.multisig_params();
  validate_map(&preprocesses, &params.view.included, multisig_params.i)?;

  {
    // Domain separate FROST
    params.algorithm.transcript().domain_separate(b"FROST");
  }

  let nonces = params.algorithm.nonces();
  #[allow(non_snake_case)]
  let mut B = BindingFactor(HashMap::<u16, _>::with_capacity(params.view.included.len()));
  {
    // Parse the preprocesses
    for l in &params.view.included {
      {
        params
          .algorithm
          .transcript()
          .append_message(b"participant", C::F::from(u64::from(*l)).to_repr().as_ref());
      }

      if *l == params.keys.params().i {
        let commitments = our_preprocess.preprocess.commitments.clone();
        commitments.transcript(params.algorithm.transcript());

        let addendum = our_preprocess.preprocess.addendum.clone();
        {
          let mut buf = vec![];
          addendum.write(&mut buf).unwrap();
          params.algorithm.transcript().append_message(b"addendum", &buf);
        }

        B.insert(*l, commitments);
        params.algorithm.process_addendum(&params.view, *l, addendum)?;
      } else {
        let preprocess = preprocesses.remove(l).unwrap();
        preprocess.commitments.transcript(params.algorithm.transcript());
        {
          let mut buf = vec![];
          preprocess.addendum.write(&mut buf).unwrap();
          params.algorithm.transcript().append_message(b"addendum", &buf);
        }

        B.insert(*l, preprocess.commitments);
        params.algorithm.process_addendum(&params.view, *l, preprocess.addendum)?;
      }
    }

    // Re-format into the FROST-expected rho transcript
    let mut rho_transcript = A::Transcript::new(b"FROST_rho");
    rho_transcript.append_message(b"message", &C::hash_msg(msg));
    rho_transcript.append_message(
      b"preprocesses",
      &C::hash_commitments(params.algorithm.transcript().challenge(b"preprocesses").as_ref()),
    );

    // Include the offset, if one exists
    // While this isn't part of the FROST-expected rho transcript, the offset being here coincides
    // with another specification (despite the transcript format being distinct)
    if let Some(offset) = params.keys.offset {
      // Transcript as a point
      // Under a coordinated model, the coordinater can be the only party to know the discrete log
      // of the offset. This removes the ability for any signer to provide the discrete log,
      // proving a key is related to another, slightly increasing security
      // While further code edits would still be required for such a model (having the offset
      // communicated as a point along with only a single party applying the offset), this means it
      // wouldn't require a transcript change as well
      rho_transcript.append_message(b"offset", (C::generator() * offset).to_bytes().as_ref());
    }

    // Generate the per-signer binding factors
    B.calculate_binding_factors(&mut rho_transcript);

    // Merge the rho transcript back into the global one to ensure its advanced, while
    // simultaneously committing to everything
    params
      .algorithm
      .transcript()
      .append_message(b"rho_transcript", rho_transcript.challenge(b"merge").as_ref());
  }

  #[allow(non_snake_case)]
  let Rs = B.nonces(&nonces);

  let our_binding_factors = B.binding_factors(multisig_params.i());
  let mut nonces = our_preprocess
    .nonces
    .iter()
    .enumerate()
    .map(|(n, nonces)| nonces.0[0] + (nonces.0[1] * our_binding_factors[n]))
    .collect::<Vec<_>>();
  our_preprocess.nonces.zeroize();

  let share = params.algorithm.sign_share(&params.view, &Rs, &nonces, msg);
  nonces.zeroize();

  Ok((SignData { B, Rs, share }, SignatureShare(share)))
}

fn complete<C: Curve, A: Algorithm<C>>(
  sign_params: &Params<C, A>,
  sign: SignData<C>,
  mut shares: HashMap<u16, SignatureShare<C>>,
) -> Result<A::Signature, FrostError> {
  let params = sign_params.multisig_params();
  validate_map(&shares, &sign_params.view.included, params.i)?;

  let mut responses = HashMap::new();
  responses.insert(params.i(), sign.share);
  let mut sum = sign.share;
  for (l, share) in shares.drain() {
    responses.insert(l, share.0);
    sum += share.0;
  }

  // Perform signature validation instead of individual share validation
  // For the success route, which should be much more frequent, this should be faster
  // It also acts as an integrity check of this library's signing function
  if let Some(sig) = sign_params.algorithm.verify(sign_params.view.group_key, &sign.Rs, sum) {
    return Ok(sig);
  }

  // Find out who misbehaved. It may be beneficial to randomly sort this to have detection be
  // within n / 2 on average, and not gameable to n, though that should be minor
  for l in &sign_params.view.included {
    if !sign_params.algorithm.verify_share(
      sign_params.view.verification_share(*l),
      &sign.B.bound(*l),
      responses[l],
    ) {
      Err(FrostError::InvalidShare(*l))?;
    }
  }

  // If everyone has a valid share and there were enough participants, this should've worked
  Err(FrostError::InternalError("everyone had a valid share yet the signature was still invalid"))
}

/// Trait for the initial state machine of a two-round signing protocol.
pub trait PreprocessMachine {
  type Preprocess: Clone + PartialEq + Writable;
  type Signature: Clone + PartialEq + fmt::Debug;
  type SignMachine: SignMachine<Self::Signature, Preprocess = Self::Preprocess>;

  /// Perform the preprocessing round required in order to sign.
  /// Returns a byte vector to be broadcast to all participants, over an authenticated channel.
  fn preprocess<R: RngCore + CryptoRng>(self, rng: &mut R)
    -> (Self::SignMachine, Self::Preprocess);
}

/// Trait for the second machine of a two-round signing protocol.
pub trait SignMachine<S> {
  type Preprocess: Clone + PartialEq + Writable;
  type SignatureShare: Clone + PartialEq + Readable + Writable;
  type SignatureMachine: SignatureMachine<S, SignatureShare = Self::SignatureShare>;

  /// Read a Preprocess message.
  fn read_preprocess<R: Read>(&self, reader: &mut R) -> io::Result<Self::Preprocess>;

  /// Sign a message.
  /// Takes in the participants' preprocesses. Returns a byte vector representing a signature share
  /// to be broadcast to all participants, over an authenticated channel.
  fn sign(
    self,
    commitments: HashMap<u16, Self::Preprocess>,
    msg: &[u8],
  ) -> Result<(Self::SignatureMachine, Self::SignatureShare), FrostError>;
}

/// Trait for the final machine of a two-round signing protocol.
pub trait SignatureMachine<S> {
  type SignatureShare: Clone + PartialEq + Readable + Writable;

  /// Complete signing.
  /// Takes in everyone elses' shares. Returns the signature.
  fn complete(self, shares: HashMap<u16, Self::SignatureShare>) -> Result<S, FrostError>;
}

/// State machine which manages signing for an arbitrary signature algorithm.
pub struct AlgorithmMachine<C: Curve, A: Algorithm<C>> {
  params: Params<C, A>,
}

/// Next step of the state machine for the signing process.
pub struct AlgorithmSignMachine<C: Curve, A: Algorithm<C>> {
  params: Params<C, A>,
  preprocess: PreprocessData<C, A::Addendum>,
}

/// Final step of the state machine for the signing process.
pub struct AlgorithmSignatureMachine<C: Curve, A: Algorithm<C>> {
  params: Params<C, A>,
  sign: SignData<C>,
}

impl<C: Curve, A: Algorithm<C>> AlgorithmMachine<C, A> {
  /// Creates a new machine to generate a signature with the specified keys.
  pub fn new(
    algorithm: A,
    keys: FrostKeys<C>,
    included: &[u16],
  ) -> Result<AlgorithmMachine<C, A>, FrostError> {
    Ok(AlgorithmMachine { params: Params::new(algorithm, keys, included)? })
  }

  #[cfg(any(test, feature = "tests"))]
  pub(crate) fn unsafe_override_preprocess(
    self,
    preprocess: PreprocessData<C, A::Addendum>,
  ) -> AlgorithmSignMachine<C, A> {
    AlgorithmSignMachine { params: self.params, preprocess }
  }
}

impl<C: Curve, A: Algorithm<C>> PreprocessMachine for AlgorithmMachine<C, A> {
  type Preprocess = Preprocess<C, A::Addendum>;
  type Signature = A::Signature;
  type SignMachine = AlgorithmSignMachine<C, A>;

  fn preprocess<R: RngCore + CryptoRng>(
    self,
    rng: &mut R,
  ) -> (Self::SignMachine, Preprocess<C, A::Addendum>) {
    let mut params = self.params;
    let (preprocess, public) = preprocess::<R, C, A>(rng, &mut params);
    (AlgorithmSignMachine { params, preprocess }, public)
  }
}

impl<C: Curve, A: Algorithm<C>> SignMachine<A::Signature> for AlgorithmSignMachine<C, A> {
  type Preprocess = Preprocess<C, A::Addendum>;
  type SignatureShare = SignatureShare<C>;
  type SignatureMachine = AlgorithmSignatureMachine<C, A>;

  fn read_preprocess<R: Read>(&self, reader: &mut R) -> io::Result<Self::Preprocess> {
    Ok(Preprocess {
      commitments: Commitments::read::<_, A::Transcript>(reader, &self.params.algorithm.nonces())?,
      addendum: self.params.algorithm.read_addendum(reader)?,
    })
  }

  fn sign(
    self,
    commitments: HashMap<u16, Preprocess<C, A::Addendum>>,
    msg: &[u8],
  ) -> Result<(Self::SignatureMachine, SignatureShare<C>), FrostError> {
    let mut params = self.params;
    let (sign, public) = sign_with_share(&mut params, self.preprocess, commitments, msg)?;
    Ok((AlgorithmSignatureMachine { params, sign }, public))
  }
}

impl<C: Curve, A: Algorithm<C>> SignatureMachine<A::Signature> for AlgorithmSignatureMachine<C, A> {
  type SignatureShare = SignatureShare<C>;
  fn complete(self, shares: HashMap<u16, SignatureShare<C>>) -> Result<A::Signature, FrostError> {
    complete(&self.params, self.sign, shares)
  }
}
