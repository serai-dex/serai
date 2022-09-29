use core::fmt;
use std::{
  io::{Read, Cursor},
  collections::HashMap,
};

use rand_core::{RngCore, CryptoRng};

use zeroize::{Zeroize, ZeroizeOnDrop};

use transcript::Transcript;

use group::{
  ff::{Field, PrimeField},
  Group, GroupEncoding,
};
use multiexp::multiexp_vartime;

use dleq::DLEqProof;

use crate::{
  curve::Curve, FrostError, FrostParams, FrostKeys, FrostView, algorithm::Algorithm, validate_map,
};

/// Pairing of an Algorithm with a FrostKeys instance and this specific signing set.
#[derive(Clone)]
pub struct Params<C: Curve, A: Algorithm<C>> {
  algorithm: A,
  keys: FrostKeys<C>,
  view: FrostView<C>,
}

// Currently public to enable more complex operations as desired, yet solely used in testing
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

fn nonce_transcript<T: Transcript>() -> T {
  T::new(b"FROST_nonce_dleq")
}

#[derive(Zeroize)]
pub(crate) struct PreprocessPackage<C: Curve> {
  pub(crate) nonces: Vec<[C::F; 2]>,
  #[zeroize(skip)]
  pub(crate) commitments: Vec<Vec<[C::G; 2]>>,
  pub(crate) addendum: Vec<u8>,
}

impl<C: Curve> Drop for PreprocessPackage<C> {
  fn drop(&mut self) {
    self.zeroize()
  }
}
impl<C: Curve> ZeroizeOnDrop for PreprocessPackage<C> {}

// This library unifies the preprocessing step with signing due to security concerns and to provide
// a simpler UX
fn preprocess<R: RngCore + CryptoRng, C: Curve, A: Algorithm<C>>(
  rng: &mut R,
  params: &mut Params<C, A>,
) -> (PreprocessPackage<C>, Vec<u8>) {
  let mut serialized = Vec::with_capacity(2 * C::G_len());
  let (nonces, commitments) = params
    .algorithm
    .nonces()
    .iter()
    .map(|generators| {
      let nonces = [
        C::random_nonce(params.view().secret_share(), &mut *rng),
        C::random_nonce(params.view().secret_share(), &mut *rng),
      ];

      let commit = |generator: C::G, buf: &mut Vec<u8>| {
        let commitments = [generator * nonces[0], generator * nonces[1]];
        buf.extend(commitments[0].to_bytes().as_ref());
        buf.extend(commitments[1].to_bytes().as_ref());
        commitments
      };

      let mut commitments = Vec::with_capacity(generators.len());
      for generator in generators.iter() {
        commitments.push(commit(*generator, &mut serialized));
      }

      // Provide a DLEq proof to verify these commitments are for the same nonce
      if generators.len() >= 2 {
        // Uses an independent transcript as each signer must do this now, yet we validate them
        // sequentially by the global order. Avoids needing to clone and fork the transcript around
        let mut transcript = nonce_transcript::<A::Transcript>();

        // This could be further optimized with a multi-nonce proof.
        // See https://github.com/serai-dex/serai/issues/38
        for mut nonce in nonces {
          DLEqProof::prove(&mut *rng, &mut transcript, generators, nonce)
            .serialize(&mut serialized)
            .unwrap();
          nonce.zeroize();
        }
      }

      (nonces, commitments)
    })
    .unzip();

  let addendum = params.algorithm.preprocess_addendum(rng, &params.view);
  serialized.extend(&addendum);

  (PreprocessPackage { nonces, commitments, addendum }, serialized)
}

#[allow(non_snake_case)]
fn read_D_E<Re: Read, C: Curve>(cursor: &mut Re, l: u16) -> Result<[C::G; 2], FrostError> {
  Ok([
    C::read_G(cursor).map_err(|_| FrostError::InvalidCommitment(l))?,
    C::read_G(cursor).map_err(|_| FrostError::InvalidCommitment(l))?,
  ])
}

#[allow(non_snake_case)]
struct Package<C: Curve> {
  B: HashMap<u16, (Vec<Vec<[C::G; 2]>>, C::F)>,
  Rs: Vec<Vec<C::G>>,
  share: C::F,
}

// Has every signer perform the role of the signature aggregator
// Step 1 was already deprecated by performing nonce generation as needed
// Step 2 is simply the broadcast round from step 1
fn sign_with_share<Re: Read, C: Curve, A: Algorithm<C>>(
  params: &mut Params<C, A>,
  our_preprocess: PreprocessPackage<C>,
  mut commitments: HashMap<u16, Re>,
  msg: &[u8],
) -> Result<(Package<C>, Vec<u8>), FrostError> {
  let multisig_params = params.multisig_params();
  validate_map(&commitments, &params.view.included, multisig_params.i)?;

  {
    // Domain separate FROST
    params.algorithm.transcript().domain_separate(b"FROST");
  }

  let nonces = params.algorithm.nonces();
  #[allow(non_snake_case)]
  let mut B = HashMap::<u16, _>::with_capacity(params.view.included.len());
  {
    // Parse the commitments
    for l in &params.view.included {
      {
        params
          .algorithm
          .transcript()
          .append_message(b"participant", C::F::from(u64::from(*l)).to_repr().as_ref());
      }

      // While this doesn't note which nonce/basepoint this is for, those are expected to be
      // static. Beyond that, they're committed to in the DLEq proof transcripts, ensuring
      // consistency. While this is suboptimal, it maintains IETF compliance, and Algorithm is
      // documented accordingly
      let transcript = |t: &mut A::Transcript, commitments: [C::G; 2]| {
        t.append_message(b"commitment_D", commitments[0].to_bytes().as_ref());
        t.append_message(b"commitment_E", commitments[1].to_bytes().as_ref());
      };

      if *l == params.keys.params().i {
        for nonce_commitments in &our_preprocess.commitments {
          for commitments in nonce_commitments {
            transcript(params.algorithm.transcript(), *commitments);
          }
        }

        B.insert(*l, (our_preprocess.commitments.clone(), C::F::zero()));
        params.algorithm.process_addendum(
          &params.view,
          *l,
          &mut Cursor::new(our_preprocess.addendum.clone()),
        )?;
      } else {
        let mut cursor = commitments.remove(l).unwrap();

        let mut commitments = Vec::with_capacity(nonces.len());
        for (n, nonce_generators) in nonces.clone().iter_mut().enumerate() {
          commitments.push(Vec::with_capacity(nonce_generators.len()));
          for _ in 0 .. nonce_generators.len() {
            commitments[n].push(read_D_E::<_, C>(&mut cursor, *l)?);
            transcript(params.algorithm.transcript(), commitments[n][commitments[n].len() - 1]);
          }

          if nonce_generators.len() >= 2 {
            let mut transcript = nonce_transcript::<A::Transcript>();
            for de in 0 .. 2 {
              DLEqProof::deserialize(&mut cursor)
                .map_err(|_| FrostError::InvalidCommitment(*l))?
                .verify(
                  &mut transcript,
                  nonce_generators,
                  &commitments[n].iter().map(|commitments| commitments[de]).collect::<Vec<_>>(),
                )
                .map_err(|_| FrostError::InvalidCommitment(*l))?;
            }
          }
        }

        B.insert(*l, (commitments, C::F::zero()));
        params.algorithm.process_addendum(&params.view, *l, &mut cursor)?;
      }
    }

    // Re-format into the FROST-expected rho transcript
    let mut rho_transcript = A::Transcript::new(b"FROST_rho");
    rho_transcript.append_message(b"message", &C::hash_msg(msg));
    // This won't just be the commitments, yet the full existing transcript if used in an extended
    // protocol
    rho_transcript.append_message(
      b"commitments",
      &C::hash_commitments(params.algorithm.transcript().challenge(b"commitments").as_ref()),
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
    for (l, commitments) in B.iter_mut() {
      let mut rho_transcript = rho_transcript.clone();
      rho_transcript.append_message(b"participant", C::F::from(u64::from(*l)).to_repr().as_ref());
      commitments.1 = C::hash_binding_factor(rho_transcript.challenge(b"rho").as_ref());
    }

    // Merge the rho transcript back into the global one to ensure its advanced while committing to
    // everything
    params
      .algorithm
      .transcript()
      .append_message(b"rho_transcript", rho_transcript.challenge(b"merge").as_ref());
  }

  #[allow(non_snake_case)]
  let mut Rs = Vec::with_capacity(nonces.len());
  for n in 0 .. nonces.len() {
    Rs.push(vec![C::G::identity(); nonces[n].len()]);
    for g in 0 .. nonces[n].len() {
      #[allow(non_snake_case)]
      let mut D = C::G::identity();
      let mut statements = Vec::with_capacity(B.len());
      #[allow(non_snake_case)]
      for (B, binding) in B.values() {
        D += B[n][g][0];
        statements.push((*binding, B[n][g][1]));
      }
      Rs[n][g] = D + multiexp_vartime(&statements);
    }
  }

  let mut nonces = our_preprocess
    .nonces
    .iter()
    .map(|nonces| nonces[0] + (nonces[1] * B[&params.keys.params().i()].1))
    .collect::<Vec<_>>();

  let share = params.algorithm.sign_share(&params.view, &Rs, &nonces, msg);
  nonces.zeroize();

  Ok((Package { B, Rs, share }, share.to_repr().as_ref().to_vec()))
}

fn complete<Re: Read, C: Curve, A: Algorithm<C>>(
  sign_params: &Params<C, A>,
  sign: Package<C>,
  mut shares: HashMap<u16, Re>,
) -> Result<A::Signature, FrostError> {
  let params = sign_params.multisig_params();
  validate_map(&shares, &sign_params.view.included, params.i)?;

  let mut responses = HashMap::new();
  let mut sum = C::F::zero();
  for l in &sign_params.view.included {
    let part = if *l == params.i {
      sign.share
    } else {
      C::read_F(shares.get_mut(l).unwrap()).map_err(|_| FrostError::InvalidShare(*l))?
    };
    sum += part;
    responses.insert(*l, part);
  }

  // Perform signature validation instead of individual share validation
  // For the success route, which should be much more frequent, this should be faster
  // It also acts as an integrity check of this library's signing function
  let res = sign_params.algorithm.verify(sign_params.view.group_key, &sign.Rs, sum);
  if let Some(res) = res {
    return Ok(res);
  }

  // Find out who misbehaved. It may be beneficial to randomly sort this to have detection be
  // within n / 2 on average, and not gameable to n, though that should be minor
  for l in &sign_params.view.included {
    if !sign_params.algorithm.verify_share(
      sign_params.view.verification_share(*l),
      &sign.B[l]
        .0
        .iter()
        .map(|nonces| {
          nonces.iter().map(|commitments| commitments[0] + (commitments[1] * sign.B[l].1)).collect()
        })
        .collect::<Vec<_>>(),
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
  type Signature: Clone + PartialEq + fmt::Debug;
  type SignMachine: SignMachine<Self::Signature>;

  /// Perform the preprocessing round required in order to sign.
  /// Returns a byte vector to be broadcast to all participants, over an authenticated channel.
  fn preprocess<R: RngCore + CryptoRng>(self, rng: &mut R) -> (Self::SignMachine, Vec<u8>);
}

/// Trait for the second machine of a two-round signing protocol.
pub trait SignMachine<S> {
  type SignatureMachine: SignatureMachine<S>;

  /// Sign a message.
  /// Takes in the participants' preprocesses. Returns a byte vector representing a signature share
  /// to be broadcast to all participants, over an authenticated channel.
  fn sign<Re: Read>(
    self,
    commitments: HashMap<u16, Re>,
    msg: &[u8],
  ) -> Result<(Self::SignatureMachine, Vec<u8>), FrostError>;
}

/// Trait for the final machine of a two-round signing protocol.
pub trait SignatureMachine<S> {
  /// Complete signing.
  /// Takes in everyone elses' shares. Returns the signature.
  fn complete<Re: Read>(self, shares: HashMap<u16, Re>) -> Result<S, FrostError>;
}

/// State machine which manages signing for an arbitrary signature algorithm.
pub struct AlgorithmMachine<C: Curve, A: Algorithm<C>> {
  params: Params<C, A>,
}

/// Next step of the state machine for the signing process.
pub struct AlgorithmSignMachine<C: Curve, A: Algorithm<C>> {
  params: Params<C, A>,
  preprocess: PreprocessPackage<C>,
}

/// Final step of the state machine for the signing process.
pub struct AlgorithmSignatureMachine<C: Curve, A: Algorithm<C>> {
  params: Params<C, A>,
  sign: Package<C>,
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

  pub(crate) fn unsafe_override_preprocess(
    self,
    preprocess: PreprocessPackage<C>,
  ) -> AlgorithmSignMachine<C, A> {
    AlgorithmSignMachine { params: self.params, preprocess }
  }
}

impl<C: Curve, A: Algorithm<C>> PreprocessMachine for AlgorithmMachine<C, A> {
  type Signature = A::Signature;
  type SignMachine = AlgorithmSignMachine<C, A>;

  fn preprocess<R: RngCore + CryptoRng>(self, rng: &mut R) -> (Self::SignMachine, Vec<u8>) {
    let mut params = self.params;
    let (preprocess, serialized) = preprocess::<R, C, A>(rng, &mut params);
    (AlgorithmSignMachine { params, preprocess }, serialized)
  }
}

impl<C: Curve, A: Algorithm<C>> SignMachine<A::Signature> for AlgorithmSignMachine<C, A> {
  type SignatureMachine = AlgorithmSignatureMachine<C, A>;

  fn sign<Re: Read>(
    self,
    commitments: HashMap<u16, Re>,
    msg: &[u8],
  ) -> Result<(Self::SignatureMachine, Vec<u8>), FrostError> {
    let mut params = self.params;
    let (sign, serialized) = sign_with_share(&mut params, self.preprocess, commitments, msg)?;
    Ok((AlgorithmSignatureMachine { params, sign }, serialized))
  }
}

impl<C: Curve, A: Algorithm<C>> SignatureMachine<A::Signature> for AlgorithmSignatureMachine<C, A> {
  fn complete<Re: Read>(self, shares: HashMap<u16, Re>) -> Result<A::Signature, FrostError> {
    complete(&self.params, self.sign, shares)
  }
}
