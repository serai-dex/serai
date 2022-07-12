use core::fmt;
use std::{sync::Arc, collections::HashMap};

use rand_core::{RngCore, CryptoRng};

use group::{ff::{Field, PrimeField}, Group, GroupEncoding};

use transcript::Transcript;

use dleq::{Generators, DLEqProof};

use crate::{
  curve::{Curve, F_len, G_len, F_from_slice, G_from_slice},
  FrostError,
  FrostParams, FrostKeys, FrostView,
  algorithm::Algorithm,
  validate_map
};

/// Pairing of an Algorithm with a FrostKeys instance and this specific signing set
#[derive(Clone)]
pub struct Params<C: Curve, A: Algorithm<C>> {
  algorithm: A,
  keys: Arc<FrostKeys<C>>,
  view: FrostView<C>,
}

// Currently public to enable more complex operations as desired, yet solely used in testing
impl<C: Curve, A: Algorithm<C>> Params<C, A> {
  pub fn new(
    algorithm: A,
    keys: Arc<FrostKeys<C>>,
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

  pub fn multisig_params(&self) -> FrostParams {
    self.keys.params
  }

  pub fn view(&self) -> FrostView<C> {
    self.view.clone()
  }
}

fn nonce_transcript<T: Transcript>() -> T {
  T::new(b"FROST_nonce_dleq")
}

pub(crate) struct PreprocessPackage<C: Curve> {
  pub(crate) nonces: Vec<[C::F; 2]>,
  pub(crate) serialized: Vec<u8>,
}

// This library unifies the preprocessing step with signing due to security concerns and to provide
// a simpler UX
fn preprocess<R: RngCore + CryptoRng, C: Curve, A: Algorithm<C>>(
  rng: &mut R,
  params: &mut Params<C, A>,
) -> PreprocessPackage<C> {
  let mut serialized = Vec::with_capacity(2 * G_len::<C>());
  let nonces = params.algorithm.nonces().iter().cloned().map(
    |mut generators| {
      let nonces = [
        C::random_nonce(params.view().secret_share(), &mut *rng),
        C::random_nonce(params.view().secret_share(), &mut *rng)
      ];

      let commit = |generator: C::G| {
        let commitments = [generator * nonces[0], generator * nonces[1]];
        [commitments[0].to_bytes().as_ref(), commitments[1].to_bytes().as_ref()].concat().to_vec()
      };

      let first = generators.remove(0);
      serialized.extend(commit(first));

      // Iterate over the rest
      for generator in generators.iter() {
        serialized.extend(commit(*generator));
        // Provide a DLEq to verify these commitments are for the same nonce
        // TODO: Provide a single DLEq. See https://github.com/serai-dex/serai/issues/34
        for nonce in nonces {
          DLEqProof::prove(
            &mut *rng,
            // Uses an independent transcript as each signer must do this now, yet we validate them
            // sequentially by the global order. Avoids needing to clone the transcript around
            &mut nonce_transcript::<A::Transcript>(),
            Generators::new(first, *generator),
            nonce
          ).serialize(&mut serialized).unwrap();
        }
      }

      nonces
    }
  ).collect::<Vec<_>>();

  serialized.extend(&params.algorithm.preprocess_addendum(rng, &params.view));

  PreprocessPackage { nonces, serialized }
}

#[allow(non_snake_case)]
struct Package<C: Curve> {
  B: HashMap<u16, Vec<Vec<[C::G; 2]>>>,
  binding: C::F,
  Rs: Vec<Vec<C::G>>,
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
      transcript.append_message(b"offset", offset.to_repr().as_ref());
    }
  }

  #[allow(non_snake_case)]
  let mut B = HashMap::<u16, _>::with_capacity(params.view.included.len());

  // Get the binding factor
  let nonces = params.algorithm.nonces();
  let mut addendums = HashMap::new();
  let binding = {
    let transcript = params.algorithm.transcript();
    // Parse the commitments
    for l in &params.view.included {
      transcript.append_message(b"participant", &l.to_be_bytes());
      let serialized = commitments.remove(l).unwrap();

      let mut read_commitment = |c, label| {
        let commitment = &serialized[c .. (c + G_len::<C>())];
        transcript.append_message(label, commitment);
        G_from_slice::<C::G>(commitment).map_err(|_| FrostError::InvalidCommitment(*l))
      };

      // While this doesn't note which nonce/basepoint this is for, those are expected to be
      // static. Beyond that, they're committed to in the DLEq proof transcripts, ensuring
      // consistency. While this is suboptimal, it maintains IETF compliance, and Algorithm is
      // documented accordingly
      #[allow(non_snake_case)]
      let mut read_D_E = |c| Ok([
        read_commitment(c, b"commitment_D")?,
        read_commitment(c + G_len::<C>(), b"commitment_E")?
      ]);

      let mut c = 0;
      let mut commitments = Vec::with_capacity(nonces.len());
      for (n, nonce_generators) in nonces.clone().iter_mut().enumerate() {
        commitments.push(Vec::with_capacity(nonce_generators.len()));

        let first = nonce_generators.remove(0);
        commitments[n].push(read_D_E(c)?);
        c += 2 * G_len::<C>();

        let mut c = 2 * G_len::<C>();
        for generator in nonce_generators {
          commitments[n].push(read_D_E(c)?);
          c += 2 * G_len::<C>();
          for de in 0 .. 2 {
            DLEqProof::deserialize(
              &mut std::io::Cursor::new(&serialized[c .. (c + (2 * F_len::<C>()))])
            ).map_err(|_| FrostError::InvalidCommitment(*l))?.verify(
              &mut nonce_transcript::<A::Transcript>(),
              Generators::new(first, *generator),
              (commitments[n][0][de], commitments[n][commitments[n].len() - 1][de])
            ).map_err(|_| FrostError::InvalidCommitment(*l))?;
            c += 2 * F_len::<C>();
          }
        }

        addendums.insert(*l, serialized[c ..].to_vec());
      }
      B.insert(*l, commitments);
    }

    // Append the message to the transcript
    transcript.append_message(b"message", &C::hash_msg(&msg));

    // Calculate the binding factor
    C::hash_binding_factor(transcript.challenge(b"binding").as_ref())
  };

  // Process the addendums
  for l in &params.view.included {
    params.algorithm.process_addendum(&params.view, *l, &addendums[l])?;
  }

  #[allow(non_snake_case)]
  let mut Rs = Vec::with_capacity(nonces.len());
  for n in 0 .. nonces.len() {
    Rs.push(vec![C::G::identity(); nonces[n].len()]);
    #[allow(non_snake_case)]
    for g in 0 .. nonces[n].len() {
      Rs[n][g] = {
        B.values().map(|B| B[n][g][0]).sum::<C::G>() +
          (B.values().map(|B| B[n][g][1]).sum::<C::G>() * binding)
      };
    }
  }

  let share = params.algorithm.sign_share(
    &params.view,
    &Rs,
    &our_preprocess.nonces.iter().map(
      |nonces| nonces[0] + (nonces[1] * binding)
    ).collect::<Vec<_>>(),
    msg
  ).to_repr().as_ref().to_vec();

  Ok((Package { B, binding, Rs, share: share.clone() }, share))
}

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
    let part = F_from_slice::<C::F>(&shares[l]).map_err(|_| FrostError::InvalidShare(*l))?;
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
      &sign.B[l].iter().map(
        |nonces| nonces.iter().map(
          |commitments| commitments[0] + (commitments[1] * sign.binding)
        ).collect()
      ).collect::<Vec<_>>(),
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

pub trait PreprocessMachine {
  type Signature: Clone + PartialEq + fmt::Debug;
  type SignMachine: SignMachine<Self::Signature>;

  /// Perform the preprocessing round required in order to sign
  /// Returns a byte vector which must be transmitted to all parties selected for this signing
  /// process, over an authenticated channel
  fn preprocess<R: RngCore + CryptoRng>(
    self,
    rng: &mut R
  ) -> (Self::SignMachine, Vec<u8>);
}

pub trait SignMachine<S> {
  type SignatureMachine: SignatureMachine<S>;

  /// Sign a message
  /// Takes in the participant's commitments, which are expected to be in a Vec where participant
  /// index = Vec index. None is expected at index 0 to allow for this. None is also expected at
  /// index i which is locally handled. Returns a byte vector representing a share of the signature
  /// for every other participant to receive, over an authenticated channel
  fn sign(
    self,
    commitments: HashMap<u16, Vec<u8>>,
    msg: &[u8],
  ) -> Result<(Self::SignatureMachine, Vec<u8>), FrostError>;
}

pub trait SignatureMachine<S> {
  /// Complete signing
  /// Takes in everyone elses' shares submitted to us as a Vec, expecting participant index =
  /// Vec index with None at index 0 and index i. Returns a byte vector representing the serialized
  /// signature
  fn complete(self, shares: HashMap<u16, Vec<u8>>) -> Result<S, FrostError>;
}

/// State machine which manages signing for an arbitrary signature algorithm
pub struct AlgorithmMachine<C: Curve, A: Algorithm<C>> {
  params: Params<C, A>
}

pub struct AlgorithmSignMachine<C: Curve, A: Algorithm<C>> {
  params: Params<C, A>,
  preprocess: PreprocessPackage<C>,
}

pub struct AlgorithmSignatureMachine<C: Curve, A: Algorithm<C>> {
  params: Params<C, A>,
  sign: Package<C>,
}

impl<C: Curve, A: Algorithm<C>> AlgorithmMachine<C, A> {
  /// Creates a new machine to generate a key for the specified curve in the specified multisig
  pub fn new(
    algorithm: A,
    keys: Arc<FrostKeys<C>>,
    included: &[u16],
  ) -> Result<AlgorithmMachine<C, A>, FrostError> {
    Ok(AlgorithmMachine { params: Params::new(algorithm, keys, included)? })
  }

  pub(crate) fn unsafe_override_preprocess(
    self,
    preprocess: PreprocessPackage<C>
  ) -> (AlgorithmSignMachine<C, A>, Vec<u8>) {
    let serialized = preprocess.serialized.clone();
    (AlgorithmSignMachine { params: self.params, preprocess }, serialized)
  }
}

impl<C: Curve, A: Algorithm<C>> PreprocessMachine for AlgorithmMachine<C, A> {
  type Signature = A::Signature;
  type SignMachine = AlgorithmSignMachine<C, A>;

  fn preprocess<R: RngCore + CryptoRng>(
    self,
    rng: &mut R
  ) -> (Self::SignMachine, Vec<u8>) {
    let mut params = self.params;
    let preprocess = preprocess::<R, C, A>(rng, &mut params);
    let serialized = preprocess.serialized.clone();
    (AlgorithmSignMachine { params, preprocess }, serialized)
  }
}

impl<C: Curve, A: Algorithm<C>> SignMachine<A::Signature> for AlgorithmSignMachine<C, A> {
  type SignatureMachine = AlgorithmSignatureMachine<C, A>;

  fn sign(
    self,
    commitments: HashMap<u16, Vec<u8>>,
    msg: &[u8]
  ) -> Result<(Self::SignatureMachine, Vec<u8>), FrostError> {
    let mut params = self.params;
    let (sign, serialized) = sign_with_share(&mut params, self.preprocess, commitments, msg)?;
    Ok((AlgorithmSignatureMachine { params, sign }, serialized))
  }
}

impl<
  C: Curve,
  A: Algorithm<C>
> SignatureMachine<A::Signature> for AlgorithmSignatureMachine<C, A> {
  fn complete(self, shares: HashMap<u16, Vec<u8>>) -> Result<A::Signature, FrostError> {
    complete(&self.params, self.sign, shares)
  }
}
