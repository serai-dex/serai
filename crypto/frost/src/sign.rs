use core::{ops::Deref, fmt::Debug};
use std::{
  io::{self, Read, Write},
  collections::HashMap,
};

use rand_core::{RngCore, CryptoRng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use zeroize::{Zeroize, Zeroizing};

use transcript::Transcript;

use ciphersuite::group::{
  ff::{Field, PrimeField},
  GroupEncoding,
};
use multiexp::BatchVerifier;

use crate::{
  curve::Curve,
  Participant, FrostError, ThresholdParams, ThresholdKeys, ThresholdView,
  algorithm::{WriteAddendum, Addendum, Algorithm},
  validate_map,
};

pub(crate) use crate::nonce::*;

/// Trait enabling writing preprocesses and signature shares.
pub trait Writable {
  fn write<W: Write>(&self, writer: &mut W) -> io::Result<()>;

  fn serialize(&self) -> Vec<u8> {
    let mut buf = vec![];
    self.write(&mut buf).unwrap();
    buf
  }
}

impl<T: Writable> Writable for Vec<T> {
  fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    for w in self {
      w.write(writer)?;
    }
    Ok(())
  }
}

// Pairing of an Algorithm with a ThresholdKeys instance.
#[derive(Clone, Zeroize)]
struct Params<C: Curve, A: Algorithm<C>> {
  // Skips the algorithm due to being too large a bound to feasibly enforce on users
  #[zeroize(skip)]
  algorithm: A,
  keys: ThresholdKeys<C>,
}

impl<C: Curve, A: Algorithm<C>> Params<C, A> {
  fn new(algorithm: A, keys: ThresholdKeys<C>) -> Params<C, A> {
    Params { algorithm, keys }
  }

  fn multisig_params(&self) -> ThresholdParams {
    self.keys.params()
  }
}

/// Preprocess for an instance of the FROST signing protocol.
#[derive(Clone, PartialEq, Eq)]
pub struct Preprocess<C: Curve, A: Addendum> {
  pub(crate) commitments: Commitments<C>,
  /// The addendum used by the algorithm.
  pub addendum: A,
}

impl<C: Curve, A: Addendum> Writable for Preprocess<C, A> {
  fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    self.commitments.write(writer)?;
    self.addendum.write(writer)
  }
}

/// A cached preprocess.
///
/// A preprocess MUST only be used once. Reuse will enable third-party recovery of your private
/// key share. Additionally, this MUST be handled with the same security as your private key share,
/// as knowledge of it also enables recovery.
// Directly exposes the [u8; 32] member to void needing to route through std::io interfaces.
// Still uses Zeroizing internally so when users grab it, they have a higher likelihood of
// appreciating how to handle it and don't immediately start copying it just by grabbing it.
#[derive(Zeroize)]
pub struct CachedPreprocess(pub Zeroizing<[u8; 32]>);

/// Trait for the initial state machine of a two-round signing protocol.
pub trait PreprocessMachine: Send {
  /// Preprocess message for this machine.
  type Preprocess: Clone + PartialEq + Writable;
  /// Signature produced by this machine.
  type Signature: Clone + PartialEq + Debug;
  /// SignMachine this PreprocessMachine turns into.
  type SignMachine: SignMachine<Self::Signature, Preprocess = Self::Preprocess>;

  /// Perform the preprocessing round required in order to sign.
  /// Returns a preprocess message to be broadcast to all participants, over an authenticated
  /// channel.
  fn preprocess<R: RngCore + CryptoRng>(self, rng: &mut R)
    -> (Self::SignMachine, Self::Preprocess);
}

/// State machine which manages signing for an arbitrary signature algorithm.
pub struct AlgorithmMachine<C: Curve, A: Algorithm<C>> {
  params: Params<C, A>,
}

impl<C: Curve, A: Algorithm<C>> AlgorithmMachine<C, A> {
  /// Creates a new machine to generate a signature with the specified keys.
  pub fn new(algorithm: A, keys: ThresholdKeys<C>) -> AlgorithmMachine<C, A> {
    AlgorithmMachine { params: Params::new(algorithm, keys) }
  }

  fn seeded_preprocess(
    self,
    seed: CachedPreprocess,
  ) -> (AlgorithmSignMachine<C, A>, Preprocess<C, A::Addendum>) {
    let mut params = self.params;

    let mut rng = ChaCha20Rng::from_seed(*seed.0);
    let (nonces, commitments) =
      Commitments::new::<_>(&mut rng, params.keys.secret_share(), &params.algorithm.nonces());
    let addendum = params.algorithm.preprocess_addendum(&mut rng, &params.keys);

    let preprocess = Preprocess { commitments, addendum };

    // Also obtain entropy to randomly sort the included participants if we need to identify blame
    let mut blame_entropy = [0; 32];
    rng.fill_bytes(&mut blame_entropy);
    (
      AlgorithmSignMachine { params, seed, nonces, preprocess: preprocess.clone(), blame_entropy },
      preprocess,
    )
  }

  #[cfg(any(test, feature = "tests"))]
  pub(crate) fn unsafe_override_preprocess(
    self,
    nonces: Vec<Nonce<C>>,
    preprocess: Preprocess<C, A::Addendum>,
  ) -> AlgorithmSignMachine<C, A> {
    AlgorithmSignMachine {
      params: self.params,
      seed: CachedPreprocess(Zeroizing::new([0; 32])),

      nonces,
      preprocess,
      // Uses 0s since this is just used to protect against a malicious participant from
      // deliberately increasing the amount of time needed to identify them (and is accordingly
      // not necessary to function)
      blame_entropy: [0; 32],
    }
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
    let mut seed = CachedPreprocess(Zeroizing::new([0; 32]));
    rng.fill_bytes(seed.0.as_mut());
    self.seeded_preprocess(seed)
  }
}

/// Share of a signature produced via FROST.
#[derive(Clone, PartialEq, Eq)]
pub struct SignatureShare<C: Curve>(C::F);
impl<C: Curve> Writable for SignatureShare<C> {
  fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(self.0.to_repr().as_ref())
  }
}
#[cfg(any(test, feature = "tests"))]
impl<C: Curve> SignatureShare<C> {
  pub(crate) fn invalidate(&mut self) {
    self.0 += C::F::ONE;
  }
}

/// Trait for the second machine of a two-round signing protocol.
pub trait SignMachine<S>: Send + Sync + Sized {
  /// Params used to instantiate this machine which can be used to rebuild from a cache.
  type Params: Clone;
  /// Keys used for signing operations.
  type Keys;
  /// Preprocess message for this machine.
  type Preprocess: Clone + PartialEq + Writable;
  /// SignatureShare message for this machine.
  type SignatureShare: Clone + PartialEq + Writable;
  /// SignatureMachine this SignMachine turns into.
  type SignatureMachine: SignatureMachine<S, SignatureShare = Self::SignatureShare>;

  /// Cache this preprocess for usage later. This cached preprocess MUST only be used once. Reuse
  /// of it enables recovery of your private key share. Third-party recovery of a cached preprocess
  /// also enables recovery of your private key share, so this MUST be treated with the same
  /// security as your private key share.
  fn cache(self) -> CachedPreprocess;

  /// Create a sign machine from a cached preprocess.

  /// After this, the preprocess must be deleted so it's never reused. Any reuse will presumably
  /// cause the signer to leak their secret share.
  fn from_cache(
    params: Self::Params,
    keys: Self::Keys,
    cache: CachedPreprocess,
  ) -> (Self, Self::Preprocess);

  /// Read a Preprocess message. Despite taking self, this does not save the preprocess.
  /// It must be externally cached and passed into sign.
  fn read_preprocess<R: Read>(&self, reader: &mut R) -> io::Result<Self::Preprocess>;

  /// Sign a message.
  /// Takes in the participants' preprocess messages. Returns the signature share to be broadcast
  /// to all participants, over an authenticated channel. The parties who participate here will
  /// become the signing set for this session.
  fn sign(
    self,
    commitments: HashMap<Participant, Self::Preprocess>,
    msg: &[u8],
  ) -> Result<(Self::SignatureMachine, Self::SignatureShare), FrostError>;
}

/// Next step of the state machine for the signing process.
#[derive(Zeroize)]
pub struct AlgorithmSignMachine<C: Curve, A: Algorithm<C>> {
  params: Params<C, A>,
  seed: CachedPreprocess,

  pub(crate) nonces: Vec<Nonce<C>>,
  // Skips the preprocess due to being too large a bound to feasibly enforce on users
  #[zeroize(skip)]
  pub(crate) preprocess: Preprocess<C, A::Addendum>,
  pub(crate) blame_entropy: [u8; 32],
}

impl<C: Curve, A: Algorithm<C>> SignMachine<A::Signature> for AlgorithmSignMachine<C, A> {
  type Params = A;
  type Keys = ThresholdKeys<C>;
  type Preprocess = Preprocess<C, A::Addendum>;
  type SignatureShare = SignatureShare<C>;
  type SignatureMachine = AlgorithmSignatureMachine<C, A>;

  fn cache(self) -> CachedPreprocess {
    self.seed
  }

  fn from_cache(
    algorithm: A,
    keys: ThresholdKeys<C>,
    cache: CachedPreprocess,
  ) -> (Self, Self::Preprocess) {
    AlgorithmMachine::new(algorithm, keys).seeded_preprocess(cache)
  }

  fn read_preprocess<R: Read>(&self, reader: &mut R) -> io::Result<Self::Preprocess> {
    Ok(Preprocess {
      commitments: Commitments::read::<_>(reader, &self.params.algorithm.nonces())?,
      addendum: self.params.algorithm.read_addendum(reader)?,
    })
  }

  fn sign(
    mut self,
    mut preprocesses: HashMap<Participant, Preprocess<C, A::Addendum>>,
    msg: &[u8],
  ) -> Result<(Self::SignatureMachine, SignatureShare<C>), FrostError> {
    let multisig_params = self.params.multisig_params();

    let mut included = Vec::with_capacity(preprocesses.len() + 1);
    included.push(multisig_params.i());
    for l in preprocesses.keys() {
      included.push(*l);
    }
    included.sort_unstable();

    // Included < threshold
    if included.len() < usize::from(multisig_params.t()) {
      Err(FrostError::InvalidSigningSet("not enough signers"))?;
    }
    // OOB index
    if u16::from(included[included.len() - 1]) > multisig_params.n() {
      Err(FrostError::InvalidParticipant(multisig_params.n(), included[included.len() - 1]))?;
    }
    // Same signer included multiple times
    for i in 0 .. (included.len() - 1) {
      if included[i] == included[i + 1] {
        Err(FrostError::DuplicatedParticipant(included[i]))?;
      }
    }

    let view = self.params.keys.view(included.clone()).unwrap();
    validate_map(&preprocesses, &included, multisig_params.i())?;

    {
      // Domain separate FROST
      self.params.algorithm.transcript().domain_separate(b"FROST");
    }

    let nonces = self.params.algorithm.nonces();
    #[allow(non_snake_case)]
    let mut B = BindingFactor(HashMap::<Participant, _>::with_capacity(included.len()));
    {
      // Parse the preprocesses
      for l in &included {
        {
          self
            .params
            .algorithm
            .transcript()
            .append_message(b"participant", C::F::from(u64::from(u16::from(*l))).to_repr());
        }

        if *l == self.params.keys.params().i() {
          let commitments = self.preprocess.commitments.clone();
          commitments.transcript(self.params.algorithm.transcript());

          let addendum = self.preprocess.addendum.clone();
          {
            let mut buf = vec![];
            addendum.write(&mut buf).unwrap();
            self.params.algorithm.transcript().append_message(b"addendum", buf);
          }

          B.insert(*l, commitments);
          self.params.algorithm.process_addendum(&view, *l, addendum)?;
        } else {
          let preprocess = preprocesses.remove(l).unwrap();
          preprocess.commitments.transcript(self.params.algorithm.transcript());
          {
            let mut buf = vec![];
            preprocess.addendum.write(&mut buf).unwrap();
            self.params.algorithm.transcript().append_message(b"addendum", buf);
          }

          B.insert(*l, preprocess.commitments);
          self.params.algorithm.process_addendum(&view, *l, preprocess.addendum)?;
        }
      }

      // Re-format into the FROST-expected rho transcript
      let mut rho_transcript = A::Transcript::new(b"FROST_rho");
      rho_transcript.append_message(
        b"group_key",
        (self.params.keys.group_key() +
          (C::generator() * self.params.keys.current_offset().unwrap_or(C::F::ZERO)))
        .to_bytes(),
      );
      rho_transcript.append_message(b"message", C::hash_msg(msg));
      rho_transcript.append_message(
        b"preprocesses",
        C::hash_commitments(self.params.algorithm.transcript().challenge(b"preprocesses").as_ref()),
      );

      // Generate the per-signer binding factors
      B.calculate_binding_factors(&rho_transcript);

      // Merge the rho transcript back into the global one to ensure its advanced, while
      // simultaneously committing to everything
      self
        .params
        .algorithm
        .transcript()
        .append_message(b"rho_transcript", rho_transcript.challenge(b"merge"));
    }

    #[allow(non_snake_case)]
    let Rs = B.nonces(&nonces);

    let our_binding_factors = B.binding_factors(multisig_params.i());
    let nonces = self
      .nonces
      .drain(..)
      .enumerate()
      .map(|(n, nonces)| {
        let [base, mut actual] = nonces.0;
        *actual *= our_binding_factors[n];
        *actual += base.deref();
        actual
      })
      .collect::<Vec<_>>();

    let share = self.params.algorithm.sign_share(&view, &Rs, nonces, msg);

    Ok((
      AlgorithmSignatureMachine {
        params: self.params.clone(),
        view,
        B,
        Rs,
        share,
        blame_entropy: self.blame_entropy,
      },
      SignatureShare(share),
    ))
  }
}

/// Trait for the final machine of a two-round signing protocol.
pub trait SignatureMachine<S>: Send + Sync {
  /// SignatureShare message for this machine.
  type SignatureShare: Clone + PartialEq + Writable;

  /// Read a Signature Share message.
  fn read_share<R: Read>(&self, reader: &mut R) -> io::Result<Self::SignatureShare>;

  /// Complete signing.
  /// Takes in everyone elses' shares. Returns the signature.
  fn complete(self, shares: HashMap<Participant, Self::SignatureShare>) -> Result<S, FrostError>;
}

/// Final step of the state machine for the signing process.
///
/// This may panic if an invalid algorithm is provided.
#[allow(non_snake_case)]
pub struct AlgorithmSignatureMachine<C: Curve, A: Algorithm<C>> {
  params: Params<C, A>,
  view: ThresholdView<C>,
  B: BindingFactor<C>,
  Rs: Vec<Vec<C::G>>,
  share: C::F,
  blame_entropy: [u8; 32],
}

impl<C: Curve, A: Algorithm<C>> SignatureMachine<A::Signature> for AlgorithmSignatureMachine<C, A> {
  type SignatureShare = SignatureShare<C>;

  fn read_share<R: Read>(&self, reader: &mut R) -> io::Result<SignatureShare<C>> {
    Ok(SignatureShare(C::read_F(reader)?))
  }

  fn complete(
    self,
    mut shares: HashMap<Participant, SignatureShare<C>>,
  ) -> Result<A::Signature, FrostError> {
    let params = self.params.multisig_params();
    validate_map(&shares, self.view.included(), params.i())?;

    let mut responses = HashMap::new();
    responses.insert(params.i(), self.share);
    let mut sum = self.share;
    for (l, share) in shares.drain() {
      responses.insert(l, share.0);
      sum += share.0;
    }

    // Perform signature validation instead of individual share validation
    // For the success route, which should be much more frequent, this should be faster
    // It also acts as an integrity check of this library's signing function
    if let Some(sig) = self.params.algorithm.verify(self.view.group_key(), &self.Rs, sum) {
      return Ok(sig);
    }

    // We could remove blame_entropy by taking in an RNG here
    // Considering we don't need any RNG for a valid signature, and we only use the RNG here for
    // performance reasons, it doesn't feel worthwhile to include as an argument to every
    // implementor of the trait
    let mut rng = ChaCha20Rng::from_seed(self.blame_entropy);
    let mut batch = BatchVerifier::new(self.view.included().len());
    for l in self.view.included() {
      if let Ok(statements) = self.params.algorithm.verify_share(
        self.view.verification_share(*l),
        &self.B.bound(*l),
        responses[l],
      ) {
        batch.queue(&mut rng, *l, statements);
      } else {
        Err(FrostError::InvalidShare(*l))?;
      }
    }

    if let Err(l) = batch.verify_vartime_with_vartime_blame() {
      Err(FrostError::InvalidShare(l))?;
    }

    // If everyone has a valid share, and there were enough participants, this should've worked
    // The only known way to cause this, for valid parameters/algorithms, is to deserialize a
    // semantically invalid FrostKeys
    Err(FrostError::InternalError("everyone had a valid share yet the signature was still invalid"))
  }
}
