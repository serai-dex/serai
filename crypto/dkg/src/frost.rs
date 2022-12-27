use std::{
  marker::PhantomData,
  ops::Deref,
  io::{self, Read, Write},
  collections::HashMap,
};

use rand_core::{RngCore, CryptoRng};

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use transcript::{Transcript, RecommendedTranscript};

use group::{
  ff::{Field, PrimeField},
  GroupEncoding,
};
use ciphersuite::Ciphersuite;
use multiexp::{multiexp_vartime, BatchVerifier};

use schnorr::SchnorrSignature;

use crate::{
  DkgError, ThresholdParams, ThresholdCore, validate_map,
  encryption::{ReadWrite, EncryptionKeyMessage, EncryptedMessage, Encryption},
};

#[allow(non_snake_case)]
fn challenge<C: Ciphersuite>(context: &str, l: u16, R: &[u8], Am: &[u8]) -> C::F {
  let mut transcript = RecommendedTranscript::new(b"DKG FROST v0.2");
  transcript.domain_separate(b"Schnorr Proof of Knowledge");
  transcript.append_message(b"context", context.as_bytes());
  transcript.append_message(b"participant", l.to_le_bytes());
  transcript.append_message(b"nonce", R);
  transcript.append_message(b"commitments", Am);
  C::hash_to_F(b"PoK 0", &transcript.challenge(b"challenge"))
}

/// Commitments message to be broadcast to all other parties.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct Commitments<C: Ciphersuite> {
  commitments: Vec<C::G>,
  cached_msg: Vec<u8>,
  sig: SchnorrSignature<C>,
}

impl<C: Ciphersuite> ReadWrite for Commitments<C> {
  fn read<R: Read>(reader: &mut R, params: ThresholdParams) -> io::Result<Self> {
    let mut commitments = Vec::with_capacity(params.t().into());
    let mut cached_msg = vec![];

    #[allow(non_snake_case)]
    let mut read_G = || -> io::Result<C::G> {
      let mut buf = <C::G as GroupEncoding>::Repr::default();
      reader.read_exact(buf.as_mut())?;
      let point = C::read_G(&mut buf.as_ref())?;
      cached_msg.extend(buf.as_ref());
      Ok(point)
    };

    for _ in 0 .. params.t() {
      commitments.push(read_G()?);
    }

    Ok(Commitments { commitments, cached_msg, sig: SchnorrSignature::read(reader)? })
  }

  fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(&self.cached_msg)?;
    self.sig.write(writer)
  }
}

/// State machine to begin the key generation protocol.
pub struct KeyGenMachine<C: Ciphersuite> {
  params: ThresholdParams,
  context: String,
  _curve: PhantomData<C>,
}

impl<C: Ciphersuite> KeyGenMachine<C> {
  /// Creates a new machine to generate a key for the specified curve in the specified multisig.
  // The context string should be unique among multisigs.
  pub fn new(params: ThresholdParams, context: String) -> KeyGenMachine<C> {
    KeyGenMachine { params, context, _curve: PhantomData }
  }

  /// Start generating a key according to the FROST DKG spec.
  /// Returns a commitments message to be sent to all parties over an authenticated channel. If any
  /// party submits multiple sets of commitments, they MUST be treated as malicious.
  pub fn generate_coefficients<R: RngCore + CryptoRng>(
    self,
    rng: &mut R,
  ) -> (SecretShareMachine<C>, EncryptionKeyMessage<C, Commitments<C>>) {
    let t = usize::from(self.params.t);
    let mut coefficients = Vec::with_capacity(t);
    let mut commitments = Vec::with_capacity(t);
    let mut cached_msg = vec![];

    for i in 0 .. t {
      // Step 1: Generate t random values to form a polynomial with
      coefficients.push(Zeroizing::new(C::random_nonzero_F(&mut *rng)));
      // Step 3: Generate public commitments
      commitments.push(C::generator() * coefficients[i].deref());
      cached_msg.extend(commitments[i].to_bytes().as_ref());
    }

    // Step 2: Provide a proof of knowledge
    let r = Zeroizing::new(C::random_nonzero_F(rng));
    let nonce = C::generator() * r.deref();
    let sig = SchnorrSignature::<C>::sign(
      &coefficients[0],
      // This could be deterministic as the PoK is a singleton never opened up to cooperative
      // discussion
      // There's no reason to spend the time and effort to make this deterministic besides a
      // general obsession with canonicity and determinism though
      r,
      challenge::<C>(&self.context, self.params.i(), nonce.to_bytes().as_ref(), &cached_msg),
    );

    // Additionally create an encryption mechanism to protect the secret shares
    let encryption = Encryption::new(b"FROST", rng);

    // Step 4: Broadcast
    let msg =
      encryption.registration(Commitments { commitments: commitments.clone(), cached_msg, sig });
    (
      SecretShareMachine {
        params: self.params,
        context: self.context,
        coefficients,
        our_commitments: commitments,
        encryption,
      },
      msg,
    )
  }
}

fn polynomial<F: PrimeField + Zeroize>(coefficients: &[Zeroizing<F>], l: u16) -> Zeroizing<F> {
  let l = F::from(u64::from(l));
  let mut share = Zeroizing::new(F::zero());
  for (idx, coefficient) in coefficients.iter().rev().enumerate() {
    *share += coefficient.deref();
    if idx != (coefficients.len() - 1) {
      *share *= l;
    }
  }
  share
}

/// Secret share to be sent to the party it's intended for over an authenticated channel.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SecretShare<F: PrimeField>(F::Repr);
impl<F: PrimeField> AsMut<[u8]> for SecretShare<F> {
  fn as_mut(&mut self) -> &mut [u8] {
    self.0.as_mut()
  }
}
impl<F: PrimeField> Zeroize for SecretShare<F> {
  fn zeroize(&mut self) {
    self.0.as_mut().zeroize()
  }
}
impl<F: PrimeField> Drop for SecretShare<F> {
  fn drop(&mut self) {
    self.zeroize();
  }
}
impl<F: PrimeField> ZeroizeOnDrop for SecretShare<F> {}

impl<F: PrimeField> ReadWrite for SecretShare<F> {
  fn read<R: Read>(reader: &mut R, _: ThresholdParams) -> io::Result<Self> {
    let mut repr = F::Repr::default();
    reader.read_exact(repr.as_mut())?;
    Ok(SecretShare(repr))
  }

  fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(self.0.as_ref())
  }
}

/// Advancement of the key generation state machine.
#[derive(Zeroize)]
pub struct SecretShareMachine<C: Ciphersuite> {
  params: ThresholdParams,
  context: String,
  coefficients: Vec<Zeroizing<C::F>>,
  our_commitments: Vec<C::G>,
  encryption: Encryption<u16, C>,
}

impl<C: Ciphersuite> SecretShareMachine<C> {
  /// Verify the data from the previous round (canonicity, PoKs, message authenticity)
  #[allow(clippy::type_complexity)]
  fn verify_r1<R: RngCore + CryptoRng>(
    &mut self,
    rng: &mut R,
    mut commitments: HashMap<u16, EncryptionKeyMessage<C, Commitments<C>>>,
  ) -> Result<HashMap<u16, Vec<C::G>>, DkgError> {
    validate_map(&commitments, &(1 ..= self.params.n()).collect::<Vec<_>>(), self.params.i())?;

    let mut batch = BatchVerifier::<u16, C::G>::new(commitments.len());
    let mut commitments = commitments
      .drain()
      .map(|(l, msg)| {
        let mut msg = self.encryption.register(l, msg);

        // Step 5: Validate each proof of knowledge
        // This is solely the prep step for the latter batch verification
        msg.sig.batch_verify(
          rng,
          &mut batch,
          l,
          msg.commitments[0],
          challenge::<C>(&self.context, l, msg.sig.R.to_bytes().as_ref(), &msg.cached_msg),
        );

        (l, msg.commitments.drain(..).collect::<Vec<_>>())
      })
      .collect::<HashMap<_, _>>();

    batch.verify_with_vartime_blame().map_err(DkgError::InvalidProofOfKnowledge)?;

    commitments.insert(self.params.i, self.our_commitments.drain(..).collect());
    Ok(commitments)
  }

  /// Continue generating a key.
  /// Takes in everyone else's commitments. Returns a HashMap of secret shares to be sent over
  /// authenticated channels to their relevant counterparties.
  #[allow(clippy::type_complexity)]
  pub fn generate_secret_shares<R: RngCore + CryptoRng>(
    mut self,
    rng: &mut R,
    commitments: HashMap<u16, EncryptionKeyMessage<C, Commitments<C>>>,
  ) -> Result<(KeyMachine<C>, HashMap<u16, EncryptedMessage<SecretShare<C::F>>>), DkgError> {
    let commitments = self.verify_r1(&mut *rng, commitments)?;

    // Step 1: Generate secret shares for all other parties
    let mut res = HashMap::new();
    for l in 1 ..= self.params.n() {
      // Don't insert our own shares to the byte buffer which is meant to be sent around
      // An app developer could accidentally send it. Best to keep this black boxed
      if l == self.params.i() {
        continue;
      }

      let mut share = polynomial(&self.coefficients, l);
      let share_bytes = Zeroizing::new(SecretShare::<C::F>(share.to_repr()));
      share.zeroize();
      res.insert(l, self.encryption.encrypt(l, share_bytes));
    }

    // Calculate our own share
    let share = polynomial(&self.coefficients, self.params.i());
    self.coefficients.zeroize();

    Ok((
      KeyMachine { params: self.params, secret: share, commitments, encryption: self.encryption },
      res,
    ))
  }
}

/// Final step of the key generation protocol.
pub struct KeyMachine<C: Ciphersuite> {
  params: ThresholdParams,
  secret: Zeroizing<C::F>,
  commitments: HashMap<u16, Vec<C::G>>,
  encryption: Encryption<u16, C>,
}
impl<C: Ciphersuite> Zeroize for KeyMachine<C> {
  fn zeroize(&mut self) {
    self.params.zeroize();
    self.secret.zeroize();
    for (_, commitments) in self.commitments.iter_mut() {
      commitments.zeroize();
    }
    self.encryption.zeroize();
  }
}
impl<C: Ciphersuite> Drop for KeyMachine<C> {
  fn drop(&mut self) {
    self.zeroize()
  }
}
impl<C: Ciphersuite> ZeroizeOnDrop for KeyMachine<C> {}

impl<C: Ciphersuite> KeyMachine<C> {
  /// Complete key generation.
  /// Takes in everyone elses' shares submitted to us. Returns a ThresholdCore object representing
  /// the generated keys. Successful protocol completion MUST be confirmed by all parties before
  /// these keys may be safely used.
  pub fn complete<R: RngCore + CryptoRng>(
    mut self,
    rng: &mut R,
    mut shares: HashMap<u16, EncryptedMessage<SecretShare<C::F>>>,
  ) -> Result<ThresholdCore<C>, DkgError> {
    validate_map(&shares, &(1 ..= self.params.n()).collect::<Vec<_>>(), self.params.i())?;

    // Calculate the exponent for a given participant and apply it to a series of commitments
    // Initially used with the actual commitments to verify the secret share, later used with
    // stripes to generate the verification shares
    let exponential = |i: u16, values: &[_]| {
      let i = C::F::from(i.into());
      let mut res = Vec::with_capacity(self.params.t().into());
      (0 .. usize::from(self.params.t())).into_iter().fold(C::F::one(), |exp, l| {
        res.push((exp, values[l]));
        exp * i
      });
      res
    };

    let mut batch = BatchVerifier::new(shares.len());
    for (l, share_bytes) in shares.drain() {
      let mut share_bytes = self.encryption.decrypt(l, share_bytes);
      let mut share = Zeroizing::new(
        Option::<C::F>::from(C::F::from_repr(share_bytes.0)).ok_or(DkgError::InvalidShare(l))?,
      );
      share_bytes.zeroize();
      *self.secret += share.deref();

      // This can be insecurely linearized from n * t to just n using the below sums for a given
      // stripe. Doing so uses naive addition which is subject to malleability. The only way to
      // ensure that malleability isn't present is to use this n * t algorithm, which runs
      // per sender and not as an aggregate of all senders, which also enables blame
      let mut values = exponential(self.params.i, &self.commitments[&l]);
      // multiexp will Zeroize this when it's done with it
      values.push((-*share.deref(), C::generator()));
      share.zeroize();

      batch.queue(rng, l, values);
    }
    batch.verify_with_vartime_blame().map_err(DkgError::InvalidShare)?;

    // Stripe commitments per t and sum them in advance. Calculating verification shares relies on
    // these sums so preprocessing them is a massive speedup
    // If these weren't just sums, yet the tables used in multiexp, this would be further optimized
    // As of right now, each multiexp will regenerate them
    let mut stripes = Vec::with_capacity(usize::from(self.params.t()));
    for t in 0 .. usize::from(self.params.t()) {
      stripes.push(self.commitments.values().map(|commitments| commitments[t]).sum());
    }

    // Calculate each user's verification share
    let mut verification_shares = HashMap::new();
    for i in 1 ..= self.params.n() {
      verification_shares.insert(
        i,
        if i == self.params.i() {
          C::generator() * self.secret.deref()
        } else {
          multiexp_vartime(&exponential(i, &stripes))
        },
      );
    }

    Ok(ThresholdCore {
      params: self.params,
      secret_share: self.secret.clone(),
      group_key: stripes[0],
      verification_shares,
    })
  }
}
