use std::{
  marker::PhantomData,
  io::{self, Read, Write},
  collections::HashMap,
};

use rand_core::{RngCore, CryptoRng};

use zeroize::{Zeroize, ZeroizeOnDrop};

use digest::Digest;
use hkdf::{Hkdf, hmac::SimpleHmac};
use chacha20::{
  cipher::{crypto_common::KeyIvInit, StreamCipher},
  Key as Cc20Key, Nonce as Cc20Iv, ChaCha20,
};

use group::{
  ff::{Field, PrimeField},
  GroupEncoding,
};

use ciphersuite::Ciphersuite;

use multiexp::{multiexp_vartime, BatchVerifier};

use schnorr::SchnorrSignature;

use crate::{DkgError, ThresholdParams, ThresholdCore, validate_map};

#[allow(non_snake_case)]
fn challenge<C: Ciphersuite>(context: &str, l: u16, R: &[u8], Am: &[u8]) -> C::F {
  const DST: &[u8] = b"FROST Schnorr Proof of Knowledge";

  // Hashes the context to get a fixed size value out of it
  let mut transcript = C::H::digest(context.as_bytes()).as_ref().to_vec();
  transcript.extend(l.to_be_bytes());
  transcript.extend(R);
  transcript.extend(Am);
  C::hash_to_F(DST, &transcript)
}

/// Commitments message to be broadcast to all other parties.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize)]
pub struct Commitments<C: Ciphersuite> {
  commitments: Vec<C::G>,
  enc_key: C::G,
  cached_msg: Vec<u8>,
  sig: SchnorrSignature<C>,
}
impl<C: Ciphersuite> Drop for Commitments<C> {
  fn drop(&mut self) {
    self.zeroize();
  }
}
impl<C: Ciphersuite> ZeroizeOnDrop for Commitments<C> {}

impl<C: Ciphersuite> Commitments<C> {
  pub fn read<R: Read>(reader: &mut R, params: ThresholdParams) -> io::Result<Self> {
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
    let enc_key = read_G()?;

    Ok(Commitments { commitments, enc_key, cached_msg, sig: SchnorrSignature::read(reader)? })
  }

  pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(&self.cached_msg)?;
    self.sig.write(writer)
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut buf = vec![];
    self.write(&mut buf).unwrap();
    buf
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
  ) -> (SecretShareMachine<C>, Commitments<C>) {
    let t = usize::from(self.params.t);
    let mut coefficients = Vec::with_capacity(t);
    let mut commitments = Vec::with_capacity(t);
    let mut cached_msg = vec![];

    for i in 0 .. t {
      // Step 1: Generate t random values to form a polynomial with
      coefficients.push(C::random_nonzero_F(&mut *rng));
      // Step 3: Generate public commitments
      commitments.push(C::generator() * coefficients[i]);
      cached_msg.extend(commitments[i].to_bytes().as_ref());
    }

    // Generate an encryption key for transmitting the secret shares
    // It would probably be perfectly fine to use one of our polynomial elements, yet doing so
    // puts the integrity of FROST at risk. While there's almost no way it could, as it's used in
    // an ECDH with validated group elemnents, better to avoid any questions on it
    let enc_key = C::random_nonzero_F(&mut *rng);
    let pub_enc_key = C::generator() * enc_key;
    cached_msg.extend(pub_enc_key.to_bytes().as_ref());

    // Step 2: Provide a proof of knowledge
    let mut r = C::random_nonzero_F(rng);
    let sig = SchnorrSignature::<C>::sign(
      coefficients[0],
      // This could be deterministic as the PoK is a singleton never opened up to cooperative
      // discussion
      // There's no reason to spend the time and effort to make this deterministic besides a
      // general obsession with canonicity and determinism though
      r,
      challenge::<C>(
        &self.context,
        self.params.i(),
        (C::generator() * r).to_bytes().as_ref(),
        &cached_msg,
      ),
    );
    r.zeroize();

    // Step 4: Broadcast
    (
      SecretShareMachine {
        params: self.params,
        context: self.context,
        coefficients,
        our_commitments: commitments.clone(),
        enc_key,
      },
      Commitments { commitments, enc_key: pub_enc_key, cached_msg, sig },
    )
  }
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

/// Secret share to be sent to the party it's intended for over an authenticated channel.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SecretShare<F: PrimeField>(F::Repr);
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

impl<F: PrimeField> SecretShare<F> {
  pub fn read<R: Read>(reader: &mut R) -> io::Result<Self> {
    let mut repr = F::Repr::default();
    reader.read_exact(repr.as_mut())?;
    Ok(SecretShare(repr))
  }

  pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(self.0.as_ref())
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut buf = vec![];
    self.write(&mut buf).unwrap();
    buf
  }
}

fn create_ciphers<C: Ciphersuite>(
  mut sender: <C::G as GroupEncoding>::Repr,
  receiver: &mut <C::G as GroupEncoding>::Repr,
  ecdh: &mut <C::G as GroupEncoding>::Repr,
) -> (ChaCha20, ChaCha20) {
  let directional = |sender: &mut <C::G as GroupEncoding>::Repr| {
    let mut key = Cc20Key::default();
    key.copy_from_slice(
      &Hkdf::<C::H, SimpleHmac<C::H>>::extract(
        Some(b"key"),
        &[sender.as_ref(), ecdh.as_ref()].concat(),
      )
      .0
      .as_ref()[.. 32],
    );
    let mut iv = Cc20Iv::default();
    iv.copy_from_slice(
      &Hkdf::<C::H, SimpleHmac<C::H>>::extract(
        Some(b"iv"),
        &[sender.as_ref(), ecdh.as_ref()].concat(),
      )
      .0
      .as_ref()[.. 12],
    );
    sender.as_mut().zeroize();

    let res = ChaCha20::new(&key, &iv);
    <Cc20Key as AsMut<[u8]>>::as_mut(&mut key).zeroize();
    <Cc20Iv as AsMut<[u8]>>::as_mut(&mut iv).zeroize();
    res
  };

  let res = (directional(&mut sender), directional(receiver));
  ecdh.as_mut().zeroize();
  res
}

/// Advancement of the key generation state machine.
#[derive(Zeroize)]
pub struct SecretShareMachine<C: Ciphersuite> {
  params: ThresholdParams,
  context: String,
  coefficients: Vec<C::F>,
  our_commitments: Vec<C::G>,
  enc_key: C::F,
}
impl<C: Ciphersuite> Drop for SecretShareMachine<C> {
  fn drop(&mut self) {
    self.zeroize()
  }
}
impl<C: Ciphersuite> ZeroizeOnDrop for SecretShareMachine<C> {}

impl<C: Ciphersuite> SecretShareMachine<C> {
  /// Verify the data from the previous round (canonicity, PoKs, message authenticity)
  fn verify_r1<R: RngCore + CryptoRng>(
    &mut self,
    rng: &mut R,
    mut commitments: HashMap<u16, Commitments<C>>,
  ) -> Result<(HashMap<u16, Vec<C::G>>, HashMap<u16, C::G>), DkgError> {
    validate_map(&commitments, &(1 ..= self.params.n()).collect::<Vec<_>>(), self.params.i())?;

    let mut enc_keys = HashMap::new();
    let mut batch = BatchVerifier::<u16, C::G>::new(commitments.len());
    let mut commitments = commitments
      .drain()
      .map(|(l, mut msg)| {
        enc_keys.insert(l, msg.enc_key);
        msg.enc_key.zeroize();

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
    Ok((commitments, enc_keys))
  }

  /// Continue generating a key.
  /// Takes in everyone else's commitments. Returns a HashMap of secret shares to be sent over
  /// authenticated channels to their relevant counterparties.
  pub fn generate_secret_shares<R: RngCore + CryptoRng>(
    mut self,
    rng: &mut R,
    commitments: HashMap<u16, Commitments<C>>,
  ) -> Result<(KeyMachine<C>, HashMap<u16, SecretShare<C::F>>), DkgError> {
    let (commitments, mut enc_keys) = self.verify_r1(&mut *rng, commitments)?;

    // Step 1: Generate secret shares for all other parties
    let mut sender = (C::generator() * self.enc_key).to_bytes();
    let mut ciphers = HashMap::new();
    let mut res = HashMap::new();
    for l in 1 ..= self.params.n() {
      // Don't insert our own shares to the byte buffer which is meant to be sent around
      // An app developer could accidentally send it. Best to keep this black boxed
      if l == self.params.i() {
        continue;
      }

      let (mut cipher_send, cipher_recv) = {
        let receiver = enc_keys.get_mut(&l).unwrap();
        let mut ecdh = (*receiver * self.enc_key).to_bytes();

        create_ciphers::<C>(sender, &mut receiver.to_bytes(), &mut ecdh)
      };

      let mut share = polynomial(&self.coefficients, l);
      let mut share_bytes = share.to_repr();
      share.zeroize();

      cipher_send.apply_keystream(share_bytes.as_mut());
      drop(cipher_send);

      ciphers.insert(l, cipher_recv);
      res.insert(l, SecretShare::<C::F>(share_bytes));
      share_bytes.as_mut().zeroize();
    }
    self.enc_key.zeroize();
    sender.as_mut().zeroize();

    // Calculate our own share
    let share = polynomial(&self.coefficients, self.params.i());

    self.coefficients.zeroize();

    Ok((KeyMachine { params: self.params, secret: share, commitments, ciphers }, res))
  }
}

/// Final step of the key generation protocol.
pub struct KeyMachine<C: Ciphersuite> {
  params: ThresholdParams,
  secret: C::F,
  ciphers: HashMap<u16, ChaCha20>,
  commitments: HashMap<u16, Vec<C::G>>,
}
impl<C: Ciphersuite> Zeroize for KeyMachine<C> {
  fn zeroize(&mut self) {
    self.params.zeroize();
    self.secret.zeroize();

    // cipher implements ZeroizeOnDrop and zeroizes on drop, yet doesn't implement Zeroize
    // The following is redundant, as Rust should automatically handle dropping it, yet it shows
    // awareness of this quirk and at least attempts to be comprehensive
    for (_, cipher) in self.ciphers.drain() {
      drop(cipher);
    }

    for (_, commitments) in self.commitments.iter_mut() {
      commitments.zeroize();
    }
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
    mut shares: HashMap<u16, SecretShare<C::F>>,
  ) -> Result<ThresholdCore<C>, DkgError> {
    let mut secret_share = self.secret;
    self.secret.zeroize();

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
    for (l, mut share_bytes) in shares.drain() {
      let mut cipher = self.ciphers.remove(&l).unwrap();
      cipher.apply_keystream(share_bytes.0.as_mut());
      drop(cipher);

      let mut share: C::F =
        Option::from(C::F::from_repr(share_bytes.0)).ok_or(DkgError::InvalidShare(l))?;
      share_bytes.zeroize();
      secret_share += share;

      // This can be insecurely linearized from n * t to just n using the below sums for a given
      // stripe. Doing so uses naive addition which is subject to malleability. The only way to
      // ensure that malleability isn't present is to use this n * t algorithm, which runs
      // per sender and not as an aggregate of all senders, which also enables blame
      let mut values = exponential(self.params.i, &self.commitments[&l]);
      values.push((-share, C::generator()));
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
      verification_shares.insert(i, multiexp_vartime(&exponential(i, &stripes)));
    }
    // Removing this check would enable optimizing the above from t + (n * t) to t + ((n - 1) * t)
    debug_assert_eq!(C::generator() * secret_share, verification_shares[&self.params.i()]);

    Ok(ThresholdCore {
      params: self.params,
      secret_share,
      group_key: stripes[0],
      verification_shares,
    })
  }
}
