use core::{ops::Deref, fmt::Debug};
use std_shims::{
  sync::{Arc, Mutex},
  io::{self, Read, Write},
  collections::HashMap,
};

use rand_core::{RngCore, CryptoRng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use zeroize::{Zeroize, Zeroizing};

use curve25519_dalek::{scalar::Scalar, edwards::EdwardsPoint};

use group::{
  ff::{Field, PrimeField},
  Group, GroupEncoding,
};

use transcript::{Transcript, RecommendedTranscript};
use dalek_ff_group as dfg;
use frost::{
  dkg::lagrange,
  curve::Ed25519,
  Participant, FrostError, ThresholdKeys, ThresholdView,
  algorithm::{WriteAddendum, Algorithm},
};

use monero_generators::hash_to_point;

use crate::{ClsagContext, Clsag};

impl ClsagContext {
  fn transcript<T: Transcript>(&self, transcript: &mut T) {
    // Doesn't domain separate as this is considered part of the larger CLSAG proof

    // Ring index
    transcript.append_message(b"signer_index", [self.decoys.signer_index()]);

    // Ring
    for (i, pair) in self.decoys.ring().iter().enumerate() {
      // Doesn't include global output indexes as CLSAG doesn't care/won't be affected by it
      // They're just a unreliable reference to this data which will be included in the message
      // if somehow relevant
      transcript.append_message(b"member", [u8::try_from(i).expect("ring size exceeded 255")]);
      // This also transcripts the key image generator since it's derived from this key
      transcript.append_message(b"key", pair[0].compress().to_bytes());
      transcript.append_message(b"commitment", pair[1].compress().to_bytes())
    }

    // Doesn't include the commitment's parts as the above ring + index includes the commitment
    // The only potential malleability would be if the G/H relationship is known, breaking the
    // discrete log problem, which breaks everything already
  }
}

/// A channel to send the mask to use for the pseudo-out (rerandomized commitment) with.
///
/// A mask must be sent along this channel before any preprocess addendums are handled. Breaking
/// this rule will cause a panic.
#[derive(Clone, Debug)]
pub struct ClsagMultisigMaskSender {
  buf: Arc<Mutex<Option<Scalar>>>,
}
#[derive(Clone, Debug)]
struct ClsagMultisigMaskReceiver {
  buf: Arc<Mutex<Option<Scalar>>>,
}
impl ClsagMultisigMaskSender {
  fn new() -> (ClsagMultisigMaskSender, ClsagMultisigMaskReceiver) {
    let buf = Arc::new(Mutex::new(None));
    (ClsagMultisigMaskSender { buf: buf.clone() }, ClsagMultisigMaskReceiver { buf })
  }

  /// Send a mask to a CLSAG multisig instance.
  pub fn send(self, mask: Scalar) {
    *self.buf.lock() = Some(mask);
  }
}
impl ClsagMultisigMaskReceiver {
  fn recv(self) -> Scalar {
    self.buf.lock().unwrap()
  }
}

/// Addendum produced during the signing process.
#[derive(Clone, PartialEq, Eq, Zeroize, Debug)]
pub struct ClsagAddendum {
  key_image_share: dfg::EdwardsPoint,
}

impl ClsagAddendum {
  /// The key image share within this addendum.
  pub fn key_image_share(&self) -> dfg::EdwardsPoint {
    self.key_image_share
  }
}

impl WriteAddendum for ClsagAddendum {
  fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(self.key_image_share.compress().to_bytes().as_ref())
  }
}

#[allow(non_snake_case)]
#[derive(Clone, PartialEq, Eq, Debug)]
struct Interim {
  p: Scalar,
  c: Scalar,

  clsag: Clsag,
  pseudo_out: EdwardsPoint,
}

/// FROST-inspired algorithm for producing a CLSAG signature.
///
/// Before this has its `process_addendum` called, a mask must be set. Else this will panic.
///
/// The message signed is expected to be a 32-byte value. Per Monero, it's the keccak256 hash of
/// the transaction data which is signed. This will panic if the message is not a 32-byte value.
#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct ClsagMultisig {
  transcript: RecommendedTranscript,

  key_image_generator: EdwardsPoint,
  key_image_shares: HashMap<[u8; 32], dfg::EdwardsPoint>,
  image: Option<dfg::EdwardsPoint>,

  context: ClsagContext,

  mask_recv: Option<ClsagMultisigMaskReceiver>,
  mask: Option<Scalar>,

  msg: Option<[u8; 32]>,
  interim: Option<Interim>,
}

impl ClsagMultisig {
  /// Construct a new instance of multisignature CLSAG signing.
  pub fn new(
    transcript: RecommendedTranscript,
    context: ClsagContext,
  ) -> (ClsagMultisig, ClsagMultisigMaskSender) {
    let (mask_send, mask_recv) = ClsagMultisigMaskSender::new();
    (
      ClsagMultisig {
        transcript,

        key_image_generator: hash_to_point(context.decoys.signer_ring_members()[0].compress().0),
        key_image_shares: HashMap::new(),
        image: None,

        context,

        mask_recv: Some(mask_recv),
        mask: None,

        msg: None,
        interim: None,
      },
      mask_send,
    )
  }

  /// The key image generator used by the signer.
  pub fn key_image_generator(&self) -> EdwardsPoint {
    self.key_image_generator
  }
}

impl Algorithm<Ed25519> for ClsagMultisig {
  type Transcript = RecommendedTranscript;
  type Addendum = ClsagAddendum;
  // We output the CLSAG and the key image, which requires an interactive protocol to obtain
  type Signature = (Clsag, EdwardsPoint);

  // We need the nonce represented against both G and the key image generator
  fn nonces(&self) -> Vec<Vec<dfg::EdwardsPoint>> {
    vec![vec![dfg::EdwardsPoint::generator(), dfg::EdwardsPoint(self.key_image_generator)]]
  }

  // We also publish our share of the key image
  fn preprocess_addendum<R: RngCore + CryptoRng>(
    &mut self,
    _rng: &mut R,
    keys: &ThresholdKeys<Ed25519>,
  ) -> ClsagAddendum {
    ClsagAddendum {
      key_image_share: dfg::EdwardsPoint(self.key_image_generator) * keys.secret_share().deref(),
    }
  }

  fn read_addendum<R: Read>(&self, reader: &mut R) -> io::Result<ClsagAddendum> {
    let mut bytes = [0; 32];
    reader.read_exact(&mut bytes)?;
    // dfg ensures the point is torsion free
    let xH = Option::<dfg::EdwardsPoint>::from(dfg::EdwardsPoint::from_bytes(&bytes))
      .ok_or_else(|| io::Error::other("invalid key image"))?;
    // Ensure this is a canonical point
    if xH.to_bytes() != bytes {
      Err(io::Error::other("non-canonical key image"))?;
    }

    Ok(ClsagAddendum { key_image_share: xH })
  }

  fn process_addendum(
    &mut self,
    view: &ThresholdView<Ed25519>,
    l: Participant,
    addendum: ClsagAddendum,
  ) -> Result<(), FrostError> {
    if self.image.is_none() {
      self.transcript.domain_separate(b"CLSAG");
      // Transcript the ring
      self.context.transcript(&mut self.transcript);
      // Fetch the mask from the Mutex
      // We set it to a variable to ensure our view of it is consistent
      // It was this or a mpsc channel... std doesn't have oneshot :/
      self.mask = Some(self.mask_recv.take().unwrap().recv());
      // Transcript the mask
      self.transcript.append_message(b"mask", self.mask.expect("mask wasn't set").to_bytes());

      // Init the image to the offset
      self.image = Some(dfg::EdwardsPoint(self.key_image_generator) * view.offset());
    }

    // Transcript this participant's contribution
    self.transcript.append_message(b"participant", l.to_bytes());
    self
      .transcript
      .append_message(b"key_image_share", addendum.key_image_share.compress().to_bytes());

    // Accumulate the interpolated share
    let interpolated_key_image_share =
      addendum.key_image_share * lagrange::<dfg::Scalar>(l, view.included());
    *self.image.as_mut().unwrap() += interpolated_key_image_share;

    self
      .key_image_shares
      .insert(view.verification_share(l).to_bytes(), interpolated_key_image_share);

    Ok(())
  }

  fn transcript(&mut self) -> &mut Self::Transcript {
    &mut self.transcript
  }

  fn sign_share(
    &mut self,
    view: &ThresholdView<Ed25519>,
    nonce_sums: &[Vec<dfg::EdwardsPoint>],
    nonces: Vec<Zeroizing<dfg::Scalar>>,
    msg: &[u8],
  ) -> dfg::Scalar {
    // Use the transcript to get a seeded random number generator
    //
    // The transcript contains private data, preventing passive adversaries from recreating this
    // process even if they have access to the commitments/key image share broadcast so far
    //
    // Specifically, the transcript contains the signer's index within the ring, along with the
    // opening of the commitment being re-randomized (and what it's re-randomized to)
    let mut rng = ChaCha20Rng::from_seed(self.transcript.rng_seed(b"decoy_responses"));

    self.msg = Some(msg.try_into().expect("CLSAG message should be 32-bytes"));

    let sign_core = Clsag::sign_core(
      &mut rng,
      &self.image.expect("verifying a share despite never processing any addendums").0,
      &self.context,
      self.mask.expect("mask wasn't set"),
      self.msg.as_ref().unwrap(),
      nonce_sums[0][0].0,
      nonce_sums[0][1].0,
    );
    self.interim = Some(Interim {
      p: sign_core.key_challenge,
      c: sign_core.challenged_mask,
      clsag: sign_core.incomplete_clsag,
      pseudo_out: sign_core.pseudo_out,
    });

    // r - p x, where p is the challenge for the keys
    *nonces[0] - dfg::Scalar(sign_core.key_challenge) * view.secret_share().deref()
  }

  #[must_use]
  fn verify(
    &self,
    _: dfg::EdwardsPoint,
    _: &[Vec<dfg::EdwardsPoint>],
    sum: dfg::Scalar,
  ) -> Option<Self::Signature> {
    let interim = self.interim.as_ref().unwrap();
    let mut clsag = interim.clsag.clone();
    // We produced shares as `r - p x`, yet the signature is actually `r - p x - c x`
    // Substract `c x` (saved as `c`) now
    clsag.s[usize::from(self.context.decoys.signer_index())] = sum.0 - interim.c;
    if clsag
      .verify(
        self.context.decoys.ring(),
        &self.image.expect("verifying a signature despite never processing any addendums").0,
        &interim.pseudo_out,
        self.msg.as_ref().unwrap(),
      )
      .is_ok()
    {
      return Some((clsag, interim.pseudo_out));
    }
    None
  }

  fn verify_share(
    &self,
    verification_share: dfg::EdwardsPoint,
    nonces: &[Vec<dfg::EdwardsPoint>],
    share: dfg::Scalar,
  ) -> Result<Vec<(dfg::Scalar, dfg::EdwardsPoint)>, ()> {
    let interim = self.interim.as_ref().unwrap();

    // For a share `r - p x`, the following two equalities should hold:
    // - `(r - p x)G == R.0 - pV`, where `V = xG`
    // - `(r - p x)H == R.1 - pK`, where `K = xH` (the key image share)
    //
    // This is effectively a discrete log equality proof for:
    // V, K over G, H
    // with nonces
    // R.0, R.1
    // and solution
    // s
    //
    // Which is a batch-verifiable rewrite of the traditional CP93 proof
    // (and also writable as Generalized Schnorr Protocol)
    //
    // That means that given a proper challenge, this alone can be certainly argued to prove the
    // key image share is well-formed and the provided signature so proves for that.

    // This is a bit funky as it doesn't prove the nonces are well-formed however. They're part of
    // the prover data/transcript for a CP93/GSP proof, not part of the statement. This practically
    // is fine, for a variety of reasons (given a consistent `x`, a consistent `r` can be
    // extracted, and the nonces as used in CLSAG are also part of its prover data/transcript).

    let key_image_share = self.key_image_shares[&verification_share.to_bytes()];

    // Hash every variable relevant here, using the hash output as the random weight
    let mut weight_transcript =
      RecommendedTranscript::new(b"monero-serai v0.1 ClsagMultisig::verify_share");
    weight_transcript.append_message(b"G", dfg::EdwardsPoint::generator().to_bytes());
    weight_transcript.append_message(b"H", self.key_image_generator.to_bytes());
    weight_transcript.append_message(b"xG", verification_share.to_bytes());
    weight_transcript.append_message(b"xH", key_image_share.to_bytes());
    weight_transcript.append_message(b"rG", nonces[0][0].to_bytes());
    weight_transcript.append_message(b"rH", nonces[0][1].to_bytes());
    weight_transcript.append_message(b"c", dfg::Scalar(interim.p).to_repr());
    weight_transcript.append_message(b"s", share.to_repr());
    let weight = weight_transcript.challenge(b"weight");
    let weight = dfg::Scalar(Scalar::from_bytes_mod_order_wide(&weight.into()));

    let part_one = vec![
      (share, dfg::EdwardsPoint::generator()),
      // -(R.0 - pV) == -R.0 + pV
      (-dfg::Scalar::ONE, nonces[0][0]),
      (dfg::Scalar(interim.p), verification_share),
    ];

    let mut part_two = vec![
      (weight * share, dfg::EdwardsPoint(self.key_image_generator)),
      // -(R.1 - pK) == -R.1 + pK
      (-weight, nonces[0][1]),
      (weight * dfg::Scalar(interim.p), key_image_share),
    ];

    let mut all = part_one;
    all.append(&mut part_two);
    Ok(all)
  }
}
