use std_shims::{
  vec::Vec,
  io::{self, Read},
  collections::HashMap,
};

use rand_core::{RngCore, CryptoRng};

use group::ff::Field;
use curve25519_dalek::{traits::Identity, Scalar, EdwardsPoint};
use dalek_ff_group as dfg;

use transcript::{Transcript, RecommendedTranscript};
use frost::{
  curve::Ed25519,
  Participant, FrostError, ThresholdKeys,
  sign::{
    Preprocess, CachedPreprocess, SignatureShare, PreprocessMachine, SignMachine, SignatureMachine,
    AlgorithmMachine, AlgorithmSignMachine, AlgorithmSignatureMachine,
  },
};

use monero_serai::{
  ringct::{
    clsag::{ClsagContext, ClsagMultisigMaskSender, ClsagAddendum, ClsagMultisig},
    RctPrunable, RctProofs,
  },
  transaction::Transaction,
};
use crate::send::{SendError, SignableTransaction, key_image_sort};

/// Initial FROST machine to produce a signed transaction.
pub struct TransactionMachine {
  signable: SignableTransaction,

  keys: ThresholdKeys<Ed25519>,

  // The key image generator, and the scalar offset from the spend key
  key_image_generators_and_offsets: Vec<(EdwardsPoint, Scalar)>,
  clsags: Vec<(ClsagMultisigMaskSender, AlgorithmMachine<Ed25519, ClsagMultisig>)>,
}

/// Second FROST machine to produce a signed transaction.
pub struct TransactionSignMachine {
  signable: SignableTransaction,

  keys: ThresholdKeys<Ed25519>,

  key_image_generators_and_offsets: Vec<(EdwardsPoint, Scalar)>,
  clsags: Vec<(ClsagMultisigMaskSender, AlgorithmSignMachine<Ed25519, ClsagMultisig>)>,

  our_preprocess: Vec<Preprocess<Ed25519, ClsagAddendum>>,
}

/// Final FROST machine to produce a signed transaction.
pub struct TransactionSignatureMachine {
  tx: Transaction,
  clsags: Vec<AlgorithmSignatureMachine<Ed25519, ClsagMultisig>>,
}

impl SignableTransaction {
  /// Create a FROST signing machine out of this signable transaction.
  pub fn multisig(self, keys: ThresholdKeys<Ed25519>) -> Result<TransactionMachine, SendError> {
    let mut clsags = vec![];

    let mut key_image_generators_and_offsets = vec![];
    for input in &self.inputs {
      // Check this is the right set of keys
      let offset = keys.offset(dfg::Scalar(input.key_offset()));
      if offset.group_key().0 != input.key() {
        Err(SendError::WrongPrivateKey)?;
      }

      let context = ClsagContext::new(input.decoys().clone(), input.commitment().clone())
        .map_err(SendError::ClsagError)?;
      let (clsag, clsag_mask_send) = ClsagMultisig::new(
        RecommendedTranscript::new(b"Monero Multisignature Transaction"),
        context,
      );
      key_image_generators_and_offsets.push((
        clsag.key_image_generator(),
        keys.current_offset().unwrap_or(dfg::Scalar::ZERO).0 + input.key_offset(),
      ));
      clsags.push((clsag_mask_send, AlgorithmMachine::new(clsag, offset)));
    }

    Ok(TransactionMachine { signable: self, keys, key_image_generators_and_offsets, clsags })
  }
}

impl PreprocessMachine for TransactionMachine {
  type Preprocess = Vec<Preprocess<Ed25519, ClsagAddendum>>;
  type Signature = Transaction;
  type SignMachine = TransactionSignMachine;

  fn preprocess<R: RngCore + CryptoRng>(
    mut self,
    rng: &mut R,
  ) -> (TransactionSignMachine, Self::Preprocess) {
    // Iterate over each CLSAG calling preprocess
    let mut preprocesses = Vec::with_capacity(self.clsags.len());
    let clsags = self
      .clsags
      .drain(..)
      .map(|(clsag_mask_send, clsag)| {
        let (clsag, preprocess) = clsag.preprocess(rng);
        preprocesses.push(preprocess);
        (clsag_mask_send, clsag)
      })
      .collect();
    let our_preprocess = preprocesses.clone();

    (
      TransactionSignMachine {
        signable: self.signable,

        keys: self.keys,

        key_image_generators_and_offsets: self.key_image_generators_and_offsets,
        clsags,

        our_preprocess,
      },
      preprocesses,
    )
  }
}

impl SignMachine<Transaction> for TransactionSignMachine {
  type Params = ();
  type Keys = ThresholdKeys<Ed25519>;
  type Preprocess = Vec<Preprocess<Ed25519, ClsagAddendum>>;
  type SignatureShare = Vec<SignatureShare<Ed25519>>;
  type SignatureMachine = TransactionSignatureMachine;

  fn cache(self) -> CachedPreprocess {
    unimplemented!(
      "Monero transactions don't support caching their preprocesses due to {}",
      "being already bound to a specific transaction"
    );
  }

  fn from_cache(
    (): (),
    _: ThresholdKeys<Ed25519>,
    _: CachedPreprocess,
  ) -> (Self, Self::Preprocess) {
    unimplemented!(
      "Monero transactions don't support caching their preprocesses due to {}",
      "being already bound to a specific transaction"
    );
  }

  fn read_preprocess<R: Read>(&self, reader: &mut R) -> io::Result<Self::Preprocess> {
    self.clsags.iter().map(|clsag| clsag.1.read_preprocess(reader)).collect()
  }

  fn sign(
    self,
    mut commitments: HashMap<Participant, Self::Preprocess>,
    msg: &[u8],
  ) -> Result<(TransactionSignatureMachine, Self::SignatureShare), FrostError> {
    if !msg.is_empty() {
      panic!("message was passed to the TransactionMachine when it generates its own");
    }

    // We do not need to be included here, yet this set of signers has yet to be validated
    // We explicitly remove ourselves to ensure we aren't included twice, if we were redundantly
    // included
    commitments.remove(&self.keys.params().i());

    // Find out who's included
    let mut included = commitments.keys().copied().collect::<Vec<_>>();
    // This push won't duplicate due to the above removal
    included.push(self.keys.params().i());
    // unstable sort may reorder elements of equal order
    // Given our lack of duplicates, we should have no elements of equal order
    included.sort_unstable();

    // Start calculating the key images, as needed on the TX level
    let mut key_images = vec![EdwardsPoint::identity(); self.clsags.len()];
    for (image, (generator, offset)) in
      key_images.iter_mut().zip(&self.key_image_generators_and_offsets)
    {
      *image = generator * offset;
    }

    // Convert the serialized nonces commitments to a parallelized Vec
    let view = self.keys.view(included.clone()).map_err(|_| {
      FrostError::InvalidSigningSet("couldn't form an interpolated view of the key")
    })?;
    let mut commitments = (0 .. self.clsags.len())
      .map(|c| {
        included
          .iter()
          .map(|l| {
            let preprocess = if *l == self.keys.params().i() {
              self.our_preprocess[c].clone()
            } else {
              commitments.get_mut(l).ok_or(FrostError::MissingParticipant(*l))?[c].clone()
            };

            // While here, calculate the key image as needed to call sign
            // The CLSAG algorithm will independently calculate the key image/verify these shares
            key_images[c] +=
              preprocess.addendum.key_image_share().0 * view.interpolation_factor(*l).unwrap().0;

            Ok((*l, preprocess))
          })
          .collect::<Result<HashMap<_, _>, _>>()
      })
      .collect::<Result<Vec<_>, _>>()?;

    // The above inserted our own preprocess into these maps (which is unnecessary)
    // Remove it now
    for map in &mut commitments {
      map.remove(&self.keys.params().i());
    }

    // The actual TX will have sorted its inputs by key image
    // We apply the same sort now to our CLSAG machines
    let mut clsags = Vec::with_capacity(self.clsags.len());
    for ((key_image, clsag), commitments) in key_images.iter().zip(self.clsags).zip(commitments) {
      clsags.push((key_image, clsag, commitments));
    }
    clsags.sort_by(|x, y| key_image_sort(x.0, y.0));
    let clsags =
      clsags.into_iter().map(|(_, clsag, commitments)| (clsag, commitments)).collect::<Vec<_>>();

    // Specify the TX's key images
    let tx = self.signable.with_key_images(key_images);

    // We now need to decide the masks for each CLSAG
    let clsag_len = clsags.len();
    let output_masks = tx.intent.sum_output_masks(&tx.key_images);
    let mut rng = tx.intent.seeded_rng(b"multisig_pseudo_out_masks");
    let mut sum_pseudo_outs = Scalar::ZERO;
    let mut to_sign = Vec::with_capacity(clsag_len);
    for (i, ((clsag_mask_send, clsag), commitments)) in clsags.into_iter().enumerate() {
      let mut mask = Scalar::random(&mut rng);
      if i == (clsag_len - 1) {
        mask = output_masks - sum_pseudo_outs;
      } else {
        sum_pseudo_outs += mask;
      }
      clsag_mask_send.send(mask);
      to_sign.push((clsag, commitments));
    }

    let tx = tx.transaction_without_signatures();
    let msg = tx.signature_hash().unwrap();

    // Iterate over each CLSAG calling sign
    let mut shares = Vec::with_capacity(to_sign.len());
    let clsags = to_sign
      .drain(..)
      .map(|(clsag, commitments)| {
        let (clsag, share) = clsag.sign(commitments, &msg)?;
        shares.push(share);
        Ok(clsag)
      })
      .collect::<Result<_, _>>()?;

    Ok((TransactionSignatureMachine { tx, clsags }, shares))
  }
}

impl SignatureMachine<Transaction> for TransactionSignatureMachine {
  type SignatureShare = Vec<SignatureShare<Ed25519>>;

  fn read_share<R: Read>(&self, reader: &mut R) -> io::Result<Self::SignatureShare> {
    self.clsags.iter().map(|clsag| clsag.read_share(reader)).collect()
  }

  fn complete(
    mut self,
    shares: HashMap<Participant, Self::SignatureShare>,
  ) -> Result<Transaction, FrostError> {
    let mut tx = self.tx;
    match tx {
      Transaction::V2 {
        proofs:
          Some(RctProofs {
            prunable: RctPrunable::Clsag { ref mut clsags, ref mut pseudo_outs, .. },
            ..
          }),
        ..
      } => {
        for (c, clsag) in self.clsags.drain(..).enumerate() {
          let (clsag, pseudo_out) = clsag.complete(
            shares.iter().map(|(l, shares)| (*l, shares[c].clone())).collect::<HashMap<_, _>>(),
          )?;
          clsags.push(clsag);
          pseudo_outs.push(pseudo_out);
        }
      }
      _ => unreachable!("attempted to sign a multisig TX which wasn't CLSAG"),
    }
    Ok(tx)
  }
}
