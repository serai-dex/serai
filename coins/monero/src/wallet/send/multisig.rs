use std::{
  io::{Read, Cursor},
  sync::{Arc, RwLock},
  collections::HashMap,
};

use rand_core::{RngCore, CryptoRng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use curve25519_dalek::{
  traits::Identity,
  scalar::Scalar,
  edwards::{EdwardsPoint, CompressedEdwardsY},
};

use transcript::{Transcript, RecommendedTranscript};
use frost::{
  curve::Ed25519,
  FrostError, FrostKeys,
  sign::{
    PreprocessMachine, SignMachine, SignatureMachine, AlgorithmMachine, AlgorithmSignMachine,
    AlgorithmSignatureMachine,
  },
};

use crate::{
  random_scalar,
  ringct::{
    clsag::{ClsagInput, ClsagDetails, ClsagMultisig},
    RctPrunable,
  },
  transaction::{Input, Transaction},
  rpc::Rpc,
  wallet::{TransactionError, SignableTransaction, Decoys, key_image_sort, uniqueness},
};

/// FROST signing machine to produce a signed transaction.
pub struct TransactionMachine {
  signable: SignableTransaction,
  i: u16,
  included: Vec<u16>,
  transcript: RecommendedTranscript,

  decoys: Vec<Decoys>,

  inputs: Vec<Arc<RwLock<Option<ClsagDetails>>>>,
  clsags: Vec<AlgorithmMachine<Ed25519, ClsagMultisig>>,
}

pub struct TransactionSignMachine {
  signable: SignableTransaction,
  i: u16,
  included: Vec<u16>,
  transcript: RecommendedTranscript,

  decoys: Vec<Decoys>,

  inputs: Vec<Arc<RwLock<Option<ClsagDetails>>>>,
  clsags: Vec<AlgorithmSignMachine<Ed25519, ClsagMultisig>>,

  our_preprocess: Vec<u8>,
}

pub struct TransactionSignatureMachine {
  tx: Transaction,
  clsags: Vec<AlgorithmSignatureMachine<Ed25519, ClsagMultisig>>,
}

impl SignableTransaction {
  /// Create a FROST signing machine out of this signable transaction.
  /// The height is the Monero blockchain height to synchronize around.
  pub async fn multisig(
    self,
    rpc: &Rpc,
    keys: FrostKeys<Ed25519>,
    mut transcript: RecommendedTranscript,
    height: usize,
    mut included: Vec<u16>,
  ) -> Result<TransactionMachine, TransactionError> {
    let mut inputs = vec![];
    for _ in 0 .. self.inputs.len() {
      // Doesn't resize as that will use a single Rc for the entire Vec
      inputs.push(Arc::new(RwLock::new(None)));
    }
    let mut clsags = vec![];

    // Create a RNG out of the input shared keys, which either requires the view key or being every
    // sender, and the payments (address and amount), which a passive adversary may be able to know
    // depending on how these transactions are coordinated
    // Being every sender would already let you note rings which happen to use your transactions
    // multiple times, already breaking privacy there

    transcript.domain_separate(b"monero_transaction");
    // Include the height we're using for our data
    // The data itself will be included, making this unnecessary, yet a lot of this is technically
    // unnecessary. Anything which further increases security at almost no cost should be followed
    transcript.append_message(b"height", &u64::try_from(height).unwrap().to_le_bytes());
    // Also include the spend_key as below only the key offset is included, so this transcripts the
    // sum product
    // Useful as transcripting the sum product effectively transcripts the key image, further
    // guaranteeing the one time properties noted below
    transcript.append_message(b"spend_key", &keys.group_key().0.compress().to_bytes());
    for input in &self.inputs {
      // These outputs can only be spent once. Therefore, it forces all RNGs derived from this
      // transcript (such as the one used to create one time keys) to be unique
      transcript.append_message(b"input_hash", &input.output.absolute.tx);
      transcript.append_message(b"input_output_index", &[input.output.absolute.o]);
      // Not including this, with a doxxed list of payments, would allow brute forcing the inputs
      // to determine RNG seeds and therefore the true spends
      transcript.append_message(b"input_shared_key", &input.key_offset().to_bytes());
    }
    for payment in &self.payments {
      transcript.append_message(b"payment_address", payment.0.to_string().as_bytes());
      transcript.append_message(b"payment_amount", &payment.1.to_le_bytes());
    }

    // Sort included before cloning it around
    included.sort_unstable();

    for (i, input) in self.inputs.iter().enumerate() {
      // Check this the right set of keys
      let offset = keys.offset(dalek_ff_group::Scalar(input.key_offset()));
      if offset.group_key().0 != input.key() {
        Err(TransactionError::WrongPrivateKey)?;
      }

      clsags.push(
        AlgorithmMachine::new(
          ClsagMultisig::new(transcript.clone(), input.key(), inputs[i].clone()),
          offset,
          &included,
        )
        .map_err(TransactionError::FrostError)?,
      );
    }

    // Select decoys
    // Ideally, this would be done post entropy, instead of now, yet doing so would require sign
    // to be async which isn't preferable. This should be suitably competent though
    // While this inability means we can immediately create the input, moving it out of the
    // Arc RwLock, keeping it within an Arc RwLock keeps our options flexible
    let decoys = Decoys::select(
      // Using a seeded RNG with a specific height, committed to above, should make these decoys
      // committed to. They'll also be committed to later via the TX message as a whole
      &mut ChaCha20Rng::from_seed(transcript.rng_seed(b"decoys")),
      rpc,
      self.protocol.ring_len(),
      height,
      &self.inputs,
    )
    .await
    .map_err(TransactionError::RpcError)?;

    Ok(TransactionMachine {
      signable: self,
      i: keys.params().i(),
      included,
      transcript,

      decoys,

      inputs,
      clsags,
    })
  }
}

impl PreprocessMachine for TransactionMachine {
  type Signature = Transaction;
  type SignMachine = TransactionSignMachine;

  fn preprocess<R: RngCore + CryptoRng>(
    mut self,
    rng: &mut R,
  ) -> (TransactionSignMachine, Vec<u8>) {
    // Iterate over each CLSAG calling preprocess
    let mut serialized = Vec::with_capacity(
      // D_{G, H}, E_{G, H}, DLEqs, key image addendum
      self.clsags.len() * ((2 * (32 + 32)) + (2 * (32 + 32)) + ClsagMultisig::serialized_len()),
    );
    let clsags = self
      .clsags
      .drain(..)
      .map(|clsag| {
        let (clsag, preprocess) = clsag.preprocess(rng);
        serialized.extend(&preprocess);
        clsag
      })
      .collect();
    let our_preprocess = serialized.clone();

    // We could add further entropy here, and previous versions of this library did so
    // As of right now, the multisig's key, the inputs being spent, and the FROST data itself
    // will be used for RNG seeds. In order to recreate these RNG seeds, breaking privacy,
    // counterparties must have knowledge of the multisig, either the view key or access to the
    // coordination layer, and then access to the actual FROST signing process
    // If the commitments are sent in plain text, then entropy here also would be, making it not
    // increase privacy. If they're not sent in plain text, or are otherwise inaccessible, they
    // already offer sufficient entropy. That's why further entropy is not included

    (
      TransactionSignMachine {
        signable: self.signable,
        i: self.i,
        included: self.included,
        transcript: self.transcript,

        decoys: self.decoys,

        inputs: self.inputs,
        clsags,

        our_preprocess,
      },
      serialized,
    )
  }
}

impl SignMachine<Transaction> for TransactionSignMachine {
  type SignatureMachine = TransactionSignatureMachine;

  fn sign<Re: Read>(
    mut self,
    mut commitments: HashMap<u16, Re>,
    msg: &[u8],
  ) -> Result<(TransactionSignatureMachine, Vec<u8>), FrostError> {
    if !msg.is_empty() {
      Err(FrostError::InternalError(
        "message was passed to the TransactionMachine when it generates its own",
      ))?;
    }

    // FROST commitments and their DLEqs, and the image and its DLEq
    const CLSAG_LEN: usize = (2 * (32 + 32)) + (2 * (32 + 32)) + ClsagMultisig::serialized_len();

    // Convert the unified commitments to a Vec of the individual commitments
    let mut images = vec![EdwardsPoint::identity(); self.clsags.len()];
    let mut commitments = (0 .. self.clsags.len())
      .map(|c| {
        let mut buf = [0; CLSAG_LEN];
        self
          .included
          .iter()
          .map(|l| {
            // Add all commitments to the transcript for their entropy
            // While each CLSAG will do this as they need to for security, they have their own
            // transcripts cloned from this TX's initial premise's transcript. For our TX
            // transcript to have the CLSAG data for entropy, it'll have to be added ourselves here
            self.transcript.append_message(b"participant", &(*l).to_be_bytes());
            if *l == self.i {
              buf.copy_from_slice(self.our_preprocess.drain(.. CLSAG_LEN).as_slice());
            } else {
              commitments
                .get_mut(l)
                .ok_or(FrostError::MissingParticipant(*l))?
                .read_exact(&mut buf)
                .map_err(|_| FrostError::InvalidCommitment(*l))?;
            }
            self.transcript.append_message(b"preprocess", &buf);

            // While here, calculate the key image
            // Clsag will parse/calculate/validate this as needed, yet doing so here as well
            // provides the easiest API overall, as this is where the TX is (which needs the key
            // images in its message), along with where the outputs are determined (where our
            // outputs may need these in order to guarantee uniqueness)
            images[c] += CompressedEdwardsY(
              buf[(CLSAG_LEN - 96) .. (CLSAG_LEN - 64)]
                .try_into()
                .map_err(|_| FrostError::InvalidCommitment(*l))?,
            )
            .decompress()
            .ok_or(FrostError::InvalidCommitment(*l))?;

            Ok((*l, Cursor::new(buf)))
          })
          .collect::<Result<HashMap<_, _>, _>>()
      })
      .collect::<Result<Vec<_>, _>>()?;

    // Remove our preprocess which shouldn't be here. It was just the easiest way to implement the
    // above
    for map in commitments.iter_mut() {
      map.remove(&self.i);
    }

    // Create the actual transaction
    let (mut tx, output_masks) = {
      let mut sorted_images = images.clone();
      sorted_images.sort_by(key_image_sort);

      self.signable.prepare_transaction(
        &mut ChaCha20Rng::from_seed(self.transcript.rng_seed(b"transaction_keys_bulletproofs")),
        uniqueness(
          &sorted_images
            .iter()
            .map(|image| Input::ToKey { amount: 0, key_offsets: vec![], key_image: *image })
            .collect::<Vec<_>>(),
        ),
      )
    };

    // Sort the inputs, as expected
    let mut sorted = Vec::with_capacity(self.clsags.len());
    while !self.clsags.is_empty() {
      sorted.push((
        images.swap_remove(0),
        self.signable.inputs.swap_remove(0),
        self.decoys.swap_remove(0),
        self.inputs.swap_remove(0),
        self.clsags.swap_remove(0),
        commitments.swap_remove(0),
      ));
    }
    sorted.sort_by(|x, y| key_image_sort(&x.0, &y.0));

    let mut rng = ChaCha20Rng::from_seed(self.transcript.rng_seed(b"pseudo_out_masks"));
    let mut sum_pseudo_outs = Scalar::zero();
    while !sorted.is_empty() {
      let value = sorted.remove(0);

      let mut mask = random_scalar(&mut rng);
      if sorted.is_empty() {
        mask = output_masks - sum_pseudo_outs;
      } else {
        sum_pseudo_outs += mask;
      }

      tx.prefix.inputs.push(Input::ToKey {
        amount: 0,
        key_offsets: value.2.offsets.clone(),
        key_image: value.0,
      });

      *value.3.write().unwrap() = Some(ClsagDetails::new(
        ClsagInput::new(value.1.commitment().clone(), value.2).map_err(|_| {
          panic!("Signing an input which isn't present in the ring we created for it")
        })?,
        mask,
      ));

      self.clsags.push(value.4);
      commitments.push(value.5);
    }

    let msg = tx.signature_hash();

    // Iterate over each CLSAG calling sign
    let mut serialized = Vec::with_capacity(self.clsags.len() * 32);
    let clsags = self
      .clsags
      .drain(..)
      .map(|clsag| {
        let (clsag, share) = clsag.sign(commitments.remove(0), &msg)?;
        serialized.extend(&share);
        Ok(clsag)
      })
      .collect::<Result<_, _>>()?;

    Ok((TransactionSignatureMachine { tx, clsags }, serialized))
  }
}

impl SignatureMachine<Transaction> for TransactionSignatureMachine {
  fn complete<Re: Read>(self, mut shares: HashMap<u16, Re>) -> Result<Transaction, FrostError> {
    let mut tx = self.tx;
    match tx.rct_signatures.prunable {
      RctPrunable::Null => panic!("Signing for RctPrunable::Null"),
      RctPrunable::Clsag { ref mut clsags, ref mut pseudo_outs, .. } => {
        for clsag in self.clsags {
          let (clsag, pseudo_out) = clsag.complete(
            shares
              .iter_mut()
              .map(|(l, shares)| {
                let mut buf = [0; 32];
                shares.read_exact(&mut buf).map_err(|_| FrostError::InvalidShare(*l))?;
                Ok((*l, Cursor::new(buf)))
              })
              .collect::<Result<HashMap<_, _>, _>>()?,
          )?;
          clsags.push(clsag);
          pseudo_outs.push(pseudo_out);
        }
      }
    }
    Ok(tx)
  }
}
