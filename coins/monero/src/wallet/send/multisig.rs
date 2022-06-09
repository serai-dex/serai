use std::{sync::{Arc, RwLock}, collections::HashMap};

use rand_core::{RngCore, CryptoRng, SeedableRng};
use rand_chacha::ChaCha12Rng;

use curve25519_dalek::{traits::Identity, scalar::Scalar, edwards::{EdwardsPoint, CompressedEdwardsY}};

use transcript::Transcript as TranscriptTrait;
use frost::{FrostError, MultisigKeys, MultisigParams, sign::{State, StateMachine, AlgorithmMachine}};

use crate::{
  frost::{Transcript, Ed25519},
  random_scalar, ringct::{clsag::{ClsagInput, ClsagDetails, ClsagMultisig}, bulletproofs::Bulletproofs, RctPrunable},
  transaction::{Input, Transaction},
  rpc::Rpc,
  wallet::{TransactionError, SignableTransaction, Decoys, key_image_sort, uniqueness}
};

pub struct TransactionMachine {
  signable: SignableTransaction,
  i: u16,
  included: Vec<u16>,
  transcript: Transcript,

  decoys: Vec<Decoys>,

  our_preprocess: Vec<u8>,

  images: Vec<EdwardsPoint>,
  output_masks: Option<Scalar>,
  inputs: Vec<Arc<RwLock<Option<ClsagDetails>>>>,
  clsags: Vec<AlgorithmMachine<Ed25519, ClsagMultisig>>,

  tx: Option<Transaction>
}

impl SignableTransaction {
  pub async fn multisig<R: RngCore + CryptoRng>(
    mut self,
    rng: &mut R,
    rpc: &Rpc,
    keys: MultisigKeys<Ed25519>,
    mut transcript: Transcript,
    height: usize,
    mut included: Vec<u16>
  ) -> Result<TransactionMachine, TransactionError> {
    let mut images = vec![];
    images.resize(self.inputs.len(), EdwardsPoint::identity());
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
    // Also include the spend_key as below only the key offset is included, so this confirms the sum product
    // Useful as confirming the sum product confirms the key image, further guaranteeing the one time
    // properties noted below
    transcript.append_message(b"spend_key", &keys.group_key().0.compress().to_bytes());
    for input in &self.inputs {
      // These outputs can only be spent once. Therefore, it forces all RNGs derived from this
      // transcript (such as the one used to create one time keys) to be unique
      transcript.append_message(b"input_hash", &input.tx);
      transcript.append_message(b"input_output_index", &[input.o]);
      // Not including this, with a doxxed list of payments, would allow brute forcing the inputs
      // to determine RNG seeds and therefore the true spends
      transcript.append_message(b"input_shared_key", &input.key_offset.to_bytes());
    }
    for payment in &self.payments {
      transcript.append_message(b"payment_address", &payment.0.as_bytes());
      transcript.append_message(b"payment_amount", &payment.1.to_le_bytes());
    }
    transcript.append_message(b"change", &self.change.as_bytes());

    // Sort included before cloning it around
    included.sort_unstable();

    for (i, input) in self.inputs.iter().enumerate() {
      // Check this the right set of keys
      let offset = keys.offset(dalek_ff_group::Scalar(input.key_offset));
      if offset.group_key().0 != input.key {
        Err(TransactionError::WrongPrivateKey)?;
      }

      clsags.push(
        AlgorithmMachine::new(
          ClsagMultisig::new(
            transcript.clone(),
            inputs[i].clone()
          ).map_err(|e| TransactionError::MultisigError(e))?,
          Arc::new(offset),
          &included
        ).map_err(|e| TransactionError::FrostError(e))?
      );
    }

    // Verify these outputs by a dummy prep
    self.prepare_outputs(rng, [0; 32])?;

    // Select decoys
    // Ideally, this would be done post entropy, instead of now, yet doing so would require sign
    // to be async which isn't preferable. This should be suitably competent though
    // While this inability means we can immediately create the input, moving it out of the
    // Arc RwLock, keeping it within an Arc RwLock keeps our options flexible
    let decoys = Decoys::select(
      // Using a seeded RNG with a specific height, committed to above, should make these decoys
      // committed to. They'll also be committed to later via the TX message as a whole
      &mut ChaCha12Rng::from_seed(transcript.rng_seed(b"decoys")),
      rpc,
      height,
      &self.inputs
    ).await.map_err(|e| TransactionError::RpcError(e))?;

    Ok(TransactionMachine {
      signable: self,
      i: keys.params().i(),
      included,
      transcript,

      decoys,

      our_preprocess: vec![],

      images,
      output_masks: None,
      inputs,
      clsags,

      tx: None
    })
  }
}

impl StateMachine for TransactionMachine {
  type Signature = Transaction;

  fn preprocess<R: RngCore + CryptoRng>(
    &mut self,
    rng: &mut R
  ) -> Result<Vec<u8>, FrostError> {
    if self.state() != State::Fresh {
      Err(FrostError::InvalidSignTransition(State::Fresh, self.state()))?;
    }

    // Iterate over each CLSAG calling preprocess
    let mut serialized = Vec::with_capacity(self.clsags.len() * (64 + ClsagMultisig::serialized_len()));
    for clsag in self.clsags.iter_mut() {
      serialized.extend(&clsag.preprocess(rng)?);
    }
    self.our_preprocess = serialized.clone();

    // We could add further entropy here, and previous versions of this library did so
    // As of right now, the multisig's key, the inputs being spent, and the FROST data itself
    // will be used for RNG seeds. In order to recreate these RNG seeds, breaking privacy,
    // counterparties must have knowledge of the multisig, either the view key or access to the
    // coordination layer, and then access to the actual FROST signing process
    // If the commitments are sent in plain text, then entropy here also would be, making it not
    // increase privacy. If they're not sent in plain text, or are otherwise inaccessible, they
    // already offer sufficient entropy. That's why further entropy is not included

    Ok(serialized)
  }

  fn sign(
    &mut self,
    mut commitments: HashMap<u16, Vec<u8>>,
    // Drop FROST's 'msg' since we calculate the actual message in this function
    _: &[u8]
  ) -> Result<Vec<u8>, FrostError> {
    if self.state() != State::Preprocessed {
      Err(FrostError::InvalidSignTransition(State::Preprocessed, self.state()))?;
    }

    // Add all commitments to the transcript for their entropy
    // While each CLSAG will do this as they need to for security, they have their own transcripts
    // cloned from this TX's initial premise's transcript. For our TX transcript to have the CLSAG
    // data for entropy, it'll have to be added ourselves
    commitments.insert(self.i, self.our_preprocess.clone());
    for l in &self.included {
      self.transcript.append_message(b"participant", &(*l).to_be_bytes());
      // FROST itself will error if this is None, so let it
      if let Some(preprocess) = commitments.get(l) {
        self.transcript.append_message(b"preprocess", preprocess);
      }
    }

    // FROST commitments, image, H commitments, and their proofs
    let clsag_len = 64 + ClsagMultisig::serialized_len();

    let mut commitments = (0 .. self.clsags.len()).map(|c| commitments.iter().map(
      |(l, commitments)| (*l, commitments[(c * clsag_len) .. ((c + 1) * clsag_len)].to_vec())
    ).collect::<HashMap<_, _>>()).collect::<Vec<_>>();

    for c in 0 .. self.clsags.len() {
      // Calculate the key images
      // Multisig will parse/calculate/validate this as needed, yet doing so here as well provides
      // the easiest API overall, as this is where the TX is (which needs the key images in its
      // message), along with where the outputs are determined (where our change output needs these
      // to be unique)
      for (l, preprocess) in &commitments[c] {
        self.images[c] += CompressedEdwardsY(
          preprocess[64 .. 96].try_into().map_err(|_| FrostError::InvalidCommitment(*l))?
        ).decompress().ok_or(FrostError::InvalidCommitment(*l))?;
      }
    }

    // Create the actual transaction
    let mut tx = {
      // Calculate uniqueness
      let mut images = self.images.clone();
      images.sort_by(key_image_sort);

      // Not invalid outputs due to already doing a dummy prep
      let (commitments, output_masks) = self.signable.prepare_outputs(
        &mut ChaCha12Rng::from_seed(self.transcript.rng_seed(b"tx_keys")),
        uniqueness(
          &images.iter().map(|image| Input::ToKey {
            amount: 0,
            key_offsets: vec![],
            key_image: *image
          }).collect::<Vec<_>>()
        )
      ).expect("Couldn't prepare outputs despite already doing a dummy prep");
      self.output_masks = Some(output_masks);

      self.signable.prepare_transaction(
        &commitments,
        Bulletproofs::new(
          &mut ChaCha12Rng::from_seed(self.transcript.rng_seed(b"bulletproofs")),
          &commitments
        ).unwrap()
      )
    };

    let mut sorted = Vec::with_capacity(self.decoys.len());
    while self.decoys.len() != 0 {
      sorted.push((
        self.signable.inputs.swap_remove(0),
        self.decoys.swap_remove(0),
        self.images.swap_remove(0),
        self.inputs.swap_remove(0),
        self.clsags.swap_remove(0),
        commitments.swap_remove(0)
      ));
    }
    sorted.sort_by(|x, y| x.2.compress().to_bytes().cmp(&y.2.compress().to_bytes()).reverse());

    let mut rng = ChaCha12Rng::from_seed(self.transcript.rng_seed(b"pseudo_out_masks"));
    let mut sum_pseudo_outs = Scalar::zero();
    while sorted.len() != 0 {
      let value = sorted.remove(0);

      let mut mask = random_scalar(&mut rng);
      if sorted.len() == 0 {
        mask = self.output_masks.unwrap() - sum_pseudo_outs;
      } else {
        sum_pseudo_outs += mask;
      }

      tx.prefix.inputs.push(
        Input::ToKey {
          amount: 0,
          key_offsets: value.1.offsets.clone(),
          key_image: value.2
        }
      );

      *value.3.write().unwrap() = Some(
        ClsagDetails::new(
          ClsagInput::new(
            value.0.commitment,
            value.1
          ).map_err(|_| panic!("Signing an input which isn't present in the ring we created for it"))?,
          mask
        )
      );

      self.clsags.push(value.4);
      commitments.push(value.5);
    }

    let msg = tx.signature_hash();
    self.tx = Some(tx);

    // Iterate over each CLSAG calling sign
    let mut serialized = Vec::with_capacity(self.clsags.len() * 32);
    for clsag in self.clsags.iter_mut() {
      serialized.extend(&clsag.sign(commitments.remove(0), &msg)?);
    }

    Ok(serialized)
  }

  fn complete(&mut self, shares: HashMap<u16, Vec<u8>>) -> Result<Transaction, FrostError> {
    if self.state() != State::Signed {
      Err(FrostError::InvalidSignTransition(State::Signed, self.state()))?;
    }

    let mut tx = self.tx.take().unwrap();
    match tx.rct_signatures.prunable {
      RctPrunable::Null => panic!("Signing for RctPrunable::Null"),
      RctPrunable::Clsag { ref mut clsags, ref mut pseudo_outs, .. } => {
        for (c, clsag) in self.clsags.iter_mut().enumerate() {
          let (clsag, pseudo_out) = clsag.complete(shares.iter().map(
            |(l, shares)| (*l, shares[(c * 32) .. ((c + 1) * 32)].to_vec())
          ).collect::<HashMap<_, _>>())?;
          clsags.push(clsag);
          pseudo_outs.push(pseudo_out);
        }
      }
    }
    Ok(tx)
  }

  fn multisig_params(&self) -> MultisigParams {
    self.clsags[0].multisig_params()
  }

  fn state(&self) -> State {
    self.clsags[0].state()
  }
}
