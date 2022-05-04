use std::{rc::Rc, cell::RefCell};

use rand_core::{RngCore, CryptoRng};

use curve25519_dalek::{scalar::Scalar, edwards::{EdwardsPoint, CompressedEdwardsY}};

use monero::{
  Hash, VarInt,
  consensus::{Encodable, deserialize},
  util::ringct::Key,
  blockdata::transaction::{KeyImage, TxIn, Transaction}
};

use transcript::Transcript as TranscriptTrait;
use frost::{FrostError, MultisigKeys, MultisigParams, sign::{State, StateMachine, AlgorithmMachine}};

use crate::{
  frost::{Transcript, Ed25519},
  key_image, bulletproofs, clsag,
  rpc::Rpc,
  transaction::{TransactionError, SignableTransaction, mixins}
};

pub struct TransactionMachine {
  leader: bool,
  signable: SignableTransaction,
  our_images: Vec<EdwardsPoint>,
  mask_sum: Rc<RefCell<Scalar>>,
  msg: Rc<RefCell<[u8; 32]>>,
  clsags: Vec<AlgorithmMachine<Ed25519, clsag::Multisig>>,
  inputs: Vec<TxIn>,
  tx: Option<Transaction>,
}

impl SignableTransaction {
  pub async fn multisig<R: RngCore + CryptoRng>(
    mut self,
    rng: &mut R,
    rpc: &Rpc,
    keys: Rc<MultisigKeys<Ed25519>>,
    included: &[usize]
  ) -> Result<TransactionMachine, TransactionError> {
    let mut our_images = vec![];

    let mask_sum = Rc::new(RefCell::new(Scalar::zero()));
    let msg = Rc::new(RefCell::new([0; 32]));
    let mut clsags = vec![];

    let mut inputs = vec![];

    // Create a RNG out of the input shared keys, which either requires the view key or being every
    // sender, and the payments (address and amount), which a passive adversary may be able to know
    // The use of input shared keys technically makes this one time given a competent wallet which
    // can withstand the burning attack
    // The lack of dedicated entropy here is frustrating. We can probably provide entropy inclusion
    // if we move CLSAG ring to a Rc RefCell like msg and mask? TODO
    let mut transcript = Transcript::new(b"InputMixins");
    let mut shared_keys = Vec::with_capacity(self.inputs.len() * 32);
    for input in &self.inputs {
      shared_keys.extend(&input.key_offset.to_bytes());
    }
    transcript.append_message(b"input_shared_keys", &shared_keys);
    let mut payments = Vec::with_capacity(self.payments.len() * ((2 * 32) + 8));
    for payment in &self.payments {
      // Network byte and spend/view key
      // Doesn't use the full address as monero-rs may provide a payment ID which adds bytes
      // By simply cutting this short, we get the relevant data without length differences nor the
      // need to prefix
      payments.extend(&payment.0.as_bytes()[0 .. 65]);
      payments.extend(payment.1.to_le_bytes());
    }
    transcript.append_message(b"payments", &payments);

    // Select mixins
    let mixins = mixins::select(
      &mut transcript.seeded_rng(b"mixins", None),
      rpc,
      rpc.get_height().await.map_err(|e| TransactionError::RpcError(e))?,
      &self.inputs
    ).await.map_err(|e| TransactionError::RpcError(e))?;

    for (i, input) in self.inputs.iter().enumerate() {
      let keys = keys.offset(dalek_ff_group::Scalar(input.key_offset));
      let (image, _) = key_image::generate_share(
        rng,
        &keys.view(included).map_err(|e| TransactionError::FrostError(e))?
      );
      our_images.push(image);

      clsags.push(
        AlgorithmMachine::new(
          clsag::Multisig::new(
            clsag::Input::new(
              mixins[i].2.clone(),
              mixins[i].1,
              input.commitment
            ).map_err(|e| TransactionError::ClsagError(e))?,
            msg.clone(),
            mask_sum.clone()
          ).map_err(|e| TransactionError::MultisigError(e))?,
          Rc::new(keys),
          included
        ).map_err(|e| TransactionError::FrostError(e))?
      );

      inputs.push(TxIn::ToKey {
        amount: VarInt(0),
        key_offsets: mixins[i].0.clone(),
        k_image: KeyImage { image: Hash([0; 32]) }
      });
    }

    // Verify these outputs by a dummy prep
    self.prepare_outputs(rng)?;

    Ok(TransactionMachine {
      leader: keys.params().i() == included[0],
      signable: self,
      our_images,
      mask_sum,
      msg,
      clsags,
      inputs,
      tx: None
    })
  }
}

// Seeded RNG so multisig participants agree on one time keys to use, preventing burning attacks
fn outputs_rng(tx: &SignableTransaction, entropy: [u8; 32]) -> <Transcript as TranscriptTrait>::SeededRng {
  let mut transcript = Transcript::new(b"StealthAddress");
  // This output can only be spent once. Therefore, it forces all one time keys used here to be
  // unique, even if the entropy is reused. While another transaction could use a different input
  // ordering to swap which 0 is, that input set can't contain this input without being a double
  // spend
  transcript.append_message(b"hash", &tx.inputs[0].tx.0);
  transcript.append_message(b"index", &u64::try_from(tx.inputs[0].o).unwrap().to_le_bytes());
  transcript.seeded_rng(b"tx_keys", Some(entropy))
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
    let mut serialized = vec![];
    for clsag in self.clsags.iter_mut() {
      serialized.extend(&clsag.preprocess(rng)?);
    }

    if self.leader {
      let mut entropy = [0; 32];
      rng.fill_bytes(&mut entropy);
      serialized.extend(&entropy);

      let mut rng = outputs_rng(&self.signable, entropy);
      // Safe to unwrap thanks to the dummy prepare
      let (commitments, mask_sum) = self.signable.prepare_outputs(&mut rng).unwrap();
      self.mask_sum.replace(mask_sum);

      let bp = bulletproofs::generate(&commitments).unwrap();
      bp.consensus_encode(&mut serialized).unwrap();

      let tx = self.signable.prepare_transaction(&commitments, bp);
      self.tx = Some(tx);
    }

    Ok(serialized)
  }

  fn sign(
    &mut self,
    commitments: &[Option<Vec<u8>>],
    _: &[u8]
  ) -> Result<Vec<u8>, FrostError> {
    if self.state() != State::Preprocessed {
      Err(FrostError::InvalidSignTransition(State::Preprocessed, self.state()))?;
    }

    // FROST commitments, image, commitments, and their proofs
    let clsag_len = 64 + clsag::Multisig::serialized_len();
    let clsag_lens = clsag_len * self.clsags.len();

    // Split out the prep and update the TX
    let mut tx = None;
    if self.leader {
      tx = self.tx.take();
    } else {
      for (l, prep) in commitments.iter().enumerate() {
        if prep.is_none() {
          continue;
        }
        let prep = prep.as_ref().unwrap();

        let mut rng = outputs_rng(
          &self.signable,
          prep[clsag_lens .. (clsag_lens + 32)].try_into().map_err(|_| FrostError::InvalidShare(l))?
        );
        // Not invalid outputs due to doing a dummy prep as leader
        let (commitments, mask_sum) = self.signable.prepare_outputs(&mut rng).map_err(|_| FrostError::InvalidShare(l))?;
        self.mask_sum.replace(mask_sum);

        // Verify the provided bulletproofs if not leader
        let bp = deserialize(&prep[(clsag_lens + 32) .. prep.len()]).map_err(|_| FrostError::InvalidShare(l))?;
        if !bulletproofs::verify(&bp, &commitments.iter().map(|c| c.calculate()).collect::<Vec<EdwardsPoint>>()) {
          Err(FrostError::InvalidShare(l))?;
        }

        let tx_inner = self.signable.prepare_transaction(&commitments, bp);
        tx = Some(tx_inner);
        break;
      }
    }

    // Calculate the key images and update the TX
    // Multisig will parse/calculate/validate this as needed, yet doing so here as well provides
    // the easiest API overall
    for c in 0 .. self.clsags.len() {
      let mut image = self.our_images[c];
      for (l, serialized) in commitments.iter().enumerate() {
        if serialized.is_none() {
          continue;
        }

        image += CompressedEdwardsY(
          serialized.as_ref().unwrap()[((c * clsag_len) + 64) .. ((c * clsag_len) + 96)]
            .try_into().map_err(|_| FrostError::InvalidCommitment(l))?
        ).decompress().ok_or(FrostError::InvalidCommitment(l))?;
      }

      self.inputs[c] = match self.inputs[c].clone() {
        TxIn::ToKey { amount, key_offsets, k_image: _ } => TxIn::ToKey {
          amount, key_offsets,
          k_image: KeyImage { image: Hash(image.compress().to_bytes()) }
        },
        _ => panic!("Signing for an input which isn't ToKey")
      };
    }

    // TODO sort inputs

    let mut tx = tx.unwrap();
    tx.prefix.inputs = self.inputs.clone();
    self.msg.replace(tx.signature_hash().unwrap().0);
    self.tx = Some(tx);

    // Iterate over each CLSAG calling sign
    let mut serialized = Vec::with_capacity(self.clsags.len() * 32);
    for (c, clsag) in self.clsags.iter_mut().enumerate() {
      serialized.extend(&clsag.sign(
        &commitments.iter().map(
          |commitments| commitments.clone().map(
            |commitments| commitments[(c * clsag_len) .. ((c * clsag_len) + clsag_len)].to_vec()
          )
        ).collect::<Vec<_>>(),
        &vec![]
      )?);
    }

    Ok(serialized)
  }

  fn complete(&mut self, shares: &[Option<Vec<u8>>]) -> Result<Transaction, FrostError> {
    if self.state() != State::Signed {
      Err(FrostError::InvalidSignTransition(State::Signed, self.state()))?;
    }

    let mut tx = self.tx.take().unwrap();
    let mut prunable = tx.rct_signatures.p.unwrap();
    for (c, clsag) in self.clsags.iter_mut().enumerate() {
      let (clsag, pseudo_out) = clsag.complete(&shares.iter().map(
        |share| share.clone().map(|share| share[(c * 32) .. ((c * 32) + 32)].to_vec())
      ).collect::<Vec<_>>())?;
      prunable.Clsags.push(clsag);
      prunable.pseudo_outs.push(Key { key: pseudo_out.compress().to_bytes() });
    }
    tx.rct_signatures.p = Some(prunable);

    Ok(tx)
  }

  fn multisig_params(&self) -> MultisigParams {
    self.clsags[0].multisig_params()
  }

  fn state(&self) -> State {
    self.clsags[0].state()
  }
}
