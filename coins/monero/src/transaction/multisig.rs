use std::{rc::Rc, cell::RefCell};

use rand_core::{RngCore, CryptoRng};

use curve25519_dalek::{scalar::Scalar, edwards::{EdwardsPoint, CompressedEdwardsY}};

use monero::{
  Hash, VarInt,
  consensus::deserialize,
  util::ringct::Key,
  blockdata::transaction::{KeyImage, TxIn, Transaction}
};

use transcript::Transcript as TranscriptTrait;
use frost::{FrostError, MultisigKeys, MultisigParams, sign::{State, StateMachine, AlgorithmMachine}};

use crate::{
  Transcript,
  frost::Ed25519,
  key_image,
  clsag,
  rpc::Rpc,
  transaction::{TransactionError, Preparation, SignableTransaction, mixins}
};

pub struct TransactionMachine {
  leader: bool,
  signable: SignableTransaction,
  our_images: Vec<EdwardsPoint>,
  inputs: Vec<TxIn>,
  tx: Option<Transaction>,
  mask_sum: Rc<RefCell<Scalar>>,
  msg: Rc<RefCell<[u8; 32]>>,
  clsags: Vec<AlgorithmMachine<Ed25519, clsag::Multisig>>
}

impl SignableTransaction {
  pub async fn multisig<R: RngCore + CryptoRng>(
    self,
    rng: &mut R,
    rpc: &Rpc,
    keys: Rc<MultisigKeys<Ed25519>>,
    included: &[usize]
  ) -> Result<TransactionMachine, TransactionError> {
    let mut our_images = vec![];
    let mut inputs = vec![];
    let mask_sum = Rc::new(RefCell::new(Scalar::zero()));
    let msg = Rc::new(RefCell::new([0; 32]));
    let mut clsags = vec![];
    for input in &self.inputs {
      // Select mixins
      let (m, mixins) = mixins::select(
        rpc.get_o_indexes(input.tx).await.map_err(|e| TransactionError::RpcError(e))?[input.o]
      );

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
              rpc.get_ring(&mixins).await.map_err(|e| TransactionError::RpcError(e))?,
              m,
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
        key_offsets: mixins::offset(&mixins).iter().map(|x| VarInt(*x)).collect(),
        k_image: KeyImage { image: Hash([0; 32]) }
      });
    }

    // Verify these outputs by a dummy prep
    self.prepare_outputs(&mut Preparation::Leader(rng))?;

    Ok(TransactionMachine {
      leader: keys.params().i() == included[0],
      signable: self,
      our_images,
      inputs,
      tx: None,
      mask_sum,
      msg,
      clsags
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
    let mut serialized = vec![];
    for clsag in self.clsags.iter_mut() {
      serialized.extend(&clsag.preprocess(rng)?);
    }

    if self.leader {
      let (prep, mask_sum, tx) = self.signable.prepare_outputs(&mut Preparation::Leader(rng)).unwrap();
      self.mask_sum.replace(mask_sum);
      self.tx = Some(tx);

      serialized.extend(&prep);
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

        // Handle the prep with a seeded RNG type to make rustc happy
        let (_, mask_sum, tx_inner) = self.signable.prepare_outputs::<<Transcript as TranscriptTrait>::SeededRng>(
          &mut Preparation::Follower(
            prep[clsag_lens .. (clsag_lens + 32)].try_into().map_err(|_| FrostError::InvalidCommitment(l))?,
            deserialize(&prep[(clsag_lens + 32) .. prep.len()]).map_err(|_| FrostError::InvalidCommitment(l))?
          )
        ).map_err(|_| FrostError::InvalidShare(l))?; // Not invalid outputs due to doing a dummy prep as leader
        self.mask_sum.replace(mask_sum);
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
