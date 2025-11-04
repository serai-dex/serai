#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
// This crate requires `dleq` which doesn't support no-std via std-shims
// #![cfg_attr(not(feature = "std"), no_std)]

use core::{marker::PhantomData, ops::Deref};
use std::{
  io::{self, Read, Write},
  collections::HashMap,
};

use rand_core::{RngCore, CryptoRng};

use ciphersuite::{group::GroupEncoding, Ciphersuite};

use transcript::{Transcript, RecommendedTranscript};
use dleq::DLEqProof;

pub use dkg::*;

#[cfg(test)]
mod tests;

/// Errors encountered when promoting keys.
#[derive(Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum PromotionError {
  /// Invalid participant identifier.
  #[error("invalid participant (1 <= participant <= {n}, yet participant is {participant})")]
  InvalidParticipant {
    /// The total amount of participants.
    n: u16,
    /// The specified participant.
    participant: Participant,
  },

  /// An incorrect amount of participants was specified.
  #[error("incorrect amount of participants. {t} <= amount <= {n}, yet amount is {amount}")]
  IncorrectAmountOfParticipants {
    /// The threshold required.
    t: u16,
    /// The total amount of participants.
    n: u16,
    /// The amount of participants specified.
    amount: usize,
  },

  /// Participant provided an invalid proof.
  #[error("invalid proof {0}")]
  InvalidProof(Participant),
}

fn transcript<G: GroupEncoding>(key: &G, i: Participant) -> RecommendedTranscript {
  let mut transcript = RecommendedTranscript::new(b"DKG Generator Promotion v0.2");
  transcript.append_message(b"group_key", key.to_bytes());
  transcript.append_message(b"participant", i.to_bytes());
  transcript
}

/// Proof of valid promotion to another generator.
#[derive(Clone, Copy)]
pub struct GeneratorProof<C: Ciphersuite> {
  share: C::G,
  proof: DLEqProof<C::G>,
}

impl<C: Ciphersuite> GeneratorProof<C> {
  pub fn write<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(self.share.to_bytes().as_ref())?;
    self.proof.write(writer)
  }

  pub fn read<R: Read>(reader: &mut R) -> io::Result<GeneratorProof<C>> {
    Ok(GeneratorProof {
      share: <C as Ciphersuite>::read_G(reader)?,
      proof: DLEqProof::read(reader)?,
    })
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut buf = vec![];
    self.write(&mut buf).unwrap();
    buf
  }
}

/// Promote a set of keys from one generator to another, where the elliptic curve is the same.
///
/// Since the Ciphersuite trait additionally specifies a generator, this provides an O(n) way to
/// update the generator used with keys. This outperforms the key generation protocol which is
/// exponential.
pub struct GeneratorPromotion<C1: Ciphersuite, C2: Ciphersuite> {
  base: ThresholdKeys<C1>,
  proof: GeneratorProof<C1>,
  _c2: PhantomData<C2>,
}

impl<C1: Ciphersuite, C2: Ciphersuite<F = C1::F, G = C1::G>> GeneratorPromotion<C1, C2> {
  /// Begin promoting keys from one generator to another.
  ///
  /// Returns a proof this share was properly promoted.
  pub fn promote<R: RngCore + CryptoRng>(
    rng: &mut R,
    base: ThresholdKeys<C1>,
  ) -> (GeneratorPromotion<C1, C2>, GeneratorProof<C1>) {
    // Do a DLEqProof for the new generator
    let proof = GeneratorProof {
      share: C2::generator() * base.original_secret_share().deref(),
      proof: DLEqProof::prove(
        rng,
        &mut transcript(&base.original_group_key(), base.params().i()),
        &[C1::generator(), C2::generator()],
        base.original_secret_share(),
      ),
    };

    (GeneratorPromotion { base, proof, _c2: PhantomData::<C2> }, proof)
  }

  /// Complete promotion by taking in the proofs from all other participants.
  pub fn complete(
    self,
    proofs: &HashMap<Participant, GeneratorProof<C1>>,
  ) -> Result<ThresholdKeys<C2>, PromotionError> {
    let params = self.base.params();
    if proofs.len() != (usize::from(params.n()) - 1) {
      Err(PromotionError::IncorrectAmountOfParticipants {
        t: params.n(),
        n: params.n(),
        amount: proofs.len() + 1,
      })?;
    }
    for i in proofs.keys().copied() {
      if u16::from(i) > params.n() {
        Err(PromotionError::InvalidParticipant { n: params.n(), participant: i })?;
      }
    }

    let mut verification_shares = HashMap::new();
    verification_shares.insert(params.i(), self.proof.share);
    for i in 1 ..= params.n() {
      let i = Participant::new(i).unwrap();
      if i == params.i() {
        continue;
      }

      let proof = proofs.get(&i).unwrap();
      proof
        .proof
        .verify(
          &mut transcript(&self.base.original_group_key(), i),
          &[C1::generator(), C2::generator()],
          &[self.base.original_verification_share(i), proof.share],
        )
        .map_err(|_| PromotionError::InvalidProof(i))?;
      verification_shares.insert(i, proof.share);
    }

    Ok(
      ThresholdKeys::new(
        params,
        self.base.interpolation().clone(),
        self.base.original_secret_share().clone(),
        verification_shares,
      )
      .unwrap(),
    )
  }
}
