use core::{marker::PhantomData, ops::Deref};
use std::{
  io::{self, Read, Write},
  sync::Arc,
  collections::HashMap,
};

use rand_core::{RngCore, CryptoRng};

use group::GroupEncoding;

use ciphersuite::Ciphersuite;

use transcript::{Transcript, RecommendedTranscript};
use dleq::DLEqProof;

use crate::{DkgError, ThresholdCore, ThresholdKeys, validate_map};

/// Promote a set of keys to another Ciphersuite definition.
pub trait CiphersuitePromote<C2: Ciphersuite> {
  #[doc(hidden)]
  #[allow(non_snake_case)]
  fn _bound_C2(_c2: C2) {
    panic!()
  }

  fn promote(self) -> ThresholdKeys<C2>;
}

fn transcript<G: GroupEncoding>(key: G, i: u16) -> RecommendedTranscript {
  let mut transcript = RecommendedTranscript::new(b"DKG Generator Promotion v0.2");
  transcript.append_message(b"group_key", key.to_bytes());
  transcript.append_message(b"participant", i.to_be_bytes());
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
    self.proof.serialize(writer)
  }

  pub fn read<R: Read>(reader: &mut R) -> io::Result<GeneratorProof<C>> {
    Ok(GeneratorProof {
      share: <C as Ciphersuite>::read_G(reader)?,
      proof: DLEqProof::deserialize(reader)?,
    })
  }

  pub fn serialize(&self) -> Vec<u8> {
    let mut buf = vec![];
    self.write(&mut buf).unwrap();
    buf
  }
}

/// Promote a set of keys from one curve to another, where the elliptic curve is the same.
/// Since the Ciphersuite trait additionally specifies a generator, this provides an O(n) way to
/// update the generator used with keys. The key generation protocol itself is exponential.
pub struct GeneratorPromotion<C1: Ciphersuite, C2: Ciphersuite> {
  base: ThresholdKeys<C1>,
  proof: GeneratorProof<C1>,
  _c2: PhantomData<C2>,
}

impl<C1: Ciphersuite, C2: Ciphersuite> GeneratorPromotion<C1, C2>
where
  C2: Ciphersuite<F = C1::F, G = C1::G>,
{
  /// Begin promoting keys from one curve to another. Returns a proof this share was properly
  /// promoted.
  pub fn promote<R: RngCore + CryptoRng>(
    rng: &mut R,
    base: ThresholdKeys<C1>,
  ) -> (GeneratorPromotion<C1, C2>, GeneratorProof<C1>) {
    // Do a DLEqProof for the new generator
    let proof = GeneratorProof {
      share: C2::generator() * base.secret_share().deref(),
      proof: DLEqProof::prove(
        rng,
        &mut transcript(base.core.group_key(), base.params().i),
        &[C1::generator(), C2::generator()],
        base.secret_share(),
      ),
    };

    (GeneratorPromotion { base, proof, _c2: PhantomData::<C2> }, proof)
  }

  /// Complete promotion by taking in the proofs from all other participants.
  pub fn complete(
    self,
    proofs: &HashMap<u16, GeneratorProof<C1>>,
  ) -> Result<ThresholdKeys<C2>, DkgError> {
    let params = self.base.params();
    validate_map(proofs, &(1 ..= params.n).collect::<Vec<_>>(), params.i)?;

    let original_shares = self.base.verification_shares();

    let mut verification_shares = HashMap::new();
    verification_shares.insert(params.i, self.proof.share);
    for (i, proof) in proofs {
      let i = *i;
      proof
        .proof
        .verify(
          &mut transcript(self.base.core.group_key(), i),
          &[C1::generator(), C2::generator()],
          &[original_shares[&i], proof.share],
        )
        .map_err(|_| DkgError::InvalidProofOfKnowledge(i))?;
      verification_shares.insert(i, proof.share);
    }

    Ok(ThresholdKeys {
      core: Arc::new(ThresholdCore::new(
        params,
        self.base.secret_share().clone(),
        verification_shares,
      )),
      offset: None,
    })
  }
}
