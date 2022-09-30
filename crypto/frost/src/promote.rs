use std::{
  marker::PhantomData,
  io::{self, Read, Write},
  sync::Arc,
  collections::HashMap,
};

use rand_core::{RngCore, CryptoRng};

use group::GroupEncoding;

use transcript::{Transcript, RecommendedTranscript};
use dleq::DLEqProof;

use crate::{
  curve::{CurveError, Curve},
  FrostError, FrostCore, FrostKeys, validate_map,
};

/// Promote a set of keys to another Curve definition.
pub trait CurvePromote<C2: Curve> {
  #[doc(hidden)]
  #[allow(non_snake_case)]
  fn _bound_C2(_c2: C2) {
    panic!()
  }

  fn promote(self) -> FrostKeys<C2>;
}

// Implement promotion to different ciphersuites, panicking if the generators are different
// Commented due to lack of practical benefit. While it'd have interoperability benefits, those
// would have their own DKG process which isn't compatible anyways. This becomes unsafe code
// that'll never be used but we're bound to support
/*
impl<C1: Curve, C2: Curve> CurvePromote<C2> for FrostKeys<C1>
where
  C2: Curve<F = C1::F, G = C1::G>,
{
  fn promote(self) -> FrostKeys<C2> {
    assert_eq!(C::GENERATOR, C2::GENERATOR);

    FrostKeys {
      core: Arc::new(FrostCore {
        params: self.core.params,
        secret_share: self.core.secret_share,
        group_key: self.core.group_key,
        verification_shares: self.core.verification_shares(),
      }),
      offset: None,
    }
  }
}
*/

fn transcript<G: GroupEncoding>(key: G, i: u16) -> RecommendedTranscript {
  let mut transcript = RecommendedTranscript::new(b"FROST Generator Update");
  transcript.append_message(b"group_key", key.to_bytes().as_ref());
  transcript.append_message(b"participant", &i.to_be_bytes());
  transcript
}

/// Proof of valid promotion to another generator.
#[derive(Clone, Copy)]
pub struct GeneratorProof<C: Curve> {
  share: C::G,
  proof: DLEqProof<C::G>,
}

impl<C: Curve> GeneratorProof<C> {
  pub fn serialize<W: Write>(&self, writer: &mut W) -> io::Result<()> {
    writer.write_all(self.share.to_bytes().as_ref())?;
    self.proof.serialize(writer)
  }

  pub fn deserialize<R: Read>(reader: &mut R) -> Result<GeneratorProof<C>, CurveError> {
    Ok(GeneratorProof {
      share: C::read_G(reader)?,
      proof: DLEqProof::deserialize(reader).map_err(|_| CurveError::InvalidScalar)?,
    })
  }
}

/// Promote a set of keys from one curve to another, where the elliptic curve is the same.
/// Since the Curve trait additionally specifies a generator, this provides an O(n) way to update
/// the generator used with keys. The key generation protocol itself is exponential.
pub struct GeneratorPromotion<C1: Curve, C2: Curve> {
  base: FrostKeys<C1>,
  proof: GeneratorProof<C1>,
  _c2: PhantomData<C2>,
}

impl<C1: Curve, C2: Curve> GeneratorPromotion<C1, C2>
where
  C2: Curve<F = C1::F, G = C1::G>,
{
  /// Begin promoting keys from one curve to another. Returns a proof this share was properly
  /// promoted.
  pub fn promote<R: RngCore + CryptoRng>(
    rng: &mut R,
    base: FrostKeys<C1>,
  ) -> (GeneratorPromotion<C1, C2>, GeneratorProof<C1>) {
    // Do a DLEqProof for the new generator
    let proof = GeneratorProof {
      share: C2::generator() * base.secret_share(),
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
  ) -> Result<FrostKeys<C2>, FrostError> {
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
        .map_err(|_| FrostError::InvalidProofOfKnowledge(i))?;
      verification_shares.insert(i, proof.share);
    }

    Ok(FrostKeys {
      core: Arc::new(FrostCore::new(params, self.base.secret_share(), verification_shares)),
      offset: None,
    })
  }
}
