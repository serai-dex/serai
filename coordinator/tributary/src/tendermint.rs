use core::ops::Deref;

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

use transcript::{Transcript, RecommendedTranscript};

use ciphersuite::{
  group::{
    GroupEncoding,
    ff::{Field, PrimeField},
  },
  Ciphersuite, Ristretto,
};
use schnorr::SchnorrSignature;

use tendermint::ext::{Signer as SignerTrait, SignatureScheme as SignatureSchemeTrait};

fn challenge(
  genesis: [u8; 32],
  key: [u8; 32],
  nonce: &[u8],
  msg: &[u8],
) -> <Ristretto as Ciphersuite>::F {
  let mut transcript = RecommendedTranscript::new(b"Tributary Chain Tendermint Message");
  transcript.append_message(b"genesis", genesis);
  transcript.append_message(b"key", key);
  transcript.append_message(b"nonce", nonce);
  transcript.append_message(b"message", msg);

  <Ristretto as Ciphersuite>::F::from_bytes_mod_order_wide(&transcript.challenge(b"schnorr").into())
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct Signer {
  genesis: [u8; 32],
  key: Zeroizing<<Ristretto as Ciphersuite>::F>,
}

#[async_trait::async_trait]
impl SignerTrait for Signer {
  type ValidatorId = [u8; 32];
  type Signature = [u8; 64];

  /// Returns the validator's current ID. Returns None if they aren't a current validator.
  async fn validator_id(&self) -> Option<Self::ValidatorId> {
    Some((Ristretto::generator() * self.key.deref()).to_bytes())
  }

  /// Sign a signature with the current validator's private key.
  async fn sign(&self, msg: &[u8]) -> Self::Signature {
    let mut nonce = Zeroizing::new(RecommendedTranscript::new(b"Tributary Chain Tendermint Nonce"));
    nonce.append_message(b"genesis", self.genesis);
    nonce.append_message(b"key", Zeroizing::new(self.key.deref().to_repr()).as_ref());
    nonce.append_message(b"message", msg);
    let mut nonce = nonce.challenge(b"nonce");

    let mut nonce_arr = [0; 64];
    nonce_arr.copy_from_slice(nonce.as_ref());

    let nonce_ref: &mut [u8] = nonce.as_mut();
    nonce_ref.zeroize();
    let nonce_ref: &[u8] = nonce.as_ref();
    assert_eq!(nonce_ref, [0; 64].as_ref());

    let nonce =
      Zeroizing::new(<Ristretto as Ciphersuite>::F::from_bytes_mod_order_wide(&nonce_arr));
    nonce_arr.zeroize();

    assert!(!bool::from(nonce.ct_eq(&<Ristretto as Ciphersuite>::F::ZERO)));

    let challenge = challenge(
      self.genesis,
      (Ristretto::generator() * self.key.deref()).to_bytes(),
      (Ristretto::generator() * nonce.deref()).to_bytes().as_ref(),
      msg,
    );

    let sig = SchnorrSignature::<Ristretto>::sign(&self.key, nonce, challenge).serialize();

    let mut res = [0; 64];
    res.copy_from_slice(&sig);
    res
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
struct SignatureScheme {
  genesis: [u8; 32],
}

impl SignatureSchemeTrait for SignatureScheme {
  type ValidatorId = [u8; 32];
  type Signature = [u8; 64];
  // TODO: Use half-aggregation.
  type AggregateSignature = Vec<[u8; 64]>;
  type Signer = Signer;

  #[must_use]
  fn verify(&self, validator: Self::ValidatorId, msg: &[u8], sig: &Self::Signature) -> bool {
    let Ok(validator_point) = Ristretto::read_G::<&[u8]>(&mut validator.as_ref()) else {
      return false;
    };
    let Ok(actual_sig) = SchnorrSignature::<Ristretto>::read::<&[u8]>(&mut sig.as_ref()) else {
      return false;
    };
    actual_sig.verify(validator_point, challenge(self.genesis, validator, &sig[.. 32], msg))
  }

  fn aggregate(sigs: &[Self::Signature]) -> Self::AggregateSignature {
    sigs.to_vec()
  }

  #[must_use]
  fn verify_aggregate(
    &self,
    signers: &[Self::ValidatorId],
    msg: &[u8],
    sig: &Self::AggregateSignature,
  ) -> bool {
    for (signer, sig) in signers.iter().zip(sig.iter()) {
      if !self.verify(*signer, msg, sig) {
        return false;
      }
    }
    true
  }
}
