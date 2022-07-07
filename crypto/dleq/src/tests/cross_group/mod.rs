use hex_literal::hex;
use rand_core::{RngCore, OsRng};

use ff::{Field, PrimeField};
use group::{Group, GroupEncoding};

use blake2::{Digest, Blake2b512};

use k256::{Scalar, ProjectivePoint};
use dalek_ff_group::{self as dfg, EdwardsPoint, CompressedEdwardsY};

use transcript::RecommendedTranscript;

use crate::{
  Generators,
  cross_group::{
    scalar::mutual_scalar_from_bytes,
    ClassicLinearDLEq, EfficientLinearDLEq, ConciseLinearDLEq, CompromiseLinearDLEq
  }
};

mod scalar;
mod schnorr;
mod aos;

type G0 = ProjectivePoint;
type G1 = EdwardsPoint;

pub(crate) fn transcript() -> RecommendedTranscript {
  RecommendedTranscript::new(b"Cross-Group DLEq Proof Test")
}

pub(crate) fn generators() -> (Generators<G0>, Generators<G1>) {
  (
    Generators::new(
      ProjectivePoint::GENERATOR,
      ProjectivePoint::from_bytes(
        &(hex!("0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0").into())
      ).unwrap()
    ),

    Generators::new(
      EdwardsPoint::generator(),
      CompressedEdwardsY::new(
        hex!("8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94")
      ).decompress().unwrap()
    )
  )
}

macro_rules! verify_and_deserialize {
  ($type: ident, $proof: ident, $generators: ident, $keys: ident) => {
    let public_keys = $proof.verify(&mut OsRng, &mut transcript(), $generators).unwrap();
    assert_eq!($generators.0.primary * $keys.0, public_keys.0);
    assert_eq!($generators.1.primary * $keys.1, public_keys.1);

    #[cfg(feature = "serialize")]
    {
      let mut buf = vec![];
      $proof.serialize(&mut buf).unwrap();
      let deserialized = $type::<G0, G1>::deserialize(&mut std::io::Cursor::new(&buf)).unwrap();
      assert_eq!(proof, deserialized);
    }
  }
}

macro_rules! test_dleq {
  ($str: expr, $benchmark: ident, $name: ident, $type: ident) => {
    #[ignore]
    #[test]
    fn $benchmark() {
      println!("Benchmarking with Secp256k1/Ed25519");
      let generators = generators();

      let mut seed = [0; 32];
      OsRng.fill_bytes(&mut seed);
      let key = Blake2b512::new().chain_update(seed);

      let runs = 200;
      let mut proofs = Vec::with_capacity(usize::try_from(runs).unwrap());
      let time = std::time::Instant::now();
      for _ in 0 .. runs {
        proofs.push($type::prove(&mut OsRng, &mut transcript(), generators, key.clone()).0);
      }
      println!("{} had a average prove time of {}ms", $str, time.elapsed().as_millis() / runs);

      let time = std::time::Instant::now();
      for proof in &proofs {
        proof.verify(&mut OsRng, &mut transcript(), generators).unwrap();
      }
      println!("{} had a average verify time of {}ms", $str, time.elapsed().as_millis() / runs);

      #[cfg(feature = "serialize")]
      {
        let mut buf = vec![];
        proofs[0].serialize(&mut buf);
        println!("{} had a proof size of {} bytes", $str, buf.len());
      }
    }

    #[test]
    fn $name() {
      let generators = generators();

      for i in 0 .. 1 {
        let (proof, keys) = if i == 0 {
          let mut seed = [0; 32];
          OsRng.fill_bytes(&mut seed);

          $type::prove(
            &mut OsRng,
            &mut transcript(),
            generators,
            Blake2b512::new().chain_update(seed)
          )
        } else {
          let mut key;
          let mut res;
          while {
            key = Scalar::random(&mut OsRng);
            res = $type::prove_without_bias(&mut OsRng, &mut transcript(), generators, key);
            res.is_none()
          } {}
          let res = res.unwrap();
          assert_eq!(key, res.1.0);
          res
        };

        verify_and_deserialize!($type, proof, generators, keys);
      }
    }
  }
}

test_dleq!("ClassicLinear", benchmark_classic_linear, test_classic_linear, ClassicLinearDLEq);
test_dleq!("ConciseLinear", benchmark_concise_linear, test_concise_linear, ConciseLinearDLEq);
test_dleq!(
  "EfficientLinear",
  benchmark_efficient_linear,
  test_efficient_linear,
  EfficientLinearDLEq
);
test_dleq!(
  "CompromiseLinear",
  benchmark_compromise_linear,
  test_compromise_linear,
  CompromiseLinearDLEq
);

#[test]
fn test_rejection_sampling() {
  let mut pow_2 = Scalar::one();
  for _ in 0 .. dfg::Scalar::CAPACITY {
    pow_2 = pow_2.double();
  }

  assert!(
    // Either would work
    EfficientLinearDLEq::prove_without_bias(
      &mut OsRng,
      &mut RecommendedTranscript::new(b""),
      generators(),
      pow_2
    ).is_none()
  );
}

#[test]
fn test_remainder() {
  // Uses Secp256k1 for both to achieve an odd capacity of 255
  assert_eq!(Scalar::CAPACITY, 255);
  let generators = (generators().0, generators().0);
  // This will ignore any unused bits, ensuring every remaining one is set
  let keys = mutual_scalar_from_bytes(&[0xFF; 32]);
  assert_eq!(keys.0 + Scalar::one(), Scalar::from(2u64).pow_vartime(&[255]));
  assert_eq!(keys.0, keys.1);

  let (proof, res) = ConciseLinearDLEq::prove_without_bias(
    &mut OsRng,
    &mut transcript(),
    generators,
    keys.0
  ).unwrap();
  assert_eq!(keys, res);

  verify_and_deserialize!(ConciseLinearDLEq, proof, generators, keys);
}
