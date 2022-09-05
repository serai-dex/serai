use hex_literal::hex;
use rand::rngs::OsRng;

use curve25519_dalek::{scalar::Scalar, edwards::CompressedEdwardsY};
use multiexp::BatchVerifier;

use crate::{
  Commitment, random_scalar,
  ringct::bulletproofs::{Bulletproofs, original::OriginalStruct},
};

#[test]
fn bulletproofs_vector() {
  let scalar = |scalar| Scalar::from_canonical_bytes(scalar).unwrap();
  let point = |point| CompressedEdwardsY(point).decompress().unwrap();

  // Generated from Monero
  assert!(Bulletproofs::Original(OriginalStruct {
    A: point(hex!("ef32c0b9551b804decdcb107eb22aa715b7ce259bf3c5cac20e24dfa6b28ac71")),
    S: point(hex!("e1285960861783574ee2b689ae53622834eb0b035d6943103f960cd23e063fa0")),
    T1: point(hex!("4ea07735f184ba159d0e0eb662bac8cde3eb7d39f31e567b0fbda3aa23fe5620")),
    T2: point(hex!("b8390aa4b60b255630d40e592f55ec6b7ab5e3a96bfcdcd6f1cd1d2fc95f441e")),
    taux: scalar(hex!("5957dba8ea9afb23d6e81cc048a92f2d502c10c749dc1b2bd148ae8d41ec7107")),
    mu: scalar(hex!("923023b234c2e64774b820b4961f7181f6c1dc152c438643e5a25b0bf271bc02")),
    L: vec![
      point(hex!("c45f656316b9ebf9d357fb6a9f85b5f09e0b991dd50a6e0ae9b02de3946c9d99")),
      point(hex!("9304d2bf0f27183a2acc58cc755a0348da11bd345485fda41b872fee89e72aac")),
      point(hex!("1bb8b71925d155dd9569f64129ea049d6149fdc4e7a42a86d9478801d922129b")),
      point(hex!("5756a7bf887aa72b9a952f92f47182122e7b19d89e5dd434c747492b00e1c6b7")),
      point(hex!("6e497c910d102592830555356af5ff8340e8d141e3fb60ea24cfa587e964f07d")),
      point(hex!("f4fa3898e7b08e039183d444f3d55040f3c790ed806cb314de49f3068bdbb218")),
      point(hex!("0bbc37597c3ead517a3841e159c8b7b79a5ceaee24b2a9a20350127aab428713")),
    ],
    R: vec![
      point(hex!("609420ba1702781692e84accfd225adb3d077aedc3cf8125563400466b52dbd9")),
      point(hex!("fb4e1d079e7a2b0ec14f7e2a3943bf50b6d60bc346a54fcf562fb234b342abf8")),
      point(hex!("6ae3ac97289c48ce95b9c557289e82a34932055f7f5e32720139824fe81b12e5")),
      point(hex!("d071cc2ffbdab2d840326ad15f68c01da6482271cae3cf644670d1632f29a15c")),
      point(hex!("e52a1754b95e1060589ba7ce0c43d0060820ebfc0d49dc52884bc3c65ad18af5")),
      point(hex!("41573b06140108539957df71aceb4b1816d2409ce896659aa5c86f037ca5e851")),
      point(hex!("a65970b2cc3c7b08b2b5b739dbc8e71e646783c41c625e2a5b1535e3d2e0f742")),
    ],
    a: scalar(hex!("0077c5383dea44d3cd1bc74849376bd60679612dc4b945255822457fa0c0a209")),
    b: scalar(hex!("fe80cf5756473482581e1d38644007793ddc66fdeb9404ec1689a907e4863302")),
    t: scalar(hex!("40dfb08e09249040df997851db311bd6827c26e87d6f0f332c55be8eef10e603"))
  })
  .verify(
    &mut OsRng,
    &[
      // For some reason, these vectors are * INV_EIGHT
      point(hex!("8e8f23f315edae4f6c2f948d9a861e0ae32d356b933cd11d2f0e031ac744c41f"))
        .mul_by_cofactor(),
      point(hex!("2829cbd025aa54cd6e1b59a032564f22f0b2e5627f7f2c4297f90da438b5510f"))
        .mul_by_cofactor(),
    ]
  ));
}

macro_rules! bulletproofs_tests {
  ($name: ident, $max: ident, $plus: literal) => {
    #[test]
    fn $name() {
      // Create Bulletproofs for all possible output quantities
      let mut verifier = BatchVerifier::new(16);
      for i in 1 .. 17 {
        let commitments = (1 ..= i)
          .map(|i| Commitment::new(random_scalar(&mut OsRng), u64::try_from(i).unwrap()))
          .collect::<Vec<_>>();

        let bp = Bulletproofs::prove(&mut OsRng, &commitments, $plus).unwrap();

        let commitments = commitments.iter().map(Commitment::calculate).collect::<Vec<_>>();
        assert!(bp.verify(&mut OsRng, &commitments));
        assert!(bp.batch_verify(&mut OsRng, &mut verifier, i, &commitments));
      }
      assert!(verifier.verify_vartime());
    }

    #[test]
    fn $max() {
      // Check Bulletproofs errors if we try to prove for too many outputs
      let mut commitments = vec![];
      for _ in 0 .. 17 {
        commitments.push(Commitment::new(Scalar::zero(), 0));
      }
      assert!(Bulletproofs::prove(&mut OsRng, &commitments, $plus).is_err());
    }
  };
}

bulletproofs_tests!(bulletproofs, bulletproofs_max, false);
bulletproofs_tests!(bulletproofs_plus, bulletproofs_plus_max, true);
