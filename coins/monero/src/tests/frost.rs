use rand::rngs::OsRng;

use sha2::Sha512;

use dalek_ff_group as dfg;
use frost::{
  Curve,
  algorithm::Hram,
  tests::{curve::test_curve, schnorr::test_schnorr, vectors::{Vectors, vectors}}
};

use crate::frost::{Ed25519, Ed25519Internal};

#[test]
fn frost_ed25519_curve() {
  test_curve::<_, Ed25519>(&mut OsRng);
}

#[test]
fn frost_ed25519_schnorr() {
  test_schnorr::<_, Ed25519>(&mut OsRng);
}

// Not spec-compliant, as this shouldn't use wide reduction
// Is vectors compliant, which is why the below tests pass
// See https://github.com/cfrg/draft-irtf-cfrg-frost/issues/204
//type TestEd25519 = Ed25519Internal<Sha512, false>;
// If this is kept, we can remove WIDE
type TestEd25519 = Ed25519Internal<Sha512, true>;

#[derive(Copy, Clone)]
struct IetfEd25519Hram {}
impl Hram<TestEd25519> for IetfEd25519Hram {
  #[allow(non_snake_case)]
  fn hram(R: &dfg::EdwardsPoint, A: &dfg::EdwardsPoint, m: &[u8]) -> dfg::Scalar {
    TestEd25519::hash_to_F(
      b"",
      &[&R.compress().to_bytes(), &A.compress().to_bytes(), m].concat()
    )
  }
}

#[test]
fn frost_ed25519_vectors() {
  vectors::<TestEd25519, IetfEd25519Hram>(
    Vectors {
      threshold: 2,
      shares: &[
        "929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509",
        "a91e66e012e4364ac9aaa405fcafd370402d9859f7b6685c07eed76bf409e80d",
        "d3cb090a075eb154e82fdb4b3cb507f110040905468bb9c46da8bdea643a9a02"
      ],
      group_secret: "7b1c33d3f5291d85de664833beb1ad469f7fb6025a0ec78b3a790c6e13a98304",
      group_key: "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673",

      msg: "74657374",
      included: &[1, 3],
      nonces: &[
        [
          "8c76af04340e83bb5fc427c117d38347fc8ef86d5397feea9aa6412d96c05b0a",
          "14a37ddbeae8d9e9687369e5eb3c6d54f03dc19d76bb54fb5425131bc37a600b"
        ],
        [
          "5ca39ebab6874f5e7b5089f3521819a2aa1e2cf738bae6974ee80555de2ef70e",
          "0afe3650c4815ff37becd3c6948066e906e929ea9b8f546c74e10002dbcc150c"
        ]
      ],
      sig_shares: &[
        "4369474a398aa10357b60d683da91ea6a767dcf53fd541a8ed6b4d780827ea0a",
        "32fcc690d926075e45d2dfb746bab71447943cddbefe80d122c39174aa2e1004"
      ],
      sig: "2b8d9c6995333c5990e3a3dd6568785539d3322f7f0376452487ea35cfda587b".to_owned() +
           "75650edb12b1a8619c88ed1f8463d6baeefb18d3fed3c279102fdfecb255fa0e"
    }
  );
}
