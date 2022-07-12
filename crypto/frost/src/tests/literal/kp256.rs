use rand::rngs::OsRng;

#[cfg(feature = "secp256k1")]
use crate::tests::{curve::test_curve, schnorr::test_schnorr};
#[cfg(feature = "secp256k1")]
use crate::curve::Secp256k1;

#[cfg(feature = "p256")]
use crate::tests::vectors::{Vectors, test_with_vectors};
#[cfg(feature = "p256")]
use crate::curve::{P256, IetfP256Hram};

#[cfg(feature = "secp256k1")]
#[test]
fn secp256k1_non_ietf() {
  test_curve::<_, Secp256k1>(&mut OsRng);
  test_schnorr::<_, Secp256k1>(&mut OsRng);
}

#[cfg(feature = "p256")]
#[test]
fn p256_vectors() {
  test_with_vectors::<_, P256, IetfP256Hram>(
    &mut OsRng,
    Vectors {
      threshold: 2,
      shares: &[
        "0c9c1a0fe806c184add50bbdcac913dda73e482daf95dcb9f35dbb0d8a9f7731",
        "8d8e787bef0ff6c2f494ca45f4dad198c6bee01212d6c84067159c52e1863ad5",
        "0e80d6e8f6192c003b5488ce1eec8f5429587d48cf001541e713b2d53c09d928"
      ],
      group_secret: "8ba9bba2e0fd8c4767154d35a0b7562244a4aaf6f36c8fb8735fa48b301bd8de",
      group_key: "023a309ad94e9fe8a7ba45dfc58f38bf091959d3c99cfbd02b4dc00585ec45ab70",

      msg: "74657374",
      included: &[1, 3],
      nonces: &[
        [
          "33a519cf070a166f9ef41a798d03423743f3e7d0b0efd5d0d963773c4c53205e",
          "307d208d0c5728f323ae374f1ebd7f14a1a49b77d9d4bc1eab222218a17765ff"
        ],
        [
          "a614eadb972dc37b88aeceb6e899903f3104742d13f379a0e014541decbea4a4",
          "e509791018504c5bb87edaf0f44761cc840888507c4cd80237971d78e65f70f2"
        ]
      ],
      sig_shares: &[
        "61e8b9c474df2e66ad19fd80a6e6cec1c6fe43c0a1cffd2d1c28299e93e1bbdb",
        "9651d355ca1dea2557ba1f73e38a9f4ff1f1afc565323ef27f88a9d14df8370e"
      ],
      sig: "02dfba781e17b830229ae4ed22ebe402873683d9dfd945d01762217fb3172c2a7".to_owned() +
           "1f83a8d1a3efd188c04d41cf48a716e11b8eff38607023c1f9bb0d36fe1d9f2e9"
    }
  );
}
