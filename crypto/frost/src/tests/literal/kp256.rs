use rand::rngs::OsRng;

#[cfg(feature = "k256")]
use crate::tests::{curve::test_curve, schnorr::test_schnorr};
#[cfg(feature = "k256")]
use crate::curves::kp256::K256;

#[cfg(feature = "p256")]
use crate::tests::vectors::{Vectors, test_with_vectors};
#[cfg(feature = "p256")]
use crate::curves::kp256::{P256, IetfP256Hram};

#[cfg(feature = "k256")]
#[test]
fn k256_not_ietf() {
  test_curve::<_, K256>(&mut OsRng);
  test_schnorr::<_, K256>(&mut OsRng);
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
          "081617b24375e069b39f649d4c4ce2fba6e38b73e7c16759de0b6079a22c4c7e",
          "4de5fb77d99f03a2491a83a6a4cb91ca3c82a3f34ce94cec939174f47c9f95dd"
        ],
        [
          "d186ea92593f83ea83181b184d41aa93493301ac2bc5b4b1767e94d2db943e38",
          "486e2ee25a3fbc8e6399d748b077a2755fde99fa85cc24fa647ea4ebf5811a15"
        ]
      ],
      sig_shares: &[
        "9e4d8865faf8c7b3193a3b35eda3d9e12118447114b1e7d5b4809ea28067f8a9",
        "b7d094eab6305ae74daeed1acd31abba9ab81f638d38b72c132cb25a5dfae1fc"
      ],
      sig: "0342c14c77f9d4ef9b8bd64fb0d7bbfdb9f8216a44e5f7bbe6ac0f3ed5e1a57367".to_owned() +
        "561e1d51b129229966e92850bad5859bfee96926fad3007cd3f38639e1ffb554"
    }
  );
}
