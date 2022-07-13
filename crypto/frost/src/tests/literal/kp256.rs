use rand::rngs::OsRng;

#[cfg(any(feature = "secp256k1", feature = "p256"))]
use crate::tests::vectors::{Vectors, test_with_vectors};

#[cfg(feature = "secp256k1")]
use crate::curve::{Secp256k1, NonIetfSecp256k1Hram};

#[cfg(feature = "p256")]
use crate::curve::{P256, IetfP256Hram};

#[cfg(feature = "secp256k1")]
#[test]
fn secp256k1_non_ietf() {
  test_with_vectors::<_, Secp256k1, NonIetfSecp256k1Hram>(
    &mut OsRng,
    Vectors {
      threshold: 2,
      shares: &[
        "08f89ffe80ac94dcb920c26f3f46140bfc7f95b493f8310f5fc1ea2b01f4254c",
        "04f0feac2edcedc6ce1253b7fab8c86b856a797f44d83d82a385554e6e401984",
        "00e95d59dd0d46b0e303e500b62b7ccb0e555d49f5b849f5e748c071da8c0dbc"
      ],
      group_secret: "0d004150d27c3bf2a42f312683d35fac7394b1e9e318249c1bfe7f0795a83114",
      group_key: "02f37c34b66ced1fb51c34a90bdae006901f10625cc06c4f64663b0eae87d87b4f",

      msg: "74657374",
      included: &[1, 3],
      nonces: &[
        [
          "31c3c1b76b76664569859b9251fbabed9d4d432c6f5aaa03ed41f9c231935798",
          "206f4ffaeb602ccb57cbe50e146ac690e6d7317d4b93377061d9d1b4caf78a26"
        ],
        [
          "0d3945bc1553676a5dd910cb4f14437d99ed421516b2617357b984820fdca520",
          "635e0fd90caaf40b5e986d0ee0f58778e4d88731bc6ac70350ef702ffe20a21b"
        ]
      ],
      sig_shares: &[
        "18b71e284c5d008896ed8847b234ec829eda376d6208838ee7faf2ce21b154c1",
        "a452a49c8116124d0a283f3589a96b704894b43246e47e59d376353bcc638311"
      ],
      sig: "03dafb28ee7ad033fd15ed470d07156617260d74a9d76a15d371d7b613d2b111e".to_owned() +
           "7bd09c2c4cd7312d5a115c77d3bde57f2e76eeb9fa8ed01e8bb712809ee14d7d2"
    }
  );
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
