use rand_core::OsRng;

use crate::tests::vectors::{Vectors, test_with_vectors};

#[cfg(feature = "secp256k1")]
use crate::curve::{Secp256k1, IetfSecp256k1Hram};

#[cfg(feature = "p256")]
use crate::curve::{P256, IetfP256Hram};

#[cfg(feature = "secp256k1")]
#[test]
fn secp256k1_vectors() {
  test_with_vectors::<_, Secp256k1, IetfSecp256k1Hram>(
    &mut OsRng,
    Vectors {
      threshold: 2,
      shares: &[
        "08f89ffe80ac94dcb920c26f3f46140bfc7f95b493f8310f5fc1ea2b01f4254c",
        "04f0feac2edcedc6ce1253b7fab8c86b856a797f44d83d82a385554e6e401984",
        "00e95d59dd0d46b0e303e500b62b7ccb0e555d49f5b849f5e748c071da8c0dbc",
      ],
      group_secret: "0d004150d27c3bf2a42f312683d35fac7394b1e9e318249c1bfe7f0795a83114",
      group_key: "02f37c34b66ced1fb51c34a90bdae006901f10625cc06c4f64663b0eae87d87b4f",

      msg: "74657374",
      included: &[1, 3],
      nonces: &[
        [
          "36d5c4185c40b02b5e4673e2531a10e6ff9883840a68ec08dbeb896467e21355",
          "7b3f573ca0a28f9f94522be4748df0ed04de8a83085aff4be7b01aa53fb6ac1b",
        ],
        [
          "ba4f8b8e587b2c9fc61a6156885f0bc67654b5e068c9e7749f75c09a98f17c13",
          "316de06639051ac7869e5ac4458eda1fef90ce93fa3c490556c4192e4fa550d0",
        ],
      ],
      sig_shares: &[
        "f9ee00d5ac0c746b751dde99f71d86f8f0300a81bd0336ca6649ef597239e13f",
        "61048ca334ac6a6cb59d6b3ea2b25b7098e204adc09e2f88b024531b081d1d6f",
      ],
      sig: "023cf76388f92d403aa937af2e3cb3e7a2350e40400c16a282e330af2c60eeb85a".to_owned() +
        "5af28d78e0b8ded82abb49d899cfe26ace633248ce58c617569be3e7aa20bd6d",
    },
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
        "0e80d6e8f6192c003b5488ce1eec8f5429587d48cf001541e713b2d53c09d928",
      ],
      group_secret: "8ba9bba2e0fd8c4767154d35a0b7562244a4aaf6f36c8fb8735fa48b301bd8de",
      group_key: "023a309ad94e9fe8a7ba45dfc58f38bf091959d3c99cfbd02b4dc00585ec45ab70",

      msg: "74657374",
      included: &[1, 3],
      nonces: &[
        [
          "9aa66350b0f72b27ce4668323b4280cd49709177ed8373977c22a75546c9995d",
          "bd8b05d7fd0ff5a5ed65b1f105478f7718a981741fa8fa9b55ac6d3c8fc59a05",
        ],
        [
          "4c1aec8e84c496b80af98415fada2e6a4b1f902d4bc6c9682699b8aeffd97419",
          "eeaf5ef7af01e55050fb8acafc9c9306ef1cc13214677ba33e7bc51e8677e892",
        ],
      ],
      sig_shares: &[
        "ec5b8ab47d55903698492a07bb322ab6e7d3cf32581dcedf43c4fa18b46f3e10",
        "c97da3580560e88725a8e393d46fee18ecd2e00148e5e303d4a510fae9c11da5",
      ],
      sig: "036b3eba585ff5d40df29893fb6f60572803aef97800cfaaaa5cf0f0f19d8237f7".to_owned() +
        "b5d92e0d82b678bcbdf20d9b8fa218d017bfb485f9ec135e24b04050a1cd3664",
    },
  );
}
