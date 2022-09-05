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
          "95f352cf568508bce96ef3cb816bf9229eb521ca9c2aff6a4fe8b86bf49ae16f",
          "c675aea50ff2510ae6b0fcb55432b97ad0b55a28b959bacb0e8b466dbf43dd26",
        ],
        [
          "b5089ebf363630d3477711005173c1419f4f40514f7287b4ca6ff110967a2d70",
          "5e50ce9975cfc6164e85752f52094b11091fdbca846a9c245fdbfa4bab1ae28c",
        ],
      ],
      sig_shares: &[
        "280c44c6c37cd64c7f5a552ae8416a57d21c115cab524dbff5fbcebbf5c0019d",
        "e372bca35133a80ca140dcac2125c966b763a934678f40e09fb8b0ae9d4aee1b",
      ],
      sig: "0364b02292a4b0e61f849f4d6fac0e67c2f698a21e1cba9e4a5b8fa535f2f9310d".to_owned() +
        "0b7f016a14b07e59209b31d7096733bfced0ddaa6398ee64d5e220ddc2d4ae77",
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
          "e9165dad654fc20a9e31ca6f32ac032ec327b551a50e8ac5cf25f5c4c9e20757",
          "e9059a232598a0fba0e495a687580e624ab425337c3221246fb2c716905bc9e7",
        ],
        [
          "b9d136e29eb758bd77cb83c317ac4e336cf8cda830c089deddf6d5ec81da9884",
          "5261e2d00ce227e67bb9b38990294e2c82970f335b2e6d9f1d07a72ba43d01f0",
        ],
      ],
      sig_shares: &[
        "bdaa275f10ca57e3a3a9a7a0d95aeabb517897d8482873a8f9713d458f94756f",
        "0e8fd85386939e8974a8748e66641df0fe043323c52487a2b10b8a397897de21",
      ],
      sig: "03c41521412528dce484c35b6b9b7cc8150102ab3e4bdf858d702270c05098e6c6".to_owned() +
        "cc39ffb2975df66d18521c2f3fbf08ac4f7ccafc0d4cfb4baa7cc77f082c5390",
    },
  );
}
