use rand::rngs::OsRng;

use crate::{
  curve,
  tests::vectors::{Vectors, test_with_vectors},
};

#[cfg(any(test, feature = "ristretto"))]
#[test]
fn ristretto_vectors() {
  test_with_vectors::<_, curve::Ristretto, curve::IetfRistrettoHram>(
    &mut OsRng,
    Vectors {
      threshold: 2,
      shares: &[
        "5c3430d391552f6e60ecdc093ff9f6f4488756aa6cebdbad75a768010b8f830e",
        "b06fc5eac20b4f6e1b271d9df2343d843e1e1fb03c4cbb673f2872d459ce6f01",
        "f17e505f0e2581c6acfe54d3846a622834b5e7b50cad9a2109a97ba7a80d5c04",
      ],
      group_secret: "1b25a55e463cfd15cf14a5d3acc3d15053f08da49c8afcf3ab265f2ebc4f970b",
      group_key: "e2a62f39eede11269e3bd5a7d97554f5ca384f9f6d3dd9c3c0d05083c7254f57",

      msg: "74657374",
      included: &[1, 3],
      nonces: &[
        [
          "eb0dc12ae7b746d36e3f2de46ce3833a05b9d4af5434eeb8cafaefda76906d00",
          "491e91aa9df514ef598d5e0c7c5cdd088fbde4965b96069d546c0f04f1822b03",
        ],
        [
          "abd12b8e6f255ee1e540eab029003a6e956567617720f61115f0941615892209",
          "218e22625f93f262f025bd2d13c46ba722aa29fe585ceed66ff442d98fe4e509",
        ],
      ],
      sig_shares: &[
        "efae3a83437fa8cd96194aacc56a7eb841630c280da99e7764a81d1340323306",
        "96ddc4582e45eabce46f07b9e9375f8b49d35d1510fd34ac02b1e79d6100a602",
      ],
      sig: "7ec584cef9a383afb43883b73bcaa6313afe878bd5fe75a608311b866a76ec67".to_owned() +
        "858cffdb71c4928a7b895165afa2dd438b366a3d1da6d323675905b1a132d908",
    },
  );
}

#[cfg(feature = "ed25519")]
#[test]
fn ed25519_vectors() {
  test_with_vectors::<_, curve::Ed25519, curve::IetfEd25519Hram>(
    &mut OsRng,
    Vectors {
      threshold: 2,
      shares: &[
        "929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509",
        "a91e66e012e4364ac9aaa405fcafd370402d9859f7b6685c07eed76bf409e80d",
        "d3cb090a075eb154e82fdb4b3cb507f110040905468bb9c46da8bdea643a9a02",
      ],
      group_secret: "7b1c33d3f5291d85de664833beb1ad469f7fb6025a0ec78b3a790c6e13a98304",
      group_key: "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673",

      msg: "74657374",
      included: &[1, 3],
      nonces: &[
        [
          "d9aad97e1a1127bb87702ce8d81d8c07c7cbca89e784868d8e3876ff6b459700",
          "5063be2774520d08a5ccd7f1213fb1179a5fa292bf13bc91cb28e7bd4d4a690c",
        ],
        [
          "86961f3a429ac0c5696f49e6d796817ff653f83c07f34e9e1f4d4c8c515b7900",
          "72225ec11c1315d9f1ea0e78b1160ed95800fadd0191d23fd2f2c90ac96cb307",
        ],
      ],
      sig_shares: &[
        "caae171b83bff0c2c6f56a1276892918ba228146f6344b85d2ec6efeb6f16d0d",
        "ea6fdbf61683cf5f1f742e1b91583f0f667f0369efd2e33399b96d5a3ff0300d",
      ],
      sig: "5da10008c13c04dd72328ba8e0f72b63cad43c3bf4b7eaada1c78225afbd977e".to_owned() +
        "c74afdb47fdfadca0fcda18a28e8891220a284afe5072fb96ba6dc58f6e19e0a",
    },
  );
}
