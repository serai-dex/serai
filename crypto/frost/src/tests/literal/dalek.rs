use rand_core::OsRng;

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
          "1eaee906e0554a5e533415e971eefa909f3c614c7c75e27f381b0270a9afe308",
          "16175fc2e7545baf7180e8f5b6e1e73c4f2769323cc76754bdd79fe93ab0bd0b",
        ],
        [
          "48d78b8c2de1a515513f9d3fc464a19a72304fac522f17cc647706cb22c21403",
          "5c0f10966b3f1386660a87de0fafd69decbe9ffae1a152a88b7d83bb4fb1c908",
        ],
      ],
      sig_shares: &[
        "5ae13621ebeef844e39454eb3478a50c4531d25939e1065f44f5b04a8535090e",
        "aa432dcf274a9441c205e76fe43497be99efe374f9853477bd5add2075f6970c",
      ],
      sig: "9c407badb8cacf10f306d94e31fb2a71d6a8398039802b4d80a1278472397206".to_owned() +
        "17516e93f8d57a2ecffd43b83ab35db6de20b6ce32673bd601508e6bfa2ba10a",
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
          "1c406170127e33142b8611bc02bf14d5909e49d5cb87150eff3ec9804212920c",
          "5be4edde8b7acd79528721191626810c94fbc2bcc814b7a67d301fbd7fc16e07",
        ],
        [
          "795f87122f05b7efc4b1a52f435c3d28597411b1a6fec198ce9c818c5451c401",
          "c9193aaef37bc074ea3286d0361c815f7201bf764cd9e7d8bb4eb5ecca840a09",
        ],
      ],
      sig_shares: &[
        "1f16a3989b4aa2cc3782a503331b9a21d7ba56c9c5455d06981b5425306c9d01",
        "4c8f33c301c05871b434a686847d5818417a01e50a59e9e7fddaefde7d244207",
      ],
      sig: "1aff2259ecb59cfcbb36ae77e02a9b134422abeae47cf7ff56c85fdf90932b18".to_owned() +
        "6ba5d65b9d0afb3decb64b8ab798f239183558aed09e46ee95f64304ae90df08",
    },
  );
}
