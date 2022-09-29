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
          "de3e8f526dcb51a1b9b48cc284aeca27c385aa3ba1a92a0c8440d51e1a1d2f00",
          "fa8dca5ec7a05d5a7b782be847ba3dde1509de1dbcf0569fc980cff795db5404",
        ],
        [
          "e07061a9ab6735de9a75b0c64f086c5b999894611d0cdc03f85c4e87c8aae602",
          "38b17578e8e6ad4077071ce6b0bf9cb85ac35fee7868dcb6d9bfa97f0e153e0e",
        ],
      ],
      sig_shares: &[
        "a5f046916a6a111672111e47f9825586e1188da8a0f3b7c61f2b6b432c636e07",
        "4c175c7e43bd197980c2021774036eb288f54179f079fbf21b7d2f9f52846401",
      ],
      sig: "94b11def3f919503c3544452ad2a59f198f64cc323bd758bb1c65b42032a7473".to_owned() +
        "f107a30fae272b8ff2d3205e6d86c3386a0ecf21916db3b93ba89ae27ee7d208",
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
          "4e64f59e90a3b9cdce346fae68eb0e459532c8ca1ad59a566c3ee2c67bf0100b",
          "470c660895c6db164ee6564120eec71023fa5297f09c663bb8171646c5632d00",
        ],
        [
          "6fc516495dbb364b807cdd0c2e5e3f58aa4914a53fed33cc340033979bb07304",
          "0837e770a88147d41ff39138ca23b35d6cf303a4f148294755ede4b7e760d701",
        ],
      ],
      sig_shares: &[
        "3f2eb12735e5b39da97e884a6caadf6bb83f1efcec709d6f66333d0d67ebe707",
        "79e572b8632fbb928519dd2eff793de8784a56d582ae48c807d39b0dc5b93509",
      ],
      sig: "e31e69a4e10d5ca2307c4a0d12cd86e3fceee550e55cb5b3f47c7ad6dbb38884".to_owned() +
        "cb3f2e837eb15cd858fb6dd68c2a3e3f318a74d16f1fe6376e06d91a2ca51d01",
    },
  );
}
