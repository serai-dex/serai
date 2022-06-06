use rand::rngs::OsRng;

use crate::{curves::dalek, tests::vectors::{Vectors, test_with_vectors}};

#[cfg(any(test, feature = "ristretto"))]
#[test]
fn ristretto_vectors() {
  test_with_vectors::<_, dalek::Ristretto, dalek::IetfRistrettoHram>(
    &mut OsRng,
    Vectors {
      threshold: 2,
      shares: &[
        "5c3430d391552f6e60ecdc093ff9f6f4488756aa6cebdbad75a768010b8f830e",
        "b06fc5eac20b4f6e1b271d9df2343d843e1e1fb03c4cbb673f2872d459ce6f01",
        "f17e505f0e2581c6acfe54d3846a622834b5e7b50cad9a2109a97ba7a80d5c04"
      ],
      group_secret: "1b25a55e463cfd15cf14a5d3acc3d15053f08da49c8afcf3ab265f2ebc4f970b",
      group_key: "e2a62f39eede11269e3bd5a7d97554f5ca384f9f6d3dd9c3c0d05083c7254f57",

      msg: "74657374",
      included: &[1, 3],
      nonces: &[
        [
          "b358743151e33d84bf00c12f71808f4103957c3e2cabab7b895c436b5e70f90c",
          "7bd112153b9ae1ab9b31f5e78f61f5c4ca9ee67b7ea6d1181799c409d14c350c"
        ],
        [
          "22acad88478e0d0373a991092a322ebd1b9a2dad90451a976d0db3215426af0e",
          "9155e3d7bcf7cd468b980c7e20b2c77cbdfbe33a1dcae031fd8bc6b1403f4b04"
        ]
      ],
      sig_shares: &[
        "ff801b4e0839faa67f16dee4127b9f7fbcf5fd007900257b0e2bbc02cbe5e709",
        "afdf5481023c855bf3411a5c8a5fafa92357296a078c3b80dc168f294cb4f504"
      ],
      sig: "deae61af10e8ee48ba492573592fba547f5debeff6bd6e2024e8673584746f5e".to_owned() +
           "ae6070cf0a757f027358f8409dda4e29e04c276b808c60fbea414b2c179add0e"
    }
  );
}

#[cfg(feature = "ed25519")]
#[test]
fn ed25519_vectors() {
  test_with_vectors::<_, dalek::Ed25519, dalek::IetfEd25519Hram>(
    &mut OsRng,
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
