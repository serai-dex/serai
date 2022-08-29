use std::io::Cursor;

use rand_core::OsRng;

use crate::{
  curve::{Curve, Ed448, Ietf8032Ed448Hram, NonIetfEd448Hram},
  schnorr::{SchnorrSignature, verify},
  tests::vectors::{Vectors, test_with_vectors},
};

#[test]
fn ed448_8032_vector() {
  let context = hex::decode("666f6f").unwrap();

  #[allow(non_snake_case)]
  let A = Ed448::read_G(&mut Cursor::new(
    hex::decode(
      "43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c".to_owned() +
        "6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a94" +
        "80",
    )
    .unwrap(),
  ))
  .unwrap();

  let msg = hex::decode("03").unwrap();

  let mut sig = Cursor::new(
    hex::decode(
      "d4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b3".to_owned() +
        "2a89f7d2151f7647f11d8ca2ae279fb842d607217fce6e042f6815ea" +
        "00" +
        "0c85741de5c8da1144a6a1aba7f96de42505d7a7298524fda538fccb" +
        "bb754f578c1cad10d54d0d5428407e85dcbc98a49155c13764e66c3c" +
        "00",
    )
    .unwrap(),
  );
  #[allow(non_snake_case)]
  let R = Ed448::read_G(&mut sig).unwrap();
  let s = Ed448::read_F(&mut sig).unwrap();

  assert!(verify(
    A,
    Ietf8032Ed448Hram::hram(&context, &R, &A, &msg),
    &SchnorrSignature::<Ed448> { R, s }
  ));
}

#[ignore]
#[test]
fn ed448_non_ietf() {
  test_with_vectors::<_, Ed448, NonIetfEd448Hram>(
    &mut OsRng,
    Vectors {
      threshold: 2,
      shares: &[
        concat!(
          "4a2b2f5858a932ad3d3b18bd16e76ced3070d72fd79ae4402df201f5",
          "25e754716a1bc1b87a502297f2a99d89ea054e0018eb55d39562fd01",
          "00"
        ),
        concat!(
          "2503d56c4f516444a45b080182b8a2ebbe4d9b2ab509f25308c88c0e",
          "a7ccdc44e2ef4fc4f63403a11b116372438a1e287265cadeff1fcb07",
          "00"
        ),
        concat!(
          "00db7a8146f995db0a7cf844ed89d8e94c2b5f259378ff66e39d1728",
          "28b264185ac4decf7219e4aa4478285b9c0eef4fccdf3eea69dd980d",
          "00"
        ),
      ],
      group_secret: concat!(
        "6298e1eef3c379392caaed061ed8a31033c9e9e3420726f23b404158",
        "a401cd9df24632adfe6b418dc942d8a091817dd8bd70e1c72ba52f3c",
        "00"
      ),
      group_key: concat!(
        "3832f82fda00ff5365b0376df705675b63d2a93c24c6e81d40801ba2",
        "65632be10f443f95968fadb70d10786827f30dc001c8d0f9b7c1d1b0",
        "00"
      ),

      msg: "74657374",
      included: &[1, 3],
      nonces: &[
        [
          concat!(
            "afa99ad5138f89d064c828ecb17accde77e4dc52e017c20b34d1db11",
            "bdd0b17d2f4ec6ea7d5414df33977267c49b8d4b3b35c7f4a089db2f",
            "00"
          ),
          concat!(
            "c9c2f6119d5a7f60fc1a3517f08f3aced6f84f53cbcfa4709080858d",
            "b8c8b49d4cb9921c4118f1961d4fb653ad5e320d175de3ee5258e904",
            "00"
          ),
        ],
        [
          concat!(
            "a575cf9ae013b63204a56cc0bb0c21184eed6e42f448344e59153cf4",
            "3798ad3b8c300a2c0ffa04ee7228a5c4ff84fcad4cf9616d1cd7fe0a",
            "00"
          ),
          concat!(
            "12419016a6c0d38a1d9d1eeb1455525d73a464113a9323fcfc75e5fb",
            "7c1f17ad71ca2f2852b71f33950adedd7f8489551ad356ecf39a4d29",
            "00"
          ),
        ],
      ],
      sig_shares: &[
        concat!(
          "e88d1e9743ac059553de940131508205eff504816935f8c9d22a29df",
          "4c541e4bb55d4c4a5c58dd65e6d2c421e35f2ddc7ea11095cffb3b16",
          "00"
        ),
        concat!(
          "d6ae2965ee86f925d38eedf0690ee54395243d244b59a5fece45cece",
          "721867a00a6c7af9635c621ea09edad8fc26db5de4ce3aa4e7e7ea3f",
          "00"
        ),
      ],
      sig: "c07db58a26bd0c33930455f1923df2ffa50c3a1679e06a1940f84e0e".to_owned() +
        "067bcec3e46008c3b4018b7b2563ba0f26740b7b5932883355e569f5" +
        "00" +
        "cbf7ef509f708697d1ddbc64289cfa27f4e36bf66ab34e04b84c2d31" +
        "c06c85ebbfc9c643c0b43f8486719ffadf86083a63704b39b7e32616" +
        "00",
    },
  );
}
