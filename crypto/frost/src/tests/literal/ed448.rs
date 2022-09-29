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
            "06f2e15b05d29a50f0686a890259f4dcf66147a80809ed9e50926f5f",
            "173fe23a0627561efa003724dc270effc47a30bc4d80aba30725401d",
            "00"
          ),
          concat!(
            "e0482e611c34f191d1c13a09bc8bbf4bda68db4de32aa7908849b02b",
            "a912cfba46c805e2d8560ab9437e343e1dde6b481a2bae527e111b2c",
            "00"
          ),
        ],
        [
          concat!(
            "295c56447c070157e6bc3c83ed2afca194569e07d0ad27d28a40dec2",
            "c4107c07d507db20da1be62ea6976b8e53ab5d26e225c663f2e71511",
            "00"
          ),
          concat!(
            "b97303a6c5ab12b6ad310834361033a19d99dfdf93109da721da35c3",
            "abbc5f29df33b3402692bef9f005bb8ea00af5ba20cc688360fd8831",
            "00"
          ),
        ],
      ],
      sig_shares: &[
        concat!(
          "5b65641e27007ec71509c6af5cf8527eb01fee5b2b07d8beecf6646e",
          "b7e7e27d85119b74f895b56ba7561834a1b0c42639b122160a0b6208",
          "00"
        ),
        concat!(
          "821b7ac04d7c01d970b0b3ba4ae8f737a5bac934aed1600b1cad7601",
          "1c240629bce6a4671a1b6f572cec708ec161a72a5ca04e50eabdfc25",
          "00"
        ),
      ],
      sig: concat!(
        "c7ad7ad9fcfeef9d1492361ba641400bd3a3c8335a83cdffbdd8867d",
        "2849bb4419dcc3e594baa731081a1a00cd3dea9219a81ecba4646e95",
        "00",
        "dd80dede747c7fa086b9796aa7e04ab655dab790d9d838ca08a4db6f",
        "d30be9a641f83fdc12b124c3d34289c262126c5195517166f4c85e2e",
        "00"
      )
      .to_string(),
    },
  );
}
