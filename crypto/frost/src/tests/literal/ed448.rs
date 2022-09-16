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
            "f770bcb22f3c0acac7f09d3b757f13f31b53489776ede2cff944b4c0",
            "cd28bb7dfbd33809e87201e152beeb552292eb748efa5267fa2dcd20",
            "00"
          ),
          concat!(
            "d3196c7f14b1a99f1715053c00fa3a30b0fe9cbeb461068c262b1714",
            "78458a15598cc1c33cd415a766577996a6efcc520c411abf0280c816",
            "00"
          ),
        ],
        [
          concat!(
            "9172a7cea56b7f564ed93116adf078ee013e4160e2687489ea580bc6",
            "f034f10e58db0b0cdf98bf1d3c85b2eb1f30b8b6df57b3611d205d2e",
            "00"
          ),
          concat!(
            "3b60b4dc036b21441620a36c84b0ec780267a9275b411a495b182dc6",
            "bfc812d1a21d93142d375b7ed80314d1693b61c1f42e20c575a4530e",
            "00"
          ),
        ],
      ],
      sig_shares: &[
        concat!(
          "95aeb18a46bac9e239d8eb51a7168da25a000d8a6938e26446c36e5d",
          "b88eff9523e0b09934558ddc8b2679bf2f10ed66415df1eb6e38a507",
          "00"
        ),
        concat!(
          "521672ae547cd95b94a9be55b72a0dfb6938715230304d39017f5a54",
          "f1333a96da50a0759eea78bdb6b670c8243dbe706cd388763fe4c50b",
          "00"
        ),
      ],
      sig: concat!(
        "f1c2605fc0b724696dff10d2df0ac28939f40dc3d9ba864605462355",
        "c139229de643a6580e5807994cfcab0796644571c501cab00e85056a",
        "00",
        "e7c423399b36a33ece81aaa75e419a9dc4387edc99682f9e4742c9b1",
        "a9c2392cfe30510fd33f069a42dde987544dabd7ad307a62ae1c6b13",
        "00"
      ).to_string()
    },
  );
}
