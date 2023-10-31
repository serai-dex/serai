use crate::ringct::generate_key_image;

use curve25519_dalek::{scalar::Scalar, edwards::CompressedEdwardsY};

use monero_generators::H;

use zeroize::Zeroizing;

use hex_literal::hex;

#[test]
fn key_image() {
  struct Vector {
    secret: String,
    key_image: String,
  }

  let vectors = [
    Vector {
      secret: "0000000000000000000000000000000000000000000000000000000000000000".into(),
      key_image: "0100000000000000000000000000000000000000000000000000000000000000".into(),
    },
    Vector {
      secret: "73d8e5c722cb2ed17188c1974045bf2766371eee8cf1f7a0c35366bd39ab0808".into(),
      key_image: "a5f0cd466b5a970b528b105e3b16137852ed76fbffe45882381d97b97925ddad".into(),
    },
  ];

  for v in vectors {
    let secret: [u8; 32] = hex::decode(v.secret).unwrap().try_into().unwrap();

    // calculate a key image for a given scalar
    let scalar = Zeroizing::new(Scalar::from_bits(secret));
    let calculated_image = generate_key_image(&scalar);

    // convert calculated image to string
    let cal_str = hex::encode(calculated_image.compress().as_bytes());

    assert_eq!(cal_str, v.key_image);
  }
}

#[test]
fn h() {
  // Taken from Monero:
  // https://github.com/monero-project/monero/blob/master/src/ringct/rctTypes.h#L623
  let monero_h =
    CompressedEdwardsY(hex!("8b655970153799af2aeadc9ff1add0ea6c7251d54154cfa92c173a0dd39c1f94"))
      .decompress()
      .unwrap();

  assert_eq!(monero_h, *H);
}
