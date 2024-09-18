pub(crate) mod output;
pub(crate) mod transaction;
pub(crate) mod block;

pub(crate) const DAI: [u8; 20] =
  match const_hex::const_decode_to_array(b"0x6B175474E89094C44Da98b954EedeAC495271d0F") {
    Ok(res) => res,
    Err(_) => panic!("invalid non-test DAI hex address"),
  };
