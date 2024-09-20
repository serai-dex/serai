use serai_client::primitives::Amount;

pub(crate) mod output;
pub(crate) mod transaction;
pub(crate) mod machine;
pub(crate) mod block;

pub(crate) const DAI: [u8; 20] =
  match const_hex::const_decode_to_array(b"0x6B175474E89094C44Da98b954EedeAC495271d0F") {
    Ok(res) => res,
    Err(_) => panic!("invalid non-test DAI hex address"),
  };

pub(crate) const TOKENS: [[u8; 20]; 1] = [DAI];

// 8 decimals, so 1_000_000_00 would be 1 ETH. This is 0.0015 ETH (5 USD if Ether is ~3300 USD).
#[allow(clippy::inconsistent_digit_grouping)]
pub(crate) const ETHER_DUST: Amount = Amount(1_500_00);
// 5 DAI
#[allow(clippy::inconsistent_digit_grouping)]
pub(crate) const DAI_DUST: Amount = Amount(5_000_000_00);
