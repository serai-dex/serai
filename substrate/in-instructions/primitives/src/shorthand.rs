#[cfg(feature = "std")]
use zeroize::Zeroize;

use serde::{Serialize, Deserialize};

use scale::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;

use serai_primitives::{Coin, Amount, SeraiAddress, ExternalAddress};

use tokens_primitives::OutInstruction;

use crate::RefundableInInstruction;
#[cfg(feature = "std")]
use crate::InInstruction;

#[derive(
  Clone, PartialEq, Eq, Debug, Serialize, Deserialize, Encode, Decode, MaxEncodedLen, TypeInfo,
)]
#[cfg_attr(feature = "std", derive(Zeroize))]
pub enum Shorthand {
  Raw(RefundableInInstruction),
  Swap {
    origin: Option<ExternalAddress>,
    coin: Coin,
    minimum: Amount,
    out: OutInstruction,
  },
  AddLiquidity {
    origin: Option<ExternalAddress>,
    minimum: Amount,
    gas: Amount,
    address: SeraiAddress,
  },
}

impl Shorthand {
  #[cfg(feature = "std")]
  pub fn transfer(origin: Option<ExternalAddress>, address: SeraiAddress) -> Self {
    Self::Raw(RefundableInInstruction { origin, instruction: InInstruction::Transfer(address) })
  }
}

impl TryFrom<Shorthand> for RefundableInInstruction {
  type Error = &'static str;
  fn try_from(shorthand: Shorthand) -> Result<RefundableInInstruction, &'static str> {
    Ok(match shorthand {
      Shorthand::Raw(instruction) => instruction,
      Shorthand::Swap { .. } => todo!(),
      Shorthand::AddLiquidity { .. } => todo!(),
    })
  }
}
