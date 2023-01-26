use scale::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;

#[cfg(feature = "std")]
use serde::{Serialize, Deserialize};

use serai_primitives::{Coin, Amount, SeraiAddress, ExternalAddress, Data};

use tokens_primitives::OutInstruction;

use crate::RefundableInInstruction;
#[cfg(feature = "std")]
use crate::InInstruction;

#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub enum Shorthand {
  Raw(Data),
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
  pub fn transfer(origin: Option<ExternalAddress>, address: SeraiAddress) -> Option<Self> {
    Some(Self::Raw(
      Data::new(
        (RefundableInInstruction { origin, instruction: InInstruction::Transfer(address) })
          .encode(),
      )
      .ok()?,
    ))
  }
}

impl TryFrom<Shorthand> for RefundableInInstruction {
  type Error = &'static str;
  fn try_from(shorthand: Shorthand) -> Result<RefundableInInstruction, &'static str> {
    Ok(match shorthand {
      Shorthand::Raw(raw) => {
        RefundableInInstruction::decode(&mut raw.data()).map_err(|_| "invalid raw instruction")?
      }
      Shorthand::Swap { .. } => todo!(),
      Shorthand::AddLiquidity { .. } => todo!(),
    })
  }
}
