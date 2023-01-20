use scale::{Encode, Decode, MaxEncodedLen};
use scale_info::TypeInfo;

#[cfg(feature = "std")]
use serde::{Serialize, Deserialize};

use sp_core::{ConstU32, bounded::BoundedVec};

use serai_primitives::{SeraiAddress, Coin, Amount};

use crate::{MAX_DATA_LEN, ExternalAddress, RefundableInInstruction, OutInstruction};

#[derive(Clone, PartialEq, Eq, Debug, Encode, Decode, MaxEncodedLen, TypeInfo)]
#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
pub enum Shorthand {
  Raw(BoundedVec<u8, ConstU32<{ MAX_DATA_LEN }>>),
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

impl TryFrom<Shorthand> for RefundableInInstruction {
  type Error = &'static str;
  fn try_from(shorthand: Shorthand) -> Result<RefundableInInstruction, &'static str> {
    Ok(match shorthand {
      Shorthand::Raw(raw) => {
        RefundableInInstruction::decode(&mut raw.as_ref()).map_err(|_| "invalid raw instruction")?
      }
      Shorthand::Swap { .. } => todo!(),
      Shorthand::AddLiquidity { .. } => todo!(),
    })
  }
}
