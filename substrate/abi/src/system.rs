use sp_runtime::DispatchError;
use frame_support::dispatch::DispatchInfo;

use serai_primitives::SeraiAddress;

#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode, scale_info::TypeInfo)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Event {
  ExtrinsicSuccess { dispatch_info: DispatchInfo },
  ExtrinsicFailed { dispatch_error: DispatchError, dispatch_info: DispatchInfo },
  CodeUpdated,
  NewAccount { account: SeraiAddress },
  KilledAccount { account: SeraiAddress },
  Remarked { sender: SeraiAddress, hash: [u8; 32] },
}
