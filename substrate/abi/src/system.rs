use frame_support::dispatch::{DispatchInfo, DispatchError};

use serai_primitives::SeraiAddress;

#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode, scale_info::TypeInfo)]
pub enum Event {
  ExtrinsicSuccess { dispatch_info: DispatchInfo },
  ExtrinsicFailed { dispatch_error: DispatchError, dispatch_info: DispatchInfo },
  CodeUpdated,
  NewAccount { account: SeraiAddress },
  KilledAccount { account: SeraiAddress },
  Remarked { sender: SeraiAddress, hash: [u8; 32] },
}
