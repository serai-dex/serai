use frame_system::DispatchEventInfo;
use frame_support::sp_runtime::DispatchError;

use serai_primitives::SeraiAddress;

#[derive(
  Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode, scale::DecodeWithMemTracking,
)]
pub enum Event {
  ExtrinsicSuccess { dispatch_info: DispatchEventInfo },
  ExtrinsicFailed { dispatch_error: DispatchError, dispatch_info: DispatchEventInfo },
  CodeUpdated,
  NewAccount { account: SeraiAddress },
  KilledAccount { account: SeraiAddress },
}
