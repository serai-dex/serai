use frame_support::dispatch::{DispatchInfo, DispatchError};

#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Event {
  ExtrinsicSuccess { dispatch_info: DispatchInfo },
  ExtrinsicFailed { dispatch_error: DispatchError, dispatch_info: DispatchInfo },
}
