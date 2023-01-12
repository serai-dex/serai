#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#![cfg_attr(not(feature = "std"), no_std)]

mod amount;
pub use amount::*;

mod coins;
pub use coins::*;

pub type NativeAddress = sp_core::sr25519::Public;
