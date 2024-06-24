use sp_consensus_grandpa::EquivocationProof;

use serai_primitives::{BlockNumber, SeraiAddress};

#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode, scale_info::TypeInfo)]
pub struct ReportEquivocation {
  pub equivocation_proof: alloc::boxed::Box<EquivocationProof<[u8; 32], BlockNumber>>,
  pub key_owner_proof: SeraiAddress,
}

#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode, scale_info::TypeInfo)]
pub enum Call {
  report_equivocation(ReportEquivocation),
  report_equivocation_unsigned(ReportEquivocation),
}

#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode, scale_info::TypeInfo)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(all(feature = "std", feature = "serde"), derive(serde::Deserialize))]
pub enum Event {
  NewAuthorities { authority_set: alloc::vec::Vec<(SeraiAddress, u64)> },
  // TODO: Remove these
  Paused,
  Resumed,
}
