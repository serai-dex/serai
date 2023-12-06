use sp_consensus_grandpa::EquivocationProof;

use serai_primitives::{BlockNumber, SeraiAddress};

#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode)]
pub struct ReportEquivocation {
  pub equivocation_proof: Box<EquivocationProof<[u8; 32], BlockNumber>>,
  pub key_owner_proof: (),
}

#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode)]
pub enum Call {
  report_equivocation(ReportEquivocation),
  report_equivocation_unsigned(ReportEquivocation),
}

#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Event {
  NewAuthorities { authority_set: Vec<(SeraiAddress, u64)> },
  Paused,
  Resumed,
}
