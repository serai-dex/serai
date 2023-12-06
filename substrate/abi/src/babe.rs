use sp_consensus_babe::EquivocationProof;

use serai_primitives::Header;

#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode)]
pub struct ReportEquivocation {
  pub equivocation_proof: Box<EquivocationProof<Header>>,
  pub key_owner_proof: (),
}

#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode)]
pub enum Call {
  report_equivocation(ReportEquivocation),
  report_equivocation_unsigned(ReportEquivocation),
}
