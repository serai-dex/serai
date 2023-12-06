#[derive(Clone, PartialEq, Eq, Debug, scale::Encode, scale::Decode)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Call {
  set { now: u64 },
}
