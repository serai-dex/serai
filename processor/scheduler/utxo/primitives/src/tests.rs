use core::fmt;

use borsh::{BorshSerialize, BorshDeserialize};

use ciphersuite::WrappedGroup;
use dalek_ff_group::Ed25519;
use primitives::ReceivedOutput;
use scanner::ScannerFeed;
use serai_primitives::{
  address::ExternalAddress,
  balance::{Amount, ExternalBalance},
  coin::ExternalCoin,
  network_id::ExternalNetworkId,
};

#[derive(Clone, Debug, PartialEq, BorshSerialize, BorshDeserialize)]
pub(crate) struct FakeAddress(pub(crate) u32);

impl fmt::Display for FakeAddress {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "fake-{}", self.0)
  }
}

impl From<FakeAddress> for ExternalAddress {
  fn from(value: FakeAddress) -> Self {
    Self::try_from(value.0.to_le_bytes().to_vec()).unwrap()
  }
}

impl TryFrom<ExternalAddress> for FakeAddress {
  type Error = ();
  fn try_from(value: ExternalAddress) -> Result<Self, Self::Error> {
    let bytes = Vec::from(value);
    let bytes: [u8; 4] = bytes.try_into().map_err(|_| ())?;
    let n = u32::from_le_bytes(bytes);
    Ok(Self(n))
  }
}

type Key = <Ed25519 as WrappedGroup>::G;

#[derive(Debug, Clone)]
pub(crate) struct FakeHeader;

impl primitives::BlockHeader for FakeHeader {
  fn id(&self) -> [u8; 32] {
    todo!()
  }

  fn parent(&self) -> [u8; 32] {
    todo!()
  }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct FakeOutput;

impl ReceivedOutput<Key, FakeAddress> for FakeOutput {
  type Id = [u8; 32];

  type TransactionId = [u8; 32];

  fn kind(&self) -> primitives::OutputType {
    todo!()
  }

  fn id(&self) -> Self::Id {
    todo!()
  }

  fn transaction_id(&self) -> Self::TransactionId {
    todo!()
  }

  fn key(&self) -> Key {
    todo!()
  }

  fn presumed_origin(&self) -> Option<FakeAddress> {
    todo!()
  }

  fn balance(&self) -> ExternalBalance {
    todo!()
  }

  fn data(&self) -> &[u8] {
    todo!()
  }

  fn write<W: std::io::Write>(&self, _writer: &mut W) -> std::io::Result<()> {
    todo!()
  }

  fn read<R: std::io::Read>(_reader: &mut R) -> std::io::Result<Self> {
    todo!()
  }
}

#[derive(Debug, Clone)]
pub(crate) struct FakeEventuality;

impl primitives::Eventuality for FakeEventuality {
  type OutputId = [u8; 32];

  fn id(&self) -> [u8; 32] {
    todo!()
  }

  fn lookup(&self) -> Vec<u8> {
    todo!()
  }

  fn singular_spent_output(&self) -> Option<Self::OutputId> {
    todo!()
  }

  fn read(_reader: &mut impl std::io::Read) -> std::io::Result<Self> {
    todo!()
  }

  fn write(&self, _writer: &mut impl std::io::Write) -> std::io::Result<()> {
    todo!()
  }
}

#[derive(Debug, Clone)]
pub(crate) struct FakeBlock;

impl primitives::Block for FakeBlock {
  type Header = FakeHeader;

  type Key = Key;

  type Address = FakeAddress;

  type Output = FakeOutput;

  type Eventuality = FakeEventuality;

  fn id(&self) -> [u8; 32] {
    todo!()
  }

  fn scan_for_outputs_unordered(
    &self,
    _latest_active_key: Self::Key,
    _key: Self::Key,
  ) -> Vec<Self::Output> {
    todo!()
  }

  fn check_for_eventuality_resolutions(
    &self,
    _eventualities: &mut primitives::EventualityTracker<Self::Eventuality>,
  ) -> std::collections::HashMap<
    <Self::Output as ReceivedOutput<Self::Key, Self::Address>>::TransactionId,
    Self::Eventuality,
  > {
    todo!()
  }
}

#[derive(Debug, Clone)]
pub(crate) struct FakeFeed;

impl ScannerFeed for FakeFeed {
  const NETWORK: ExternalNetworkId = ExternalNetworkId::Monero;

  const CONFIRMATIONS: u64 = 1;

  const WINDOW_LENGTH: u64 = 1;

  const TEN_MINUTES: u64 = 1;

  type Block = FakeBlock;

  type EphemeralError = ();

  fn latest_finalized_block_number(
    &self,
  ) -> impl Send + Future<Output = Result<u64, Self::EphemeralError>> {
    async { todo!() }
  }

  fn time_of_block(
    &self,
    _number: u64,
  ) -> impl Send + Future<Output = Result<u64, Self::EphemeralError>> {
    async { todo!() }
  }

  fn unchecked_block_header_by_number(
    &self,
    _number: u64,
  ) -> impl Send
  + Future<Output = Result<<Self::Block as primitives::Block>::Header, Self::EphemeralError>> {
    async { todo!() }
  }

  fn unchecked_block_by_number(
    &self,
    _number: u64,
  ) -> impl Send + Future<Output = Result<Self::Block, Self::EphemeralError>> {
    async { todo!() }
  }

  fn dust(_coin: ExternalCoin) -> Amount {
    Amount(10)
  }

  fn cost_to_aggregate(
    &self,
    _coin: ExternalCoin,
    _reference_block: &Self::Block,
  ) -> impl Send + Future<Output = Result<Amount, Self::EphemeralError>> {
    async { todo!() }
  }
}
