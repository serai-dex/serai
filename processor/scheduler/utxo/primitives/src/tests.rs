use core::fmt;
use std::{collections::HashMap, io};

use borsh::{BorshSerialize, BorshDeserialize};

use ciphersuite::WrappedGroup;
use dalek_ff_group::Ed25519;
use frost::{
  FrostError, Participant, ThresholdKeys,
  sign::{CachedPreprocess, PreprocessMachine, SignMachine, SignatureMachine, Writable},
};
use primitives::{Payment, ReceivedOutput};
use rand_core::{CryptoRng, RngCore};
use scanner::{AddressFor, BlockFor, KeyFor, OutputFor, ScannerFeed};
use scheduler_primitives::SignableTransaction;
use serai_primitives::{
  address::ExternalAddress,
  balance::{Amount, ExternalBalance},
  coin::ExternalCoin,
  network_id::ExternalNetworkId,
};

use crate::{PlannedTransaction, TransactionPlanner};

pub(crate) fn payment(address: u32, amount: u64) -> Payment<FakeAddress> {
  Payment::new(
    FakeAddress(address),
    ExternalBalance { amount: Amount(amount), coin: ExternalCoin::Monero },
  )
}

pub(crate) fn get_addresses_and_amounts(
  payments: &[Payment<FakeAddress>],
) -> (Vec<FakeAddress>, Vec<u64>) {
  let addresses = payments.iter().map(|p| p.address().clone()).collect();
  let amounts = payments.iter().map(|p| p.balance().amount.0).collect();

  (addresses, amounts)
}

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

  fn write<W: io::Write>(&self, _writer: &mut W) -> io::Result<()> {
    todo!()
  }

  fn read<R: io::Read>(_reader: &mut R) -> io::Result<Self> {
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

  fn read(_reader: &mut impl io::Read) -> io::Result<Self> {
    todo!()
  }

  fn write(&self, _writer: &mut impl io::Write) -> io::Result<()> {
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
  ) -> HashMap<
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

#[derive(Debug, Clone)]
pub(crate) struct FakeTransaction;

impl scheduler_primitives::Transaction for FakeTransaction {
  fn read(_reader: &mut impl io::Read) -> io::Result<Self> {
    todo!()
  }

  fn write(&self, _writer: &mut impl io::Write) -> io::Result<()> {
    todo!()
  }
}

#[derive(Clone)]
pub(crate) struct FakeMessage;

impl Writable for FakeMessage {
  fn write<W: io::Write>(&self, _writer: &mut W) -> io::Result<()> {
    todo!()
  }
}

pub(crate) struct FakeSignatureMachine;

impl SignatureMachine<FakeTransaction> for FakeSignatureMachine {
  type SignatureShare = FakeMessage;

  fn read_share<R: io::Read>(&self, _reader: &mut R) -> io::Result<Self::SignatureShare> {
    todo!()
  }

  fn complete(
    self,
    _shares: HashMap<Participant, Self::SignatureShare>,
  ) -> Result<FakeTransaction, FrostError> {
    todo!()
  }
}

pub(crate) struct FakeSignMachine;

impl SignMachine<FakeTransaction> for FakeSignMachine {
  type Params = ();

  type Keys = ();

  type Preprocess = FakeMessage;

  type SignatureShare = FakeMessage;

  type SignatureMachine = FakeSignatureMachine;

  fn cache(self) -> CachedPreprocess {
    todo!()
  }

  fn from_cache(
    _params: Self::Params,
    _keys: Self::Keys,
    _cache: CachedPreprocess,
  ) -> (Self, Self::Preprocess) {
    todo!()
  }

  fn read_preprocess<R: io::Read>(&self, _reader: &mut R) -> io::Result<Self::Preprocess> {
    todo!()
  }

  fn sign(
    self,
    _commitments: HashMap<Participant, Self::Preprocess>,
    _msg: &[u8],
  ) -> Result<(Self::SignatureMachine, Self::SignatureShare), FrostError> {
    todo!()
  }
}

#[derive(Clone)]
pub(crate) struct FakePreprocessMachine;

impl PreprocessMachine for FakePreprocessMachine {
  type Preprocess = FakeMessage;

  type Signature = FakeTransaction;

  type SignMachine = FakeSignMachine;

  fn preprocess<R: RngCore + CryptoRng>(
    self,
    _rng: &mut R,
  ) -> (Self::SignMachine, Self::Preprocess) {
    todo!()
  }
}

#[derive(Clone)]
pub(crate) struct FakeSignableTransaction;

impl SignableTransaction for FakeSignableTransaction {
  type Transaction = FakeTransaction;

  type Ciphersuite = Ed25519;

  type PreprocessMachine = FakePreprocessMachine;

  fn read(_reader: &mut impl io::Read) -> io::Result<Self> {
    todo!()
  }

  fn write(&self, _writer: &mut impl io::Write) -> io::Result<()> {
    todo!()
  }

  fn id(&self) -> [u8; 32] {
    todo!()
  }

  fn sign(self, _keys: ThresholdKeys<Self::Ciphersuite>) -> Self::PreprocessMachine {
    todo!()
  }
}

pub(crate) struct FakePlanner;

impl TransactionPlanner<FakeFeed, ()> for FakePlanner {
  type EphemeralError = ();

  type SignableTransaction = FakeSignableTransaction;

  const MAX_INPUTS: usize = 3;

  const MAX_OUTPUTS: usize = 3;

  fn branch_address(_key: Key) -> FakeAddress {
    todo!()
  }

  fn change_address(_key: Key) -> FakeAddress {
    todo!()
  }

  fn forwarding_address(_key: Key) -> FakeAddress {
    todo!()
  }

  fn calculate_fee(
    &self,
    _reference_block: &BlockFor<FakeFeed>,
    _inputs: Vec<OutputFor<FakeFeed>>,
    _payments: Vec<Payment<FakeAddress>>,
    _change: Option<KeyFor<FakeFeed>>,
  ) -> impl Send + Future<Output = Result<Amount, Self::EphemeralError>> {
    async { todo!() }
  }

  fn plan(
    &self,
    _reference_block: &BlockFor<FakeFeed>,
    _inputs: Vec<OutputFor<FakeFeed>>,
    _payments: Vec<Payment<AddressFor<FakeFeed>>>,
    _change: Option<KeyFor<FakeFeed>>,
  ) -> impl Send
  + Future<
    Output = Result<
      PlannedTransaction<FakeFeed, Self::SignableTransaction, ()>,
      Self::EphemeralError,
    >,
  > {
    async { todo!() }
  }
}
