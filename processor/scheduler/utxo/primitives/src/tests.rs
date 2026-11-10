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

pub(crate) fn payment(address: u32, amount: u64) -> Payment<TestAddress> {
  Payment::new(
    TestAddress(address),
    ExternalBalance { amount: Amount(amount), coin: ExternalCoin::Monero },
  )
}

pub(crate) fn payments(qty: u32) -> Vec<Payment<TestAddress>> {
  let mut payments = Vec::with_capacity(qty.try_into().unwrap());

  for i in 0 .. qty {
    payments.push(payment(i, (100 * (i + 1)).into()));
  }

  payments
}

pub(crate) fn get_addresses_and_amounts(
  payments: &[Payment<TestAddress>],
) -> (Vec<TestAddress>, Vec<u64>) {
  let addresses = payments.iter().map(|p| p.address().clone()).collect();
  let amounts = payments.iter().map(|p| p.balance().amount.0).collect();

  (addresses, amounts)
}

#[derive(Clone, Debug, PartialEq, BorshSerialize, BorshDeserialize)]
pub(crate) struct TestAddress(pub(crate) u32);

impl fmt::Display for TestAddress {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(f, "test-{}", self.0)
  }
}

impl From<TestAddress> for ExternalAddress {
  fn from(value: TestAddress) -> Self {
    Self::try_from(value.0.to_le_bytes().to_vec()).unwrap()
  }
}

impl TryFrom<ExternalAddress> for TestAddress {
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
pub(crate) struct TestHeader;

impl primitives::BlockHeader for TestHeader {
  fn id(&self) -> [u8; 32] {
    todo!()
  }

  fn parent(&self) -> [u8; 32] {
    todo!()
  }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct TestOutput(pub(crate) u64);

impl ReceivedOutput<Key, TestAddress> for TestOutput {
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

  fn presumed_origin(&self) -> Option<TestAddress> {
    todo!()
  }

  fn balance(&self) -> ExternalBalance {
    ExternalBalance { coin: ExternalCoin::Monero, amount: Amount(self.0) }
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
pub(crate) struct TestEventuality;

impl primitives::Eventuality for TestEventuality {
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
pub(crate) struct TestBlock;

impl primitives::Block for TestBlock {
  type Header = TestHeader;

  type Key = Key;

  type Address = TestAddress;

  type Output = TestOutput;

  type Eventuality = TestEventuality;

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
pub(crate) struct TestFeed;

impl ScannerFeed for TestFeed {
  const NETWORK: ExternalNetworkId = ExternalNetworkId::Monero;

  const CONFIRMATIONS: u64 = 1;

  const WINDOW_LENGTH: u64 = 1;

  const TEN_MINUTES: u64 = 1;

  type Block = TestBlock;

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
pub(crate) struct TestTransaction;

impl scheduler_primitives::Transaction for TestTransaction {
  fn read(_reader: &mut impl io::Read) -> io::Result<Self> {
    todo!()
  }

  fn write(&self, _writer: &mut impl io::Write) -> io::Result<()> {
    todo!()
  }
}

#[derive(Clone)]
pub(crate) struct TestMessage;

impl Writable for TestMessage {
  fn write<W: io::Write>(&self, _writer: &mut W) -> io::Result<()> {
    todo!()
  }
}

pub(crate) struct TestSignatureMachine;

impl SignatureMachine<TestTransaction> for TestSignatureMachine {
  type SignatureShare = TestMessage;

  fn read_share<R: io::Read>(&self, _reader: &mut R) -> io::Result<Self::SignatureShare> {
    todo!()
  }

  fn complete(
    self,
    _shares: HashMap<Participant, Self::SignatureShare>,
  ) -> Result<TestTransaction, FrostError> {
    todo!()
  }
}

pub(crate) struct TestSignMachine;

impl SignMachine<TestTransaction> for TestSignMachine {
  type Params = ();

  type Keys = ();

  type Preprocess = TestMessage;

  type SignatureShare = TestMessage;

  type SignatureMachine = TestSignatureMachine;

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
pub(crate) struct TestPreprocessMachine;

impl PreprocessMachine for TestPreprocessMachine {
  type Preprocess = TestMessage;

  type Signature = TestTransaction;

  type SignMachine = TestSignMachine;

  fn preprocess<R: RngCore + CryptoRng>(
    self,
    _rng: &mut R,
  ) -> (Self::SignMachine, Self::Preprocess) {
    todo!()
  }
}

#[derive(Clone)]
pub(crate) struct TestSignableTransaction;

impl SignableTransaction for TestSignableTransaction {
  type Transaction = TestTransaction;

  type Ciphersuite = Ed25519;

  type PreprocessMachine = TestPreprocessMachine;

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

pub(crate) struct TestPlanner;

impl TransactionPlanner<TestFeed, ()> for TestPlanner {
  type EphemeralError = ();

  type SignableTransaction = TestSignableTransaction;

  const MAX_INPUTS: usize = 3;

  const MAX_OUTPUTS: usize = 3;

  fn branch_address(_key: Key) -> TestAddress {
    todo!()
  }

  fn change_address(_key: Key) -> TestAddress {
    todo!()
  }

  fn forwarding_address(_key: Key) -> TestAddress {
    todo!()
  }

  fn calculate_fee(
    &self,
    _reference_block: &BlockFor<TestFeed>,
    _inputs: Vec<OutputFor<TestFeed>>,
    payments: Vec<Payment<TestAddress>>,
    change: Option<KeyFor<TestFeed>>,
  ) -> impl Send + Future<Output = Result<Amount, Self::EphemeralError>> {
    let outputs_n = if change.is_some() { payments.len() + 1 } else { payments.len() };
    let fee: u64 = (outputs_n * 5 + 10).try_into().unwrap();

    async move { Ok(Amount(fee)) }
  }

  fn plan(
    &self,
    _reference_block: &BlockFor<TestFeed>,
    _inputs: Vec<OutputFor<TestFeed>>,
    _payments: Vec<Payment<AddressFor<TestFeed>>>,
    _change: Option<KeyFor<TestFeed>>,
  ) -> impl Send
  + Future<
    Output = Result<
      PlannedTransaction<TestFeed, Self::SignableTransaction, ()>,
      Self::EphemeralError,
    >,
  > {
    async {
      Ok(PlannedTransaction {
        signable: TestSignableTransaction,
        eventuality: TestEventuality,
        auxilliary: (),
      })
    }
  }
}
