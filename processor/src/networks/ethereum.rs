use core::time::Duration;
use std::{sync::Arc, collections::HashMap, io};

use async_trait::async_trait;

use k256::ProjectivePoint;
use ciphersuite::{group::ff::PrimeField, Ciphersuite, Secp256k1};
use frost::ThresholdKeys;

use ethereum_serai::{
  ethers_core::types::Transaction,
  ethers_providers::{Http, Provider},
  crypto::{PublicKey, Signature},
  machine::*,
};

use tokio::time::sleep;

use serai_client::primitives::{Coin, Amount, Balance, NetworkId};

use crate::{
  Payment,
  networks::{
    OutputType, Output, Transaction as TransactionTrait, SignableTransaction, Block,
    Eventuality as EventualityTrait, EventualitiesTracker, NetworkError, Network,
  },
  multisigs::scheduler::account::{Nonce, RotateTo, Scheduler},
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Address(pub [u8; 20]);
impl TryFrom<Vec<u8>> for Address {
  type Error = ();
  fn try_from(bytes: Vec<u8>) -> Result<Address, ()> {
    if bytes.len() != 20 {
      Err(())?;
    }
    let mut res = [0; 20];
    res.copy_from_slice(&bytes);
    Ok(Address(res))
  }
}
impl TryInto<Vec<u8>> for Address {
  type Error = ();
  fn try_into(self) -> Result<Vec<u8>, ()> {
    Ok(self.0.to_vec())
  }
}
impl ToString for Address {
  fn to_string(&self) -> String {
    ethereum_serai::ethers_core::types::H160(self.0).to_string()
  }
}

impl SignableTransaction for RouterCommand {
  fn fee(&self) -> u64 {
    todo!("TODO")
  }
}

#[async_trait]
impl TransactionTrait<Ethereum> for Transaction {
  type Id = [u8; 32];
  fn id(&self) -> Self::Id {
    self.hash.0
  }

  // TODO: Move to Balance
  #[cfg(test)]
  async fn fee(&self, network: &Ethereum) -> u64 {
    todo!("TODO")
  }
}

// We use 32-block Epochs to represent blocks.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Epoch {
  // The hash of the block which ended the prior Epoch.
  prior_end_hash: [u8; 32],
  // The first block number within this Epoch.
  start: u64,
  // The hash of the last block within this Epoch.
  end_hash: [u8; 32],
  // The monotonic time for this Epoch.
  time: u64,
}
#[async_trait]
impl Block<Ethereum> for Epoch {
  type Id = [u8; 32];
  fn id(&self) -> [u8; 32] {
    self.end_hash
  }
  fn parent(&self) -> [u8; 32] {
    self.prior_end_hash
  }
  async fn time(&self, _: &Ethereum) -> u64 {
    self.time
  }
}

// Taking the role of an Output, this is an Input, an instruction easiest to cram into here,
// and an actual received Output.
// TODO: Extend Plan such that this isn't needed
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum MetaEvent {
  NonceToUse(u64),
  RotateTo(ProjectivePoint),
  EmittedEvent { tx: [u8; 32], balance: Balance },
}
impl From<Nonce> for MetaEvent {
  fn from(nonce: Nonce) -> MetaEvent {
    MetaEvent::NonceToUse(nonce.0)
  }
}
impl From<RotateTo<Ethereum>> for MetaEvent {
  fn from(rotate_to: RotateTo<Ethereum>) -> MetaEvent {
    MetaEvent::RotateTo(rotate_to.0)
  }
}
impl Output<Ethereum> for MetaEvent {
  type Id = [u8; 32];

  fn kind(&self) -> OutputType {
    OutputType::External
  }

  fn id(&self) -> Self::Id {
    todo!("TODO")
  }
  fn tx_id(&self) -> [u8; 32] {
    match self {
      MetaEvent::NonceToUse(_) => {
        panic!("requesting the tx_id of an input we use to pass messages (NonceToUse)")
      }
      MetaEvent::RotateTo(_) => {
        panic!("requesting the tx_id of an input we use to pass messages (RotateTo)")
      }
      MetaEvent::EmittedEvent { tx, .. } => *tx,
    }
  }
  fn key(&self) -> <Secp256k1 as Ciphersuite>::G {
    todo!("TODO")
  }

  fn presumed_origin(&self) -> Option<Address> {
    todo!("TODO")
  }

  fn balance(&self) -> Balance {
    match self {
      MetaEvent::NonceToUse(_) | MetaEvent::RotateTo(_) => {
        Balance { coin: Coin::Ether, amount: Amount(0) }
      }
      MetaEvent::EmittedEvent { balance, .. } => *balance,
    }
  }
  fn data(&self) -> &[u8] {
    todo!("TODO")
  }

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    todo!("TODO")
  }
  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    todo!("TODO")
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Claim {
  signature: [u8; 64],
}
impl AsRef<[u8]> for Claim {
  fn as_ref(&self) -> &[u8] {
    &self.signature
  }
}
impl AsMut<[u8]> for Claim {
  fn as_mut(&mut self) -> &mut [u8] {
    &mut self.signature
  }
}
impl Default for Claim {
  fn default() -> Self {
    Self { signature: [0; 64] }
  }
}
impl From<&Signature> for Claim {
  fn from(sig: &Signature) -> Self {
    let mut res = Self::default();
    res.signature[.. 32].copy_from_slice(sig.c().to_repr().as_ref());
    res.signature[32 ..].copy_from_slice(sig.s().to_repr().as_ref());
    res
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Eventuality(RouterCommand);
impl EventualityTrait for Eventuality {
  type Claim = Claim;
  type Completion = SignedRouterCommand;

  fn lookup(&self) -> Vec<u8> {
    todo!("TODO")
  }

  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    todo!("TODO")
  }
  fn serialize(&self) -> Vec<u8> {
    todo!("TODO")
  }

  fn claim(completion: &Self::Completion) -> Self::Claim {
    Claim::from(completion.signature())
  }
  fn serialize_completion(completion: &Self::Completion) -> Vec<u8> {
    todo!("TODO")
  }
  fn read_completion<R: io::Read>(completion: &mut R) -> io::Result<Self::Completion> {
    todo!("TODO")
  }
}

#[derive(Clone, Debug)]
pub struct Ethereum {
  provider: Arc<Provider<Http>>,
}
impl PartialEq for Ethereum {
  fn eq(&self, _other: &Ethereum) -> bool {
    true
  }
}
impl Ethereum {
  pub async fn new(url: String) -> Ethereum {
    let mut provider = Provider::<Http>::try_from(&url);
    while let Err(e) = provider {
      log::error!("couldn't connect to Ethereum node: {e:?}");
      sleep(Duration::from_secs(5)).await;
      provider = Provider::<Http>::try_from(&url);
    }
    Ethereum { provider: Arc::new(provider.unwrap()) }
  }
}

#[async_trait]
impl Network for Ethereum {
  type Curve = Secp256k1;

  type Transaction = Transaction;
  type Block = Epoch;

  type Output = MetaEvent;
  type SignableTransaction = RouterCommand;
  type Eventuality = Eventuality;
  type TransactionMachine = RouterCommandMachine;

  type Scheduler = Scheduler<Self>;

  type Address = Address;

  const NETWORK: NetworkId = NetworkId::Ethereum;
  const ID: &'static str = "Ethereum";
  const ESTIMATED_BLOCK_TIME_IN_SECONDS: usize = 32 * 12;
  const CONFIRMATIONS: usize = 1;

  const DUST: u64 = 0; // TODO

  const COST_TO_AGGREGATE: u64 = 0;

  const MAX_INPUTS: usize = 1;
  const MAX_OUTPUTS: usize = 256;

  fn tweak_keys(keys: &mut ThresholdKeys<Self::Curve>) {
    while PublicKey::new(keys.group_key()).is_none() {
      *keys = keys.offset(<Secp256k1 as Ciphersuite>::F::ONE);
    }
  }

  fn external_address(_: <Secp256k1 as Ciphersuite>::G) -> Self::Address {
    Address([0; 20])
  }

  fn branch_address(_: <Secp256k1 as Ciphersuite>::G) -> Self::Address {
    Address([0; 20])
  }

  fn change_address(_: <Secp256k1 as Ciphersuite>::G) -> Self::Address {
    Address([0; 20])
  }

  fn forward_address(_: <Secp256k1 as Ciphersuite>::G) -> Self::Address {
    Address([0; 20])
  }

  async fn get_latest_block_number(&self) -> Result<usize, NetworkError> {
    todo!("TODO")
  }

  async fn get_block(&self, number: usize) -> Result<Self::Block, NetworkError> {
    todo!("TODO")
  }

  async fn get_outputs(
    &self,
    block: &Self::Block,
    key: <Secp256k1 as Ciphersuite>::G,
  ) -> Vec<Self::Output> {
    todo!("TODO")
  }

  async fn get_eventuality_completions(
    &self,
    eventualities: &mut EventualitiesTracker<Self::Eventuality>,
    block: &Self::Block,
  ) -> HashMap<
    [u8; 32],
    (
      usize,
      <Self::Transaction as TransactionTrait<Self>>::Id,
      <Self::Eventuality as EventualityTrait>::Completion,
    ),
  > {
    todo!("TODO")
  }

  async fn needed_fee(
    &self,
    block_number: usize,
    _: &[u8; 32],
    inputs: &[Self::Output],
    payments: &[Payment<Self>],
    change: &Option<Self::Address>,
  ) -> Result<Option<u64>, NetworkError> {
    todo!("TODO")
  }

  async fn signable_transaction(
    &self,
    block_number: usize,
    plan_id: &[u8; 32],
    inputs: &[Self::Output],
    payments: &[Payment<Self>],
    change: &Option<Self::Address>,
  ) -> Result<Option<(Self::SignableTransaction, Self::Eventuality)>, NetworkError> {
    todo!("TODO")
  }

  async fn attempt_sign(
    &self,
    keys: ThresholdKeys<Self::Curve>,
    transaction: Self::SignableTransaction,
  ) -> Result<Self::TransactionMachine, NetworkError> {
    todo!("TODO")
  }

  async fn publish_completion(
    &self,
    completion: &<Self::Eventuality as EventualityTrait>::Completion,
  ) -> Result<(), NetworkError> {
    todo!("TODO")
  }

  async fn confirm_completion(
    &self,
    eventuality: &Self::Eventuality,
    claim: &<Self::Eventuality as EventualityTrait>::Claim,
  ) -> Result<Option<<Self::Eventuality as EventualityTrait>::Completion>, NetworkError> {
    todo!("TODO")
  }

  #[cfg(test)]
  async fn get_block_number(&self, id: &<Self::Block as Block<Self>>::Id) -> usize {
    todo!("TODO")
  }

  #[cfg(test)]
  async fn check_eventuality_by_claim(
    &self,
    eventuality: &Self::Eventuality,
    claim: &<Self::Eventuality as EventualityTrait>::Claim,
  ) -> bool {
    todo!("TODO")
  }

  #[cfg(test)]
  async fn get_transaction_by_eventuality(
    &self,
    block: usize,
    eventuality: &Self::Eventuality,
  ) -> Self::Transaction {
    todo!("TODO")
  }

  #[cfg(test)]
  async fn mine_block(&self) {
    todo!("TODO")
  }

  #[cfg(test)]
  async fn test_send(&self, key: Self::Address) -> Self::Block {
    todo!("TODO")
  }
}
