use core::{fmt::Debug, time::Duration};
use std::{
  sync::Arc,
  collections::{HashSet, HashMap},
  io,
};

use async_trait::async_trait;

use ciphersuite::{group::GroupEncoding, Ciphersuite, Secp256k1};
use frost::ThresholdKeys;

use ethereum_serai::{
  alloy_core::primitives::U256,
  alloy_rpc_types::{BlockNumberOrTag, Transaction},
  alloy_simple_request_transport::SimpleRequest,
  alloy_rpc_client::ClientBuilder,
  alloy_provider::{Provider, RootProvider},
  crypto::{PublicKey, Signature},
  deployer::Deployer,
  router::{Router, InInstruction as EthereumInInstruction},
  machine::*,
};
#[cfg(test)]
use ethereum_serai::alloy_core::primitives::B256;

use tokio::{
  time::sleep,
  sync::{RwLock, RwLockReadGuard},
};

use serai_client::{
  primitives::{Coin, Balance, NetworkId},
  validator_sets::primitives::Session,
};

fn amount_to_serai_amount(coin: Coin, amount: U256) -> u64 {
  assert_eq!(coin.network(), NetworkId::Ethereum);
  assert_eq!(coin.decimals(), 8);
  // Remove 10 decimals so we go from 18 decimals to 8 decimals
  let divisor = U256::from(10_000_000_000u64);
  // This is valid up to 184b, which is assumed for the coins allowed
  u64::try_from(amount / divisor).unwrap()
}

fn balance_to_ethereum_amount(balance: Balance) -> U256 {
  assert_eq!(balance.coin.network(), NetworkId::Ethereum);
  assert_eq!(balance.coin.decimals(), 8);
  // Restore 10 decimals so we go from 8 decimals to 18 decimals
  let factor = U256::from(10_000_000_000u64);
  U256::from(balance.amount.0) * factor
}

use crate::{
  Db, Payment,
  networks::{
    OutputType, Output, Transaction as TransactionTrait, SignableTransaction, Block,
    Eventuality as EventualityTrait, EventualitiesTracker, NetworkError, Network,
  },
  key_gen::NetworkKeyDb,
  multisigs::scheduler::{
    Scheduler as SchedulerTrait,
    smart_contract::{Addendum, Scheduler},
  },
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
    ethereum_serai::alloy_core::primitives::Address::from(self.0).to_string()
  }
}

impl SignableTransaction for RouterCommand {
  fn fee(&self) -> u64 {
    // Return a fee of 0 as we'll handle amortization on our end
    0
  }
}

#[async_trait]
impl<D: Debug + Db> TransactionTrait<Ethereum<D>> for Transaction {
  type Id = [u8; 32];
  fn id(&self) -> Self::Id {
    self.hash.0
  }

  #[cfg(test)]
  async fn fee(&self, network: &Ethereum<D>) -> u64 {
    // Return a fee of 0 as we'll handle amortization on our end
    0
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
impl<D: Debug + Db> Block<Ethereum<D>> for Epoch {
  type Id = [u8; 32];
  fn id(&self) -> [u8; 32] {
    self.end_hash
  }
  fn parent(&self) -> [u8; 32] {
    self.prior_end_hash
  }
  async fn time(&self, _: &Ethereum<D>) -> u64 {
    self.time
  }
}

impl<D: Debug + Db> Output<Ethereum<D>> for EthereumInInstruction {
  type Id = [u8; 32];

  fn kind(&self) -> OutputType {
    OutputType::External
  }

  fn id(&self) -> Self::Id {
    let mut id = [0; 40];
    id[.. 32].copy_from_slice(&self.id.0);
    id[32 ..].copy_from_slice(&self.id.1.to_le_bytes());
    *ethereum_serai::alloy_core::primitives::keccak256(id)
  }
  fn tx_id(&self) -> [u8; 32] {
    self.id.0
  }
  fn key(&self) -> <Secp256k1 as Ciphersuite>::G {
    self.key_at_end_of_block
  }

  fn presumed_origin(&self) -> Option<Address> {
    Some(Address(self.from))
  }

  fn balance(&self) -> Balance {
    todo!("TODO")
  }
  fn data(&self) -> &[u8] {
    &self.data
  }

  fn write<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
    EthereumInInstruction::write(self, writer)
  }
  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    EthereumInInstruction::read(reader)
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
    Self { signature: sig.to_bytes() }
  }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Eventuality(PublicKey, RouterCommand);
impl EventualityTrait for Eventuality {
  type Claim = Claim;
  type Completion = SignedRouterCommand;

  fn lookup(&self) -> Vec<u8> {
    match self.1 {
      RouterCommand::UpdateSeraiKey { nonce, .. } => {
        let mut res = vec![0];
        res.extend(&*nonce.as_le_bytes());
        res
      }
      RouterCommand::Execute { nonce, .. } => {
        let mut res = vec![1];
        res.extend(&*nonce.as_le_bytes());
        res
      }
    }
  }

  fn read<R: io::Read>(reader: &mut R) -> io::Result<Self> {
    let point = Secp256k1::read_G(reader)?;
    let command = RouterCommand::read(reader)?;
    Ok(Eventuality(
      PublicKey::new(point).ok_or(io::Error::other("unusable key within Eventuality"))?,
      command,
    ))
  }
  fn serialize(&self) -> Vec<u8> {
    let mut res = vec![];
    res.extend(self.0.point().to_bytes().as_slice());
    self.1.write(&mut res).unwrap();
    res
  }

  fn claim(completion: &Self::Completion) -> Self::Claim {
    Claim::from(completion.signature())
  }
  fn serialize_completion(completion: &Self::Completion) -> Vec<u8> {
    let mut res = vec![];
    completion.write(&mut res).unwrap();
    res
  }
  fn read_completion<R: io::Read>(reader: &mut R) -> io::Result<Self::Completion> {
    SignedRouterCommand::read(reader)
  }
}

#[derive(Clone, Debug)]
pub struct Ethereum<D: Debug + Db> {
  // This DB is solely used to access the first key generated, as needed to determine the Router's
  // address. Accordingly, all methods present are consistent to a Serai chain with a finalized
  // first key (regardless of local state), and this is safe.
  db: D,
  provider: Arc<RootProvider<SimpleRequest>>,
  deployer: Deployer,
  router: Arc<RwLock<Option<Router>>>,
}
impl<D: Debug + Db> PartialEq for Ethereum<D> {
  fn eq(&self, _other: &Ethereum<D>) -> bool {
    true
  }
}
impl<D: Debug + Db> Ethereum<D> {
  pub async fn new(db: D, url: String) -> Self {
    let provider = Arc::new(RootProvider::new(
      ClientBuilder::default().transport(SimpleRequest::new(url), true),
    ));

    let mut deployer = Deployer::new(provider.clone()).await;
    while !matches!(deployer, Ok(Some(_))) {
      log::error!("Deployer wasn't deployed yet or networking error");
      sleep(Duration::from_secs(5)).await;
      deployer = Deployer::new(provider.clone()).await;
    }
    let deployer = deployer.unwrap().unwrap();

    Ethereum { db, provider, deployer, router: Arc::new(RwLock::new(None)) }
  }

  pub async fn router(&self) -> RwLockReadGuard<'_, Option<Router>> {
    // If we've already instantiated the Router, return a read reference
    {
      let router = self.router.read().await;
      if router.is_some() {
        return router;
      }
    }

    // Instantiate it
    let mut router = self.router.write().await;
    // If another attempt beat us to it, return
    if router.is_some() {
      drop(router);
      return self.router.read().await;
    }

    // Get the first key from the DB
    let first_key =
      NetworkKeyDb::get(&self.db, Session(0)).expect("getting outputs before confirming a key");
    let key = Secp256k1::read_G(&mut first_key.as_slice()).unwrap();
    let public_key = PublicKey::new(key).unwrap();

    // Find the router
    let mut found = self.deployer.find_router(self.provider.clone(), &public_key).await;
    while !matches!(found, Ok(Some(_))) {
      log::error!("Router wasn't deployed yet or networking error");
      sleep(Duration::from_secs(5)).await;
      found = self.deployer.find_router(self.provider.clone(), &public_key).await;
    }

    // Set it
    *router = Some(found.unwrap().unwrap());

    // Downgrade to a read lock
    // Explicitly doesn't use `downgrade` so that another pending write txn can realize it's no
    // longer necessary
    drop(router);
    self.router.read().await
  }
}

#[async_trait]
impl<D: Debug + Db> Network for Ethereum<D> {
  type Curve = Secp256k1;

  type Transaction = Transaction;
  type Block = Epoch;

  type Output = EthereumInInstruction;
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

  // TODO: usize::max, with a merkle tree in the router
  const MAX_OUTPUTS: usize = 256;

  fn tweak_keys(keys: &mut ThresholdKeys<Self::Curve>) {
    while PublicKey::new(keys.group_key()).is_none() {
      *keys = keys.offset(<Secp256k1 as Ciphersuite>::F::ONE);
    }
  }

  #[cfg(test)]
  async fn external_address(&self, key: <Secp256k1 as Ciphersuite>::G) -> Address {
    Address(self.router().await.as_ref().unwrap().address())
  }

  fn branch_address(key: <Secp256k1 as Ciphersuite>::G) -> Option<Address> {
    None
  }

  fn change_address(key: <Secp256k1 as Ciphersuite>::G) -> Option<Address> {
    None
  }

  fn forward_address(key: <Secp256k1 as Ciphersuite>::G) -> Option<Address> {
    None
  }

  async fn get_latest_block_number(&self) -> Result<usize, NetworkError> {
    let actual_number = self
      .provider
      .get_block(BlockNumberOrTag::Finalized.into(), false)
      .await
      .map_err(|_| NetworkError::ConnectionError)?
      .expect("no blocks were finalized")
      .header
      .number
      .unwrap();
    // Error if there hasn't been a full epoch yet
    if actual_number < 32 {
      Err(NetworkError::ConnectionError)?
    }
    // If this is 33, the division will return 1, yet 1 is the epoch in progress
    let latest_full_epoch = (actual_number / 32).saturating_sub(1);
    Ok(latest_full_epoch.try_into().unwrap())
  }

  async fn get_block(&self, number: usize) -> Result<Self::Block, NetworkError> {
    let latest_finalized = self.get_latest_block_number().await?;
    if number > latest_finalized {
      Err(NetworkError::ConnectionError)?
    }

    let start = number * 32;
    let prior_end_hash = if start == 0 {
      [0; 32]
    } else {
      self
        .provider
        .get_block(u64::try_from(start - 1).unwrap().into(), false)
        .await
        .ok()
        .flatten()
        .ok_or(NetworkError::ConnectionError)?
        .header
        .hash
        .unwrap()
        .into()
    };

    let end_header = self
      .provider
      .get_block(u64::try_from(start + 31).unwrap().into(), false)
      .await
      .ok()
      .flatten()
      .ok_or(NetworkError::ConnectionError)?
      .header;

    let end_hash = end_header.hash.unwrap().into();
    let time = end_header.timestamp.try_into().unwrap();

    Ok(Epoch { prior_end_hash, start: start.try_into().unwrap(), end_hash, time })
  }

  async fn get_outputs(
    &self,
    block: &Self::Block,
    _: <Secp256k1 as Ciphersuite>::G,
  ) -> Vec<Self::Output> {
    let router = self.router().await;
    let router = router.as_ref().unwrap();

    let mut all_events = vec![];
    for block in block.start .. (block.start + 32) {
      let mut events = router.in_instructions(block, &HashSet::new()).await; // TODO re: tokens
      while let Err(e) = events {
        log::error!("couldn't connect to Ethereum node for the Router's events: {e:?}");
        sleep(Duration::from_secs(5)).await;
        events = router.in_instructions(block, &HashSet::new()).await; // TODO re: tokens
      }
      all_events.extend(events.unwrap());
    }
    all_events
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
    // Claim no fee is needed so we can perform amortization ourselves
    Ok(Some(0))
  }

  async fn signable_transaction(
    &self,
    block_number: usize,
    _plan_id: &[u8; 32],
    key: <Self::Curve as Ciphersuite>::G,
    inputs: &[Self::Output],
    payments: &[Payment<Self>],
    change: &Option<Self::Address>,
    scheduler_addendum: &<Self::Scheduler as SchedulerTrait<Self>>::Addendum,
  ) -> Result<Option<(Self::SignableTransaction, Self::Eventuality)>, NetworkError> {
    assert_eq!(inputs.len(), 0);
    assert!(change.is_none());
    let chain_id = self.provider.get_chain_id().await.map_err(|_| NetworkError::ConnectionError)?;

    // TODO: Perform fee amortization (in scheduler?
    // TODO: Make this function internal and have needed_fee properly return None as expected?
    // TODO: signable_transaction is written as cannot return None if needed_fee returns Some
    // TODO: Why can this return None at all if it isn't allowed to return None?

    let command = match scheduler_addendum {
      Addendum::Nonce(nonce) => RouterCommand::Execute {
        chain_id: U256::try_from(chain_id).unwrap(),
        nonce: U256::try_from(*nonce).unwrap(),
        outs: payments
          .iter()
          .filter_map(|payment| {
            Some(OutInstruction {
              target: if let Some(data) = payment.data.as_ref() {
                // This introspects the Call serialization format, expecting the first 20 bytes to
                // be the address
                // This avoids wasting the 20-bytes allocated within address
                let full_data = [payment.address.0.as_slice(), data].concat();
                let mut reader = full_data.as_slice();

                let mut calls = vec![];
                while !reader.is_empty() {
                  calls.push(Call::read(&mut reader).ok()?)
                }
                // The above must have executed at least once since reader contains the address
                assert_eq!(calls[0].to, payment.address.0);

                OutInstructionTarget::Calls(calls)
              } else {
                OutInstructionTarget::Direct(payment.address.0)
              },
              value: {
                assert_eq!(payment.balance.coin, Coin::Ether); // TODO
                balance_to_ethereum_amount(payment.balance)
              },
            })
          })
          .collect(),
      },
      Addendum::RotateTo { nonce, new_key } => {
        assert!(payments.is_empty());
        RouterCommand::UpdateSeraiKey {
          chain_id: U256::try_from(chain_id).unwrap(),
          nonce: U256::try_from(*nonce).unwrap(),
          key: PublicKey::new(*new_key).expect("new key wasn't a valid ETH public key"),
        }
      }
    };
    Ok(Some((
      command.clone(),
      Eventuality(PublicKey::new(key).expect("key wasn't a valid ETH public key"), command),
    )))
  }

  async fn attempt_sign(
    &self,
    keys: ThresholdKeys<Self::Curve>,
    transaction: Self::SignableTransaction,
  ) -> Result<Self::TransactionMachine, NetworkError> {
    Ok(
      RouterCommandMachine::new(keys, transaction)
        .expect("keys weren't usable to sign router commands"),
    )
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
    Ok(SignedRouterCommand::new(&eventuality.0, eventuality.1.clone(), &claim.signature))
  }

  #[cfg(test)]
  async fn get_block_number(&self, id: &<Self::Block as Block<Self>>::Id) -> usize {
    self
      .provider
      .get_block(B256::from(*id).into(), false)
      .await
      .unwrap()
      .unwrap()
      .header
      .number
      .unwrap()
      .try_into()
      .unwrap()
  }

  #[cfg(test)]
  async fn check_eventuality_by_claim(
    &self,
    eventuality: &Self::Eventuality,
    claim: &<Self::Eventuality as EventualityTrait>::Claim,
  ) -> bool {
    SignedRouterCommand::new(&eventuality.0, eventuality.1.clone(), &claim.signature).is_some()
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
    // anvil_mine
    todo!("TODO")
  }

  #[cfg(test)]
  async fn test_send(&self, key: Self::Address) -> Self::Block {
    todo!("TODO")
  }
}
