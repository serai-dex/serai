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
  router::{Router, Coin as EthereumCoin, InInstruction as EthereumInInstruction},
  machine::*,
};
#[cfg(test)]
use ethereum_serai::alloy_core::primitives::B256;

use tokio::{
  time::sleep,
  sync::{RwLock, RwLockReadGuard},
};

use serai_client::{
  primitives::{Coin, Amount, Balance, NetworkId},
  validator_sets::primitives::Session,
};

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

#[cfg(not(test))]
const DAI: [u8; 20] =
  match const_hex::const_decode_to_array(b"0x6B175474E89094C44Da98b954EedeAC495271d0F") {
    Ok(res) => res,
    Err(_) => panic!("invalid non-test DAI hex address"),
  };
#[cfg(test)] // TODO
const DAI: [u8; 20] =
  match const_hex::const_decode_to_array(b"0000000000000000000000000000000000000000") {
    Ok(res) => res,
    Err(_) => panic!("invalid test DAI hex address"),
  };

fn coin_to_serai_coin(coin: &EthereumCoin) -> Option<Coin> {
  match coin {
    EthereumCoin::Ether => Some(Coin::Ether),
    EthereumCoin::Erc20(token) => {
      if *token == DAI {
        return Some(Coin::Dai);
      }
      None
    }
  }
}

fn amount_to_serai_amount(coin: Coin, amount: U256) -> Amount {
  assert_eq!(coin.network(), NetworkId::Ethereum);
  assert_eq!(coin.decimals(), 8);
  // Remove 10 decimals so we go from 18 decimals to 8 decimals
  let divisor = U256::from(10_000_000_000u64);
  // This is valid up to 184b, which is assumed for the coins allowed
  Amount(u64::try_from(amount / divisor).unwrap())
}

fn balance_to_ethereum_amount(balance: Balance) -> U256 {
  assert_eq!(balance.coin.network(), NetworkId::Ethereum);
  assert_eq!(balance.coin.decimals(), 8);
  // Restore 10 decimals so we go from 8 decimals to 18 decimals
  let factor = U256::from(10_000_000_000u64);
  U256::from(balance.amount.0) * factor
}

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
  async fn fee(&self, _network: &Ethereum<D>) -> u64 {
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

impl Epoch {
  fn end(&self) -> u64 {
    self.start + 31
  }
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
    let coin = coin_to_serai_coin(&self.coin).unwrap_or_else(|| {
      panic!(
        "requesting coin for an EthereumInInstruction with a coin {}",
        "we don't handle. this never should have been yielded"
      )
    });
    Balance { coin, amount: amount_to_serai_amount(coin, self.amount) }
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
      RouterCommand::UpdateSeraiKey { nonce, .. } | RouterCommand::Execute { nonce, .. } => {
        nonce.as_le_bytes().to_vec()
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

    #[cfg(test)] // TODO: Move to test code
    provider.raw_request::<_, ()>("evm_setAutomine".into(), false).await.unwrap();

    let mut deployer = Deployer::new(provider.clone()).await;
    while !matches!(deployer, Ok(Some(_))) {
      log::error!("Deployer wasn't deployed yet or networking error");
      sleep(Duration::from_secs(5)).await;
      deployer = Deployer::new(provider.clone()).await;
    }
    let deployer = deployer.unwrap().unwrap();

    Ethereum { db, provider, deployer, router: Arc::new(RwLock::new(None)) }
  }

  // Obtain a reference to the Router, sleeping until it's deployed if it hasn't already been.
  // This is guaranteed to return Some.
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
  async fn external_address(&self, _key: <Secp256k1 as Ciphersuite>::G) -> Address {
    Address(self.router().await.as_ref().unwrap().address())
  }

  fn branch_address(_key: <Secp256k1 as Ciphersuite>::G) -> Option<Address> {
    None
  }

  fn change_address(_key: <Secp256k1 as Ciphersuite>::G) -> Option<Address> {
    None
  }

  fn forward_address(_key: <Secp256k1 as Ciphersuite>::G) -> Option<Address> {
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
    let time = end_header.timestamp;

    Ok(Epoch { prior_end_hash, start: start.try_into().unwrap(), end_hash, time })
  }

  async fn get_outputs(
    &self,
    block: &Self::Block,
    _: <Secp256k1 as Ciphersuite>::G,
  ) -> Vec<Self::Output> {
    let router = self.router().await;
    let router = router.as_ref().unwrap();

    // TODO: Top-level transfers

    let mut all_events = vec![];
    for block in block.start .. (block.start + 32) {
      let mut events = router.in_instructions(block, &HashSet::from([DAI])).await;
      while let Err(e) = events {
        log::error!("couldn't connect to Ethereum node for the Router's events: {e:?}");
        sleep(Duration::from_secs(5)).await;
        events = router.in_instructions(block, &HashSet::from([DAI])).await;
      }
      all_events.extend(events.unwrap());
    }

    for event in &all_events {
      assert!(
        coin_to_serai_coin(&event.coin).is_some(),
        "router yielded events for unrecognized coins"
      );
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
    let mut res = HashMap::new();
    if eventualities.map.is_empty() {
      return res;
    }

    let router = self.router().await;
    let router = router.as_ref().unwrap();

    let past_scanned_epoch = loop {
      match self.get_block(eventualities.block_number).await {
        Ok(block) => break block,
        Err(e) => log::error!("couldn't get the last scanned block in the tracker: {}", e),
      }
      sleep(Duration::from_secs(10)).await;
    };
    assert_eq!(
      past_scanned_epoch.start / 32,
      u64::try_from(eventualities.block_number).unwrap(),
      "assumption of tracker block number's relation to epoch start is incorrect"
    );

    // Iterate from after the epoch number in the tracker to the end of this epoch
    for block_num in (past_scanned_epoch.end() + 1) ..= block.end() {
      let executed = loop {
        match router.executed_commands(block_num).await {
          Ok(executed) => break executed,
          Err(e) => log::error!("couldn't get the executed commands in block {block_num}: {e}"),
        }
        sleep(Duration::from_secs(10)).await;
      };

      for executed in executed {
        let lookup = executed.nonce.to_le_bytes().to_vec();
        if let Some((plan_id, eventuality)) = eventualities.map.get(&lookup) {
          if let Some(command) =
            SignedRouterCommand::new(&eventuality.0, eventuality.1.clone(), &executed.signature)
          {
            res.insert(*plan_id, (block_num.try_into().unwrap(), executed.tx_id, command));
            eventualities.map.remove(&lookup);
          }
        }
      }
    }
    eventualities.block_number = (block.start / 32).try_into().unwrap();

    res
  }

  async fn needed_fee(
    &self,
    _block_number: usize,
    inputs: &[Self::Output],
    _payments: &[Payment<Self>],
    _change: &Option<Self::Address>,
  ) -> Result<Option<u64>, NetworkError> {
    assert_eq!(inputs.len(), 0);
    // Claim no fee is needed so we can perform amortization ourselves
    Ok(Some(0))
  }

  async fn signable_transaction(
    &self,
    _block_number: usize,
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
    // Publish this to the dedicated TX server for a solver to actually publish
    #[cfg(not(test))]
    {
      let _ = completion;
      todo!("TODO");
    }

    // Publish this using a dummy account we fund with magic RPC commands
    #[cfg(test)]
    {
      use rand_core::OsRng;
      use ciphersuite::group::ff::Field;

      let key = <Secp256k1 as Ciphersuite>::F::random(&mut OsRng);
      let address = ethereum_serai::crypto::address(&(Secp256k1::generator() * key));

      // Set a 1.1 ETH balance
      self
        .provider
        .raw_request::<_, ()>(
          "anvil_setBalance".into(),
          [Address(address).to_string(), "1100000000000000000".into()],
        )
        .await
        .unwrap();

      let router = self.router().await;
      let router = router.as_ref().unwrap();

      let mut tx = match completion.command() {
        RouterCommand::UpdateSeraiKey { key, .. } => {
          router.update_serai_key(key, completion.signature())
        }
        RouterCommand::Execute { outs, .. } => router.execute(
          &outs.iter().cloned().map(Into::into).collect::<Vec<_>>(),
          completion.signature(),
        ),
      };
      tx.gas_price = 100_000_000_000u128;

      use ethereum_serai::alloy_consensus::SignableTransaction;
      let sig =
        k256::ecdsa::SigningKey::from(k256::elliptic_curve::NonZeroScalar::new(key).unwrap())
          .sign_prehash_recoverable(tx.signature_hash().as_ref())
          .unwrap();

      let mut bytes = vec![];
      tx.encode_with_signature_fields(&sig.into(), &mut bytes);
      let _ = self.provider.send_raw_transaction(&bytes).await.ok().unwrap();

      Ok(())
    }
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
    match eventuality.1 {
      RouterCommand::UpdateSeraiKey { nonce, .. } | RouterCommand::Execute { nonce, .. } => {
        let router = self.router().await;
        let router = router.as_ref().unwrap();

        let block = u64::try_from(block).unwrap();
        let filter = router
          .key_updated_filter()
          .from_block(block * 32)
          .to_block(((block + 1) * 32) - 1)
          .topic1(nonce);
        let logs = self.provider.get_logs(&filter).await.unwrap();
        if let Some(log) = logs.first() {
          return self
            .provider
            .get_transaction_by_hash(log.clone().transaction_hash.unwrap())
            .await
            .unwrap();
        };

        let filter = router
          .executed_filter()
          .from_block(block * 32)
          .to_block(((block + 1) * 32) - 1)
          .topic1(nonce);
        let logs = self.provider.get_logs(&filter).await.unwrap();
        self.provider.get_transaction_by_hash(logs[0].transaction_hash.unwrap()).await.unwrap()
      }
    }
  }

  #[cfg(test)]
  async fn mine_block(&self) {
    self.provider.raw_request::<_, ()>("anvil_mine".into(), [32]).await.unwrap();
  }

  #[cfg(test)]
  async fn test_send(&self, send_to: Self::Address) -> Self::Block {
    use rand_core::OsRng;
    use ciphersuite::group::ff::Field;

    let key = <Secp256k1 as Ciphersuite>::F::random(&mut OsRng);
    let address = ethereum_serai::crypto::address(&(Secp256k1::generator() * key));

    // Set a 1.1 ETH balance
    self
      .provider
      .raw_request::<_, ()>(
        "anvil_setBalance".into(),
        [Address(address).to_string(), "1100000000000000000".into()],
      )
      .await
      .unwrap();

    let tx = ethereum_serai::alloy_consensus::TxLegacy {
      chain_id: None,
      nonce: 0,
      gas_price: 100_000_000_000u128,
      gas_limit: 21_0000u128,
      to: ethereum_serai::alloy_core::primitives::TxKind::Call(send_to.0.into()),
      // 1 ETH
      value: U256::from_str_radix("1000000000000000000", 10).unwrap(),
      input: vec![].into(),
    };

    use ethereum_serai::alloy_consensus::SignableTransaction;
    let sig = k256::ecdsa::SigningKey::from(k256::elliptic_curve::NonZeroScalar::new(key).unwrap())
      .sign_prehash_recoverable(tx.signature_hash().as_ref())
      .unwrap();

    let mut bytes = vec![];
    tx.encode_with_signature_fields(&sig.into(), &mut bytes);
    let pending_tx = self.provider.send_raw_transaction(&bytes).await.ok().unwrap();

    // Mine an epoch containing this TX
    self.mine_block().await;
    assert!(pending_tx.get_receipt().await.unwrap().status());
    // Yield the freshly mined block
    self.get_block(self.get_latest_block_number().await.unwrap()).await.unwrap()
  }
}
