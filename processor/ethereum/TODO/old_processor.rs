/*
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use core::{fmt, time::Duration};
use std::{
  sync::Arc,
  collections::{HashSet, HashMap},
  io,
};

use async_trait::async_trait;

use ciphersuite::{group::GroupEncoding, Ciphersuite, Secp256k1};
use frost::ThresholdKeys;

use ethereum_serai::{
  alloy::{
    primitives::U256,
    rpc_types::{BlockTransactionsKind, BlockNumberOrTag, Transaction},
    simple_request_transport::SimpleRequest,
    rpc_client::ClientBuilder,
    provider::{Provider, RootProvider},
  },
  crypto::{PublicKey, Signature},
  erc20::Erc20,
  deployer::Deployer,
  router::{Router, Coin as EthereumCoin, InInstruction as EthereumInInstruction},
  machine::*,
};
#[cfg(test)]
use ethereum_serai::alloy::primitives::B256;

use tokio::{
  time::sleep,
  sync::{RwLock, RwLockReadGuard},
};
#[cfg(not(test))]
use tokio::{
  io::{AsyncReadExt, AsyncWriteExt},
  net::TcpStream,
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

#[derive(Clone)]
pub struct Ethereum<D: Db> {
  // This DB is solely used to access the first key generated, as needed to determine the Router's
  // address. Accordingly, all methods present are consistent to a Serai chain with a finalized
  // first key (regardless of local state), and this is safe.
  db: D,
  #[cfg_attr(test, allow(unused))]
  relayer_url: String,
  provider: Arc<RootProvider<SimpleRequest>>,
  deployer: Deployer,
  router: Arc<RwLock<Option<Router>>>,
}
impl<D: Db> Ethereum<D> {
  pub async fn new(db: D, daemon_url: String, relayer_url: String) -> Self {
    let provider = Arc::new(RootProvider::new(
      ClientBuilder::default().transport(SimpleRequest::new(daemon_url), true),
    ));

    let mut deployer = Deployer::new(provider.clone()).await;
    while !matches!(deployer, Ok(Some(_))) {
      log::error!("Deployer wasn't deployed yet or networking error");
      sleep(Duration::from_secs(5)).await;
      deployer = Deployer::new(provider.clone()).await;
    }
    let deployer = deployer.unwrap().unwrap();

    dbg!(&relayer_url);
    dbg!(relayer_url.len());
    Ethereum { db, relayer_url, provider, deployer, router: Arc::new(RwLock::new(None)) }
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
impl<D: Db> Network for Ethereum<D> {
  const DUST: u64 = 0; // TODO

  const COST_TO_AGGREGATE: u64 = 0;

  async fn get_outputs(
    &self,
    block: &Self::Block,
    _: <Secp256k1 as Ciphersuite>::G,
  ) -> Vec<Self::Output> {
    let router = self.router().await;
    let router = router.as_ref().unwrap();
    // Grab the key at the end of the epoch
    let key_at_end_of_block = loop {
      match router.key_at_end_of_block(block.start + 31).await {
        Ok(Some(key)) => break key,
        Ok(None) => return vec![],
        Err(e) => {
          log::error!("couldn't connect to router for the key at the end of the block: {e:?}");
          sleep(Duration::from_secs(5)).await;
          continue;
        }
      }
    };

    let mut all_events = vec![];
    let mut top_level_txids = HashSet::new();
    for erc20_addr in [DAI] {
      let erc20 = Erc20::new(self.provider.clone(), erc20_addr);

      for block in block.start .. (block.start + 32) {
        let transfers = loop {
          match erc20.top_level_transfers(block, router.address()).await {
            Ok(transfers) => break transfers,
            Err(e) => {
              log::error!("couldn't connect to Ethereum node for the top-level transfers: {e:?}");
              sleep(Duration::from_secs(5)).await;
              continue;
            }
          }
        };

        for transfer in transfers {
          top_level_txids.insert(transfer.id);
          all_events.push(EthereumInInstruction {
            id: (transfer.id, 0),
            from: transfer.from,
            coin: EthereumCoin::Erc20(erc20_addr),
            amount: transfer.amount,
            data: transfer.data,
            key_at_end_of_block,
          });
        }
      }
    }

    for block in block.start .. (block.start + 32) {
      let mut events = router.in_instructions(block, &HashSet::from([DAI])).await;
      while let Err(e) = events {
        log::error!("couldn't connect to Ethereum node for the Router's events: {e:?}");
        sleep(Duration::from_secs(5)).await;
        events = router.in_instructions(block, &HashSet::from([DAI])).await;
      }
      let mut events = events.unwrap();
      for event in &mut events {
        // A transaction should either be a top-level transfer or a Router InInstruction
        if top_level_txids.contains(&event.id.0) {
          panic!("top-level transfer had {} and router had {:?}", hex::encode(event.id.0), event);
        }
        // Overwrite the key at end of block to key at end of epoch
        event.key_at_end_of_block = key_at_end_of_block;
      }
      all_events.extend(events);
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

  async fn publish_completion(
    &self,
    completion: &<Self::Eventuality as EventualityTrait>::Completion,
  ) -> Result<(), NetworkError> {
    // Publish this to the dedicated TX server for a solver to actually publish
    #[cfg(not(test))]
    {
    }

    // Publish this using a dummy account we fund with magic RPC commands
    #[cfg(test)]
    {
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
      tx.gas_limit = 1_000_000u64.into();
      tx.gas_price = 1_000_000_000u64.into();
      let tx = ethereum_serai::crypto::deterministically_sign(&tx);

      if self.provider.get_transaction_by_hash(*tx.hash()).await.unwrap().is_none() {
        self
          .provider
          .raw_request::<_, ()>(
            "anvil_setBalance".into(),
            [
              tx.recover_signer().unwrap().to_string(),
              (U256::from(tx.tx().gas_limit) * U256::from(tx.tx().gas_price)).to_string(),
            ],
          )
          .await
          .unwrap();

        let (tx, sig, _) = tx.into_parts();
        let mut bytes = vec![];
        tx.encode_with_signature_fields(&sig, &mut bytes);
        let pending_tx = self.provider.send_raw_transaction(&bytes).await.unwrap();
        self.mine_block().await;
        assert!(pending_tx.get_receipt().await.unwrap().status());
      }

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
      .get_block(B256::from(*id).into(), BlockTransactionsKind::Hashes)
      .await
      .unwrap()
      .unwrap()
      .header
      .number
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
    // We mine 96 blocks to ensure the 32 blocks relevant are finalized
    // Back-check the prior two epochs in response to this
    // TODO: Review why this is sub(3) and not sub(2)
    for block in block.saturating_sub(3) ..= block {
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
              .unwrap()
              .unwrap();
          };

          let filter = router
            .executed_filter()
            .from_block(block * 32)
            .to_block(((block + 1) * 32) - 1)
            .topic1(nonce);
          let logs = self.provider.get_logs(&filter).await.unwrap();
          if logs.is_empty() {
            continue;
          }
          return self
            .provider
            .get_transaction_by_hash(logs[0].transaction_hash.unwrap())
            .await
            .unwrap()
            .unwrap();
        }
      }
    }
    panic!("couldn't find completion in any three of checked blocks");
  }

  #[cfg(test)]
  async fn mine_block(&self) {
    self.provider.raw_request::<_, ()>("anvil_mine".into(), [96]).await.unwrap();
  }

  #[cfg(test)]
  async fn test_send(&self, send_to: Self::Address) -> Self::Block {
    use rand_core::OsRng;
    use ciphersuite::group::ff::Field;
    use ethereum_serai::alloy::sol_types::SolCall;

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

    let value = U256::from_str_radix("1000000000000000000", 10).unwrap();
    let tx = ethereum_serai::alloy::consensus::TxLegacy {
      chain_id: None,
      nonce: 0,
      gas_price: 1_000_000_000u128,
      gas_limit: 200_000u128,
      to: ethereum_serai::alloy::primitives::TxKind::Call(send_to.0.into()),
      // 1 ETH
      value,
      input: ethereum_serai::router::abi::inInstructionCall::new((
        [0; 20].into(),
        value,
        vec![].into(),
      ))
      .abi_encode()
      .into(),
    };

    use ethereum_serai::alloy::{primitives::Signature, consensus::SignableTransaction};
    let sig = k256::ecdsa::SigningKey::from(k256::elliptic_curve::NonZeroScalar::new(key).unwrap())
      .sign_prehash_recoverable(tx.signature_hash().as_ref())
      .unwrap();

    let mut bytes = vec![];
    tx.encode_with_signature_fields(&Signature::from(sig), &mut bytes);
    let pending_tx = self.provider.send_raw_transaction(&bytes).await.ok().unwrap();

    // Mine an epoch containing this TX
    self.mine_block().await;
    assert!(pending_tx.get_receipt().await.unwrap().status());
    // Yield the freshly mined block
    self.get_block(self.get_latest_block_number().await.unwrap()).await.unwrap()
  }
}
*/
