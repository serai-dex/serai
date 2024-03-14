use tokio::time::{sleep, Duration};

use ciphersuite::Secp256k1;

use serai_client::{
  primitives::{insecure_pair_from_name, NetworkId},
  validator_sets::{
    self,
    primitives::{Session, ValidatorSet},
    ValidatorSetsEvent,
  },
  Amount, Pair, Transaction,
};
use crate::{*, tests::*};

async fn publish_tx(serai: &Serai, tx: &Transaction) -> [u8; 32] {
  let mut latest = serai
    .block(serai.latest_finalized_block_hash().await.unwrap())
    .await
    .unwrap()
    .unwrap()
    .number();

  serai.publish(tx).await.unwrap();

  // Get the block it was included in
  // TODO: Add an RPC method for this/check the guarantee on the subscription
  let mut ticks = 0;
  loop {
    latest += 1;

    let block = {
      let mut block;
      while {
        block = serai.finalized_block_by_number(latest).await.unwrap();
        block.is_none()
      } {
        sleep(Duration::from_secs(1)).await;
        ticks += 1;

        if ticks > 60 {
          panic!("60 seconds without inclusion in a finalized block");
        }
      }
      block.unwrap()
    };

    for transaction in &block.transactions {
      if transaction == tx {
        return block.hash();
      }
    }
  }
}

#[allow(dead_code)]
async fn allocate_stake(
  serai: &Serai,
  network: NetworkId,
  amount: Amount,
  pair: &Pair,
  nonce: u32,
) -> [u8; 32] {
  // get the call
  let tx =
    serai.sign(pair, validator_sets::SeraiValidatorSets::allocate(network, amount), nonce, 0);
  publish_tx(serai, &tx).await
}

#[allow(dead_code)]
async fn deallocate_stake(
  serai: &Serai,
  network: NetworkId,
  amount: Amount,
  pair: &Pair,
  nonce: u32,
) -> [u8; 32] {
  // get the call
  let tx =
    serai.sign(pair, validator_sets::SeraiValidatorSets::deallocate(network, amount), nonce, 0);
  publish_tx(serai, &tx).await
}

async fn wait_till_next_epoch(serai: &Serai, current_epoch: u32) -> Session {
  let mut session = Session(current_epoch);
  while session.0 < current_epoch + 1 {
    sleep(Duration::from_secs(6)).await;
    session = serai
      .as_of_latest_finalized_block()
      .await
      .unwrap()
      .validator_sets()
      .session(NetworkId::Serai)
      .await
      .unwrap()
      .unwrap();
  }
  session
}

async fn get_session(serai: &Serai, block: [u8; 32], network: NetworkId) -> Session {
  serai.as_of(block).validator_sets().session(network).await.unwrap().unwrap()
}

async fn new_set_events(
  serai: &Serai,
  session: Session,
  network: NetworkId,
) -> Vec<ValidatorSetsEvent> {
  let mut current_block = serai.latest_finalized_block().await.unwrap();
  let mut current_session = get_session(serai, current_block.hash(), network).await;

  while current_session == session {
    let events = serai.as_of(current_block.hash()).validator_sets().new_set_events().await.unwrap();
    if !events.is_empty() {
      return events;
    }

    current_block = serai.block(current_block.header.parent_hash.0).await.unwrap().unwrap();
    current_session = get_session(serai, current_block.hash(), network).await;
  }

  panic!("can't find the new set events for session: {} ", session.0);
}

#[tokio::test]
async fn set_rotation_test() {
  new_test(
    |mut processors: Vec<Processor>| async move {
      // exclude the last processor from keygen since we will add him later
      let excluded = processors.pop().unwrap();
      assert_eq!(processors.len(), COORDINATORS);

      // genesis keygen
      let _ = key_gen::<Secp256k1>(&mut processors, Session(0)).await;

      let pair5 = insecure_pair_from_name("Eve");
      let network = NetworkId::Bitcoin;
      let amount = Amount(1_000_000 * 10_u64.pow(8));
      let serai = processors[0].serai().await;

      // add the last participant into validator set for btc network
      let block = allocate_stake(&serai, network, amount, &pair5, 0).await;

      // wait until next session to see the effect on coordinator
      let current_epoch = get_session(&serai, block, NetworkId::Serai).await;
      let session = wait_till_next_epoch(&serai, current_epoch.0).await;

      // verfiy that coordinator received new_set
      let events = new_set_events(&serai, session, network).await;
      assert!(
        events.contains(&ValidatorSetsEvent::NewSet { set: ValidatorSet { session, network } })
      );

      // add the last participant & do the keygen
      processors.push(excluded);
      let _ = key_gen::<Secp256k1>(&mut processors, session).await;
    },
    true,
  )
  .await;
}
