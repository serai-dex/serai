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

// TODO: This is duplicated with serai-client's tests
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

async fn get_session(serai: &Serai, network: NetworkId) -> Session {
  serai
    .as_of_latest_finalized_block()
    .await
    .unwrap()
    .validator_sets()
    .session(network)
    .await
    .unwrap()
    .unwrap()
}

async fn wait_till_session_1(serai: &Serai, network: NetworkId) {
  let mut current_session = get_session(serai, network).await;

  while current_session.0 < 1 {
    sleep(Duration::from_secs(6)).await;
    current_session = get_session(serai, network).await;
  }
}

async fn most_recent_new_set_event(serai: &Serai, network: NetworkId) -> ValidatorSetsEvent {
  let mut current_block = serai.latest_finalized_block().await.unwrap();
  loop {
    let events = serai.as_of(current_block.hash()).validator_sets().new_set_events().await.unwrap();
    for event in events {
      match event {
        ValidatorSetsEvent::NewSet { set } => {
          if set.network == network {
            return event;
          }
        }
        _ => panic!("new_set_events gave non-NewSet event: {event:?}"),
      }
    }
    current_block = serai.block(current_block.header.parent_hash.0).await.unwrap().unwrap();
  }
}

#[tokio::test]
async fn set_rotation_test() {
  new_test(
    |mut processors: Vec<Processor>| async move {
      // exclude the last processor from keygen since we will add him later
      let mut excluded = processors.pop().unwrap();
      assert_eq!(processors.len(), COORDINATORS);

      // excluded participant
      let pair5 = insecure_pair_from_name("Eve");
      let network = NetworkId::Bitcoin;
      let amount = Amount(1_000_000 * 10_u64.pow(8));
      let serai = processors[0].serai().await;

      // allocate now for the last participant so that it is guaranteed to be included into session
      // 1 set. This doesn't affect the genesis set at all since that is a predetermined set.
      allocate_stake(&serai, network, amount, &pair5, 0).await;

      // genesis keygen
      let _ = key_gen::<Secp256k1>(&mut processors, Session(0)).await;
      // Even the excluded processor should receive the key pair confirmation
      match excluded.recv_message().await {
        CoordinatorMessage::Substrate(
          messages::substrate::CoordinatorMessage::ConfirmKeyPair { session, .. },
        ) => assert_eq!(session, Session(0)),
        _ => panic!("excluded got message other than ConfirmKeyPair"),
      }

      // wait until next session to see the effect on coordinator
      wait_till_session_1(&serai, network).await;

      // Ensure the new validator was included in the new set
      assert_eq!(
        most_recent_new_set_event(&serai, network).await,
        ValidatorSetsEvent::NewSet { set: ValidatorSet { session: Session(1), network } },
      );

      // add the last participant & do the keygen
      processors.push(excluded);
      let _ = key_gen::<Secp256k1>(&mut processors, Session(1)).await;
    },
    true,
  )
  .await;
}
