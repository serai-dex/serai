use rand::{Rng, RngCore};
use rand_core::OsRng;
use serai_abi::primitives::test_helpers::random_serai_address;
use serai_shim_rpc::{*, test_helpers::*};

use serai_client_serai::{
  *,
  abi::{
    primitives::{balance::*, network_id::*, validator_sets::*},
    validator_sets::*,
  },
};

#[tokio::test]
async fn test_basic_block_and_number() {
  let shim = SeraiShimRpcBuilder::new()
    .with_block(vec![vec![]])
    .with_block(vec![vec![]])
    .with_block(vec![vec![]])
    .build()
    .await;

  let serai = Serai::new(shim.url()).unwrap();

  let latest = serai.latest_finalized_block_number().await.unwrap();
  assert_eq!(latest, 3, "latest finalized block number should be 3");

  let block = serai.block_by_number(1).await.unwrap();
  assert!(block.is_some(), "block 1 should exist");
  assert_eq!(block.unwrap().header.number(), 1, "block 1 should have number 1");

  let block2 = serai.block_by_number(2).await.unwrap().unwrap();
  assert_eq!(block2.header.number(), 2, "block 2 should have number 2");

  let block3 = serai.block_by_number(3).await.unwrap().unwrap();
  assert_eq!(block3.header.number(), 3, "block 3 should have number 3");

  let none = serai.block_by_number(OsRng.gen_range(5 .. 999)).await.unwrap();
  assert!(none.is_none(), "non-existent block should return None");
}

#[tokio::test]
async fn test_block_by_hash() {
  let shim = SeraiShimRpcBuilder::new().with_block(vec![vec![]]).build().await;
  let serai = Serai::new(shim.url()).unwrap();

  let block = serai.block_by_number(1).await.unwrap().unwrap();
  let hash = block.header.hash();

  let block_by_hash = serai.block(hash).await.unwrap();
  assert!(block_by_hash.is_some(), "block lookup by hash should return Some");
  assert_eq!(
    block_by_hash.unwrap().header.number(),
    1,
    "block looked up by hash should be block 1"
  );

  let finalized = serai.finalized(hash).await.unwrap();
  assert!(finalized, "block should be finalized");
}

#[tokio::test]
async fn test_events_round_trip() {
  let validator = random_serai_address(&mut OsRng);
  let events = vec![vec![
    allocation_event(validator, NetworkId::External(ExternalNetworkId::Bitcoin), OsRng.next_u64()),
    set_decided_event(
      ValidatorSet {
        network: NetworkId::External(ExternalNetworkId::Bitcoin),
        session: Session(0),
      },
      vec![(validator, KeyShares::ONE)],
    ),
  ]];

  let shim = SeraiShimRpcBuilder::new().with_block(events).build().await;

  let serai = Serai::new(shim.url()).unwrap();

  let block = serai.block_by_number(1).await.unwrap().unwrap();
  let hash = block.header.hash();

  let events = serai.events(hash).await.unwrap();

  let vs = events.validator_sets();
  let vs_events: Vec<_> = vs.events().collect();
  assert_eq!(vs_events.len(), 2, "should have 2 validator_sets events");

  assert!(matches!(vs_events[0], Event::Allocation { .. }), "first event should be Allocation");
  assert!(matches!(vs_events[1], Event::SetDecided { .. }), "second event should be SetDecided");
}

#[tokio::test]
async fn test_dynamic_block_addition() {
  let shim = SeraiShimRpc::builder().build().await;

  let serai = Serai::new(shim.url()).unwrap();

  let latest = serai.latest_finalized_block_number().await.unwrap();
  assert_eq!(latest, 0, "initially no blocks should exist");

  let hash = shim.add_block_with_events(vec![vec![]]).await;

  let latest = serai.latest_finalized_block_number().await.unwrap();
  assert_eq!(latest, 1, "should have 1 block after adding one");

  let block = serai.block(hash).await.unwrap();
  assert!(block.is_some(), "block should be retrievable by hash");
  assert_eq!(block.unwrap().header.number(), 1, "dynamically added block should be block 1");

  shim.add_block_with_events(vec![vec![]]).await;
  let latest = serai.latest_finalized_block_number().await.unwrap();
  assert_eq!(latest, 2, "should have 2 blocks after adding another");
}

#[tokio::test]
async fn test_error_injection() {
  let shim = SeraiShimRpcBuilder::new().with_block(vec![vec![]]).build().await;

  let serai = Serai::new(shim.url()).unwrap();

  let latest = serai.latest_finalized_block_number().await.unwrap();
  assert_eq!(latest, 1, "should work normally before error injection");

  shim.set_error("blockchain/latest_finalized_block_number", "simulated failure").await;

  let result = serai.latest_finalized_block_number().await;
  assert!(result.is_err(), "should fail after error injection");
  let err_msg = format!("{}", result.unwrap_err());
  assert!(err_msg.contains("simulated failure"), "error was: {err_msg}");

  shim.clear_error("blockchain/latest_finalized_block_number").await;

  let latest = serai.latest_finalized_block_number().await.unwrap();
  assert_eq!(latest, 1, "should work again after clearing error");
}

#[tokio::test]
async fn test_clear_all_errors() {
  let shim = SeraiShimRpcBuilder::new().with_block(vec![vec![]]).build().await;

  let serai = Serai::new(shim.url()).unwrap();

  shim.set_error("blockchain/latest_finalized_block_number", "err1").await;
  shim.set_error("blockchain/block", "err2").await;

  assert!(
    serai.latest_finalized_block_number().await.is_err(),
    "latest_finalized should fail with injected error"
  );
  assert!(
    serai.block_by_number(1).await.is_err(),
    "block_by_number should fail with injected error"
  );

  shim.clear_all_errors().await;

  assert_eq!(
    serai.latest_finalized_block_number().await.unwrap(),
    1,
    "latest_finalized should work after clearing all errors"
  );
  assert!(
    serai.block_by_number(1).await.unwrap().is_some(),
    "block_by_number should work after clearing all errors"
  );
}

#[tokio::test]
async fn test_builds_upon_chain() {
  let shim = SeraiShimRpcBuilder::new()
    .with_block(vec![vec![]])
    .with_block(vec![vec![]])
    .with_block(vec![vec![]])
    .build()
    .await;

  let serai = Serai::new(shim.url()).unwrap();

  let block1 = serai.block_by_number(1).await.unwrap().unwrap();
  let block2 = serai.block_by_number(2).await.unwrap().unwrap();
  let block3 = serai.block_by_number(3).await.unwrap().unwrap();

  assert_ne!(
    block1.header.builds_upon(),
    block2.header.builds_upon(),
    "block 1 and 2 should have distinct builds_upon"
  );
  assert_ne!(
    block2.header.builds_upon(),
    block3.header.builds_upon(),
    "block 2 and 3 should have distinct builds_upon"
  );

  assert_ne!(
    block1.header.hash(),
    block2.header.hash(),
    "block 1 and 2 should have distinct hashes"
  );
  assert_ne!(
    block2.header.hash(),
    block3.header.hash(),
    "block 2 and 3 should have distinct hashes"
  );
}

#[tokio::test]
async fn test_publish_transaction() {
  let shim = SeraiShimRpc::builder().with_block(vec![vec![]]).build().await;

  {
    let state = shim.state().read().await;
    assert!(state.published_transactions.is_empty(), "no transactions should exist initially");
  }

  {
    let mut state = shim.state().write().await;
    state.published_transactions.push(vec![0xDE, 0xAD]);
  }
  {
    let state = shim.state().read().await;
    assert_eq!(state.published_transactions.len(), 1, "should have 1 published transaction");
    assert_eq!(state.published_transactions[0], vec![0xDE, 0xAD], "transaction bytes should match");
  }
}

#[tokio::test]
async fn test_validator_sets_state() {
  let shim = SeraiShimRpc::builder().with_block(vec![vec![]]).build().await;

  let serai = Serai::new(shim.url()).unwrap();

  {
    let mut state = shim.state().write().await;
    let network = NetworkId::External(ExternalNetworkId::Bitcoin);
    state.default_validator_sets.sessions.insert(network, Session(5));
    state.default_validator_sets.stakes.insert(network, Amount(1_000_000));
  }

  let serai_state = serai.state().await.unwrap();

  let session =
    serai_state.current_session(NetworkId::External(ExternalNetworkId::Bitcoin)).await.unwrap();
  assert_eq!(session, Some(Session(5)), "current session should be 5");

  let stake =
    serai_state.current_stake(NetworkId::External(ExternalNetworkId::Bitcoin)).await.unwrap();
  assert_eq!(stake, Some(Amount(1_000_000)), "current stake should be 1_000_000");
}
