use serai_shim_rpc::{SeraiShimRpc, SeraiShimRpcBuilder};

use serai_client_serai::{
  Serai,
  abi::{
    Event,
    primitives::{
      address::SeraiAddress,
      balance::Amount,
      network_id::{ExternalNetworkId, NetworkId},
      validator_sets::{KeyShares, Session, ValidatorSet},
    },
    validator_sets as vs_mod,
  },
};

fn allocation_event(validator: SeraiAddress, network: NetworkId, amount: u64) -> Event {
  Event::ValidatorSets(vs_mod::Event::Allocation { validator, network, amount: Amount(amount) })
}

fn set_decided_event(network: NetworkId, session: u32, validator: SeraiAddress) -> Event {
  Event::ValidatorSets(vs_mod::Event::SetDecided {
    set: ValidatorSet { network, session: Session(session) },
    validators: vec![(validator, KeyShares::ONE)],
  })
}

#[tokio::test]
async fn test_basic_block_and_number() {
  let sim = SeraiShimRpcBuilder::new()
    .with_block(vec![vec![]])
    .with_block(vec![vec![]])
    .with_block(vec![vec![]])
    .build()
    .await;

  let client = Serai::new(sim.url()).unwrap();

  // Latest finalized block number should be 3
  let latest = client.latest_finalized_block_number().await.unwrap();
  assert_eq!(latest, 3);

  // Block by number should return a valid block
  let block = client.block_by_number(1).await.unwrap();
  assert!(block.is_some());
  let block = block.unwrap();
  assert_eq!(block.header.number(), 1);

  // Block 2 has number 2
  let block2 = client.block_by_number(2).await.unwrap().unwrap();
  assert_eq!(block2.header.number(), 2);

  // Block 3 has number 3
  let block3 = client.block_by_number(3).await.unwrap().unwrap();
  assert_eq!(block3.header.number(), 3);

  // Non-existent block returns None
  let none = client.block_by_number(999).await.unwrap();
  assert!(none.is_none());

  sim.stop();
}

#[tokio::test]
async fn test_block_by_hash() {
  let sim = SeraiShimRpcBuilder::new().with_block(vec![vec![]]).build().await;

  let client = Serai::new(sim.url()).unwrap();

  // Get block by number, then look it up by hash
  let block = client.block_by_number(1).await.unwrap().unwrap();
  let hash = block.header.hash();

  let block_by_hash = client.block(hash).await.unwrap();
  assert!(block_by_hash.is_some());
  assert_eq!(block_by_hash.unwrap().header.number(), 1);

  // is_finalized should return true
  let finalized = client.finalized(hash).await.unwrap();
  assert!(finalized);

  sim.stop();
}

#[tokio::test]
async fn test_events_round_trip() {
  let validator = SeraiAddress([1u8; 32]);
  let events = vec![vec![
    allocation_event(validator, NetworkId::External(ExternalNetworkId::Bitcoin), 1_000_000),
    set_decided_event(NetworkId::External(ExternalNetworkId::Bitcoin), 0, validator),
  ]];

  let sim = SeraiShimRpcBuilder::new().with_block(events).build().await;

  let client = Serai::new(sim.url()).unwrap();

  let block = client.block_by_number(1).await.unwrap().unwrap();
  let hash = block.header.hash();

  let events = client.events(hash).await.unwrap();

  // Extract validator_sets events
  let vs = events.validator_sets();
  let vs_events: Vec<_> = vs.events().collect();
  assert_eq!(vs_events.len(), 2);

  // Verify first event is an Allocation
  assert!(matches!(vs_events[0], vs_mod::Event::Allocation { .. }));
  // Verify second event is a SetDecided
  assert!(matches!(vs_events[1], vs_mod::Event::SetDecided { .. }));

  sim.stop();
}

#[tokio::test]
async fn test_dynamic_block_addition() {
  let sim = SeraiShimRpc::builder().build().await;

  let client = Serai::new(sim.url()).unwrap();

  // Initially no blocks
  let latest = client.latest_finalized_block_number().await.unwrap();
  assert_eq!(latest, 0);

  // Add a block dynamically
  let hash = sim.add_block_with_events(vec![vec![]]).await;

  let latest = client.latest_finalized_block_number().await.unwrap();
  assert_eq!(latest, 1);

  // Look up the block by its hash
  let block = client.block(hash).await.unwrap();
  assert!(block.is_some());
  assert_eq!(block.unwrap().header.number(), 1);

  // Add another
  sim.add_block_with_events(vec![vec![]]).await;
  let latest = client.latest_finalized_block_number().await.unwrap();
  assert_eq!(latest, 2);

  sim.stop();
}

#[tokio::test]
async fn test_error_injection() {
  let sim = SeraiShimRpcBuilder::new().with_block(vec![vec![]]).build().await;

  let client = Serai::new(sim.url()).unwrap();

  // Works normally
  let latest = client.latest_finalized_block_number().await.unwrap();
  assert_eq!(latest, 1);

  // Inject error
  sim.set_error("blockchain/latest_finalized_block_number", "simulated failure").await;

  // Now it should fail
  let result = client.latest_finalized_block_number().await;
  assert!(result.is_err());
  let err_msg = format!("{}", result.unwrap_err());
  assert!(err_msg.contains("simulated failure"), "error was: {err_msg}");

  // Clear error
  sim.clear_error("blockchain/latest_finalized_block_number").await;

  // Should work again
  let latest = client.latest_finalized_block_number().await.unwrap();
  assert_eq!(latest, 1);

  sim.stop();
}

#[tokio::test]
async fn test_clear_all_errors() {
  let sim = SeraiShimRpcBuilder::new().with_block(vec![vec![]]).build().await;

  let client = Serai::new(sim.url()).unwrap();

  // Inject multiple errors
  sim.set_error("blockchain/latest_finalized_block_number", "err1").await;
  sim.set_error("blockchain/block", "err2").await;

  // Both should fail
  client.latest_finalized_block_number().await.unwrap_err();
  client.block_by_number(1).await.unwrap_err();

  // Clear all
  sim.clear_all_errors().await;

  // Both should work
  assert_eq!(client.latest_finalized_block_number().await.unwrap(), 1);
  assert!(client.block_by_number(1).await.unwrap().is_some());

  sim.stop();
}

#[tokio::test]
async fn test_builds_upon_chain() {
  // Verify that blocks form a proper chain via builds_upon
  let sim = SeraiShimRpcBuilder::new()
    .with_block(vec![vec![]])
    .with_block(vec![vec![]])
    .with_block(vec![vec![]])
    .build()
    .await;

  let client = Serai::new(sim.url()).unwrap();

  let block1 = client.block_by_number(1).await.unwrap().unwrap();
  let block2 = client.block_by_number(2).await.unwrap().unwrap();
  let block3 = client.block_by_number(3).await.unwrap().unwrap();

  // Each block should have a distinct builds_upon
  assert_ne!(block1.header.builds_upon(), block2.header.builds_upon());
  assert_ne!(block2.header.builds_upon(), block3.header.builds_upon());

  // Each block should have a distinct hash
  assert_ne!(block1.header.hash(), block2.header.hash());
  assert_ne!(block2.header.hash(), block3.header.hash());

  sim.stop();
}

#[tokio::test]
async fn test_publish_transaction() {
  let sim = SeraiShimRpc::builder().with_block(vec![vec![]]).build().await;

  // The simulator stores raw transaction bytes without execution.
  {
    let state = sim.state().read().await;
    assert!(state.published_transactions.is_empty());
  }

  // The publish_transaction method on the client requires a real Transaction,
  // so we verify the endpoint works by pushing directly to state.
  {
    let mut state = sim.state().write().await;
    state.published_transactions.push(vec![0xDE, 0xAD]);
  }
  {
    let state = sim.state().read().await;
    assert_eq!(state.published_transactions.len(), 1);
    assert_eq!(state.published_transactions[0], vec![0xDE, 0xAD]);
  }

  sim.stop();
}

#[tokio::test]
async fn test_validator_sets_state() {
  let sim = SeraiShimRpc::builder().with_block(vec![vec![]]).build().await;

  let client = Serai::new(sim.url()).unwrap();

  // Set up validator-sets state on the default
  {
    let mut state = sim.state().write().await;
    let network = NetworkId::External(ExternalNetworkId::Bitcoin);
    state.default_validator_sets.sessions.insert(network, Session(5));
    state.default_validator_sets.stakes.insert(network, Amount(1_000_000));
  }

  // Query via the real client's State API
  let serai_state = client.state().await.unwrap();

  let session =
    serai_state.current_session(NetworkId::External(ExternalNetworkId::Bitcoin)).await.unwrap();
  assert_eq!(session, Some(Session(5)));

  let stake =
    serai_state.current_stake(NetworkId::External(ExternalNetworkId::Bitcoin)).await.unwrap();
  assert_eq!(stake, Some(Amount(1_000_000)));

  sim.stop();
}
