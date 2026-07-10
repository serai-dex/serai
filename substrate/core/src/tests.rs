#![expect(clippy::as_conversions, clippy::same_name_method)]

use rand_core::{RngCore as _, OsRng};

use sp_core::Encode as _;
use frame_support::{
  sp_runtime::{
    traits::{Header as _, Block as BlockTrait},
    generic::{DigestItem, Digest},
  },
  weights::Weight,
  traits::{OnInitialize as _, OnFinalize as _},
  derive_impl, construct_runtime,
};
use frame_system::pallet_prelude::BlockNumberFor;

use borsh::BorshDeserialize as _;
use serai_abi::{
  primitives::{BlockHash, address::SeraiAddress, merkle::UnbalancedMerkleTree},
  ImplicitContext, TransactionContext as _, SeraiPreExecutionDigest, SeraiExecutionDigest, Block,
};

use crate as core_pallet;

construct_runtime!(
  pub enum Test
  {
    System: frame_system,
    Timestamp: pallet_timestamp,
    Core: core_pallet,
  }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Test {
  type AccountId = SeraiAddress;
  type Lookup = frame_support::sp_runtime::traits::IdentityLookup<Self::AccountId>;
  type Block = frame_system::mocking::MockBlock<Test>;
  type BlockLength = crate::Limits;
  type BlockWeights = crate::Limits;
}

impl From<serai_abi::Call> for RuntimeCall {
  fn from(_call: serai_abi::Call) -> Self {
    unimplemented!();
  }
}

#[derive_impl(pallet_timestamp::config_preludes::TestDefaultConfig)]
impl pallet_timestamp::Config for Test {}

#[rustfmt::skip]
const PROTOCOL_ID: [u8; 32] = [
  0xa6, 0x2c, 0x51, 0xd9, 0x12, 0xa0, 0x60, 0x9f, 0x33, 0x8a, 0x1b, 0xec, 0x0a, 0x06, 0x7f, 0xea,
  0xb2, 0x6a, 0x87, 0x17, 0xdb, 0x62, 0x72, 0x53, 0x2b, 0x36, 0x08, 0x22, 0x6e, 0xe8, 0x46, 0x2b,
];

const PRE_INHERENTS_KEY: &[u8] = b"PreInherents";
pub struct PreInherents;
impl frame_support::traits::PreInherents for PreInherents {
  fn pre_inherents() {
    sp_io::storage::set(PRE_INHERENTS_KEY, &System::block_number().encode());
  }
}

impl crate::Config for Test {
  const PROTOCOL_ID: [u8; 32] = PROTOCOL_ID;
  const SIGNATURE_VERIFICATION_WEIGHT: Weight = Weight::zero();
  type PreInherents = PreInherents;
}

fn new_test_ext() -> sp_io::TestExternalities {
  let mut externalities = sp_io::TestExternalities::new_empty();
  externalities.execute_with(|| {
    let system = frame_system::GenesisConfig::<Test>::default();
    Core::genesis(&system);
  });
  externalities
}

fn new_frame_system_block() {
  let parent_block_number = System::block_number();
  let parent_hash = System::finalize().hash();

  let block_number = parent_block_number + 1;

  System::reset_events();
  System::initialize(
    &block_number,
    &parent_hash,
    &Digest {
      logs: vec![DigestItem::PreRuntime(
        SeraiPreExecutionDigest::CONSENSUS_ID,
        borsh::to_vec(&SeraiPreExecutionDigest {
          proposer: SeraiAddress([0; 32]),
          unix_time_in_millis: block_number * 6_000,
        })
        .unwrap(),
      )],
    },
  );
}

fn new_block() {
  new_frame_system_block();
  let _weight = AllPalletsWithSystem::on_initialize(System::block_number());
  // Check the `PreInherents` successfully executed
  assert_eq!(sp_io::storage::get(PRE_INHERENTS_KEY).unwrap(), System::block_number().encode());
}

fn end_block() -> <<Test as frame_system::Config>::Block as BlockTrait>::Header {
  let block_number = System::block_number();

  let builds_upon_merkle = crate::BlocksCommitmentMerkle::<Test>::get();
  let transactions_commitment_merkle = crate::BlockTransactionsCommitmentMerkle::<Test>::get();
  let events_commitment_merkle = crate::BlockEventsCommitmentMerkle::<Test>::get();

  let () = AllPalletsWithSystem::on_finalize(block_number);
  let header = System::finalize();

  // Check the `SeraiExecutionDigest`
  {
    fn serai_execution_digest(
      header: &<<Test as frame_system::Config>::Block as BlockTrait>::Header,
    ) -> SeraiExecutionDigest {
      for log in header.digest().logs() {
        if let DigestItem::Consensus(SeraiExecutionDigest::CONSENSUS_ID, log) = log {
          return SeraiExecutionDigest::deserialize_reader(&mut log.as_slice()).unwrap();
        }
      }
      panic!("`SeraiExecutionDigest` not found in header");
    }

    let SeraiExecutionDigest { builds_upon, transactions_commitment, events_commitment } =
      serai_execution_digest(&header);
    assert_eq!(builds_upon, builds_upon_merkle);
    assert_eq!(transactions_commitment, transactions_commitment_merkle);
    assert_eq!(events_commitment, events_commitment_merkle);
  }

  header
}

#[test]
fn genesis() {
  const KEY: &[u8] = b"CustomGenesis";
  const VALUE: &[u8] = b"built";
  struct CustomGenesis;
  impl frame_support::traits::BuildGenesisConfig for CustomGenesis {
    fn build(&self) {
      sp_io::storage::set(KEY, VALUE);
    }
  }

  let mut externalities = sp_io::TestExternalities::new_empty();
  externalities.execute_with(|| {
    Core::genesis(&CustomGenesis);
    assert_eq!(&sp_io::storage::get(KEY).unwrap(), VALUE);
  });
}

#[test]
fn implicit_context() {
  new_test_ext().execute_with(|| {
    new_frame_system_block();
    assert_eq!(
      Core::implicit_context(),
      ImplicitContext {
        genesis_block_hash: System::block_hash(0).into(),
        protocol_id: PROTOCOL_ID
      }
    );
  });
}

#[test]
fn block_size_limit() {
  new_test_ext().execute_with(|| {
    let empty_block = Block {
      header: serai_abi::Header::V1(serai_abi::HeaderV1 {
        number: 0,
        builds_upon: UnbalancedMerkleTree::EMPTY,
        proposer: SeraiAddress([0; 32]),
        unix_time_in_millis: 0,
        transactions_commitment: UnbalancedMerkleTree::EMPTY,
        events_commitment: UnbalancedMerkleTree::EMPTY,
        consensus_commitment: [0; 32],
      }),
      transactions: vec![],
    };

    new_frame_system_block();
    assert_eq!(Core::current_block_size(), 0);

    // Starting a block should initialize the size of the block to the size of an empty block
    let _weight = AllPalletsWithSystem::on_initialize(System::block_number());
    assert_eq!(Core::current_block_size(), borsh::to_vec(&empty_block).unwrap().len());

    // Test basic accumulations
    for len in [0, 1] {
      let size = Core::current_block_size();
      let () = Core::start_transaction(len);
      let () = Core::end_transaction([0; 32]);
      assert_eq!(Core::current_block_size(), size + len);
    }

    // Go up to right before the limit
    {
      let size = Core::current_block_size();
      let len = Block::MAX_SIZE - 1 - size;
      let () = Core::start_transaction(len);
      let () = Core::end_transaction([0; 32]);
      assert_eq!(Core::current_block_size(), size + len);
    }

    // Go to the limit
    {
      let len = 1;
      let () = Core::start_transaction(len);
      let () = Core::end_transaction([0; 32]);
      assert_eq!(Core::current_block_size(), Block::MAX_SIZE);
    }

    // Check this is cleared at the end of the block
    end_block();
    assert_eq!(Core::current_block_size(), 0);

    // And with a new block, this should have the same behavior as before
    new_block();
    assert_eq!(Core::current_block_size(), borsh::to_vec(&empty_block).unwrap().len());

    // Exceeding the block size limit should cause a panic
    {
      let size = Core::current_block_size();
      let len = Block::MAX_SIZE + 1 - size;
      std::panic::catch_unwind(|| Core::start_transaction(len)).unwrap_err();
    }
  });
}

#[test]
fn historical_blocks() {
  new_test_ext().execute_with(|| {
    let mut hashes = vec![];
    for i in 1u16 .. 512 {
      new_block();
      assert_eq!(System::block_number(), BlockNumberFor::<Test>::from(i));
      let header = end_block();

      if i == 1 {
        hashes.push(System::block_hash(0));
      }

      // Check `BlocksCommitmentMerkle` is being correctly defined
      assert_eq!(hashes.len(), usize::from(i));
      let builds_upon = UnbalancedMerkleTree::new(
        serai_abi::BLOCK_BRANCH_TAG,
        hashes
          .iter()
          .map(|hash| {
            sp_io::hashing::blake2_256(
              &borsh::to_vec(&(serai_abi::BLOCK_LEAF_TAG, <[u8; 32]>::from(*hash))).unwrap(),
            )
          })
          .collect::<Vec<_>>(),
      );
      assert_eq!(crate::BlocksCommitmentMerkle::<Test>::get(), builds_upon);

      hashes.push(header.hash());
    }
    // The final block is still 'being executed' and is not yet added to the chain
    hashes.pop();

    {
      assert!(!Core::block_is_present_in_blockchain(&BlockHash([0; 32])));
      let mut random_block_hash = [0; 32];
      OsRng.fill_bytes(&mut random_block_hash);
      assert!(!Core::block_is_present_in_blockchain(&random_block_hash.into()));
    }

    for hash in hashes {
      assert!(Core::block_is_present_in_blockchain(&hash.into()));
    }

    // Check `frame-system` doesn't prune the genesis block's hash
    assert_ne!(System::block_hash(0), Default::default());
    // Check `frame-system` has started pruning blocks however
    assert_eq!(System::block_hash(1), Default::default());
  });
}

#[test]
fn time() {
  new_test_ext().execute_with(|| {
    assert_eq!(Timestamp::get(), 0);

    new_block();

    let first_time = Timestamp::get();
    assert_ne!(first_time, 0);
    assert_eq!(Core::current_time(), first_time);

    end_block();
    new_block();

    let second_time = Timestamp::get();
    assert!(second_time > first_time);
    assert_eq!(Core::current_time(), second_time);
  });
}

#[test]
fn nonce() {
  new_test_ext().execute_with(|| {
    assert_eq!(Core::next_nonce(&SeraiAddress([0; 32])), 0);
    let () = Core::consume_next_nonce(&SeraiAddress([0; 32]));
    assert_eq!(Core::next_nonce(&SeraiAddress([0; 32])), 1);
  });
}

// Test a block's flow, starting/ending transactions with plenty of events
#[test]
fn block_flow() {
  use serai_abi::*;
  use crate::*;

  type TransactionAndEvents = ([u8; 32], Vec<serai_abi::Event>);

  // Check the behavior of `Core::events`
  let core_events = |transactions: &[TransactionAndEvents]| {
    assert_eq!(
      Core::events(),
      transactions
        .iter()
        .map(|(_transaction_hash, events)| events
          .iter()
          .map(|event| borsh::to_vec(event).unwrap())
          .collect::<Vec<_>>())
        .collect::<Vec<_>>()
    );
  };

  // Push a transaction onto our state and apply the checks
  let push_transaction = |transactions: &mut Vec<TransactionAndEvents>, transaction_hash| {
    transactions.push((transaction_hash, vec![]));
    assert_eq!(
      System::events().last().unwrap().event,
      RuntimeEvent::Core(crate::Event::Transaction)
    );
    core_events(transactions);
  };

  // Start a transaction with a randomly-generated hash
  let start_transaction = |transactions: &mut Vec<TransactionAndEvents>| {
    let existing_events = System::events().len();
    let () = Core::start_transaction(0);
    assert_eq!(System::events().len(), existing_events + 1);

    let mut transaction_hash = [0; 32];
    OsRng.fill_bytes(&mut transaction_hash);
    push_transaction(transactions, transaction_hash);
  };

  // Apply the expected checks after a transaction ends regarding how its committed to
  let end_transaction_checks = |transactions: &mut Vec<TransactionAndEvents>| {
    assert_eq!(
      BlockTransactionsCommitmentMerkle::<Test>::get(),
      UnbalancedMerkleTree::new(
        TRANSACTION_COMMITMENT_BRANCH_TAG,
        transactions
          .iter()
          .map(|(transaction_hash, _events)| sp_io::hashing::blake2_256(
            &borsh::to_vec(&(TRANSACTION_COMMITMENT_LEAF_TAG, transaction_hash)).unwrap()
          ))
          .collect::<Vec<_>>()
      )
    );

    assert_eq!(
      BlockEventsCommitmentMerkle::<Test>::get(),
      UnbalancedMerkleTree::new(
        EVENTS_COMMITMENT_BRANCH_TAG,
        transactions
          .iter()
          .map(|(transaction_hash, events)| {
            sp_io::hashing::blake2_256(
              &borsh::to_vec(&(
                EVENTS_COMMITMENT_LEAF_TAG,
                transaction_hash,
                UnbalancedMerkleTree::new(
                  TRANSACTION_EVENTS_COMMITMENT_BRANCH_TAG,
                  events
                    .iter()
                    .map(|event| {
                      sp_io::hashing::blake2_256(
                        &borsh::to_vec(&(TRANSACTION_EVENTS_COMMITMENT_LEAF_TAG, event)).unwrap(),
                      )
                    })
                    .collect::<Vec<_>>(),
                )
                .root,
              ))
              .unwrap(),
            )
          })
          .collect::<Vec<_>>()
      )
    );
  };

  // End the most recent transaction and apply the checks
  let end_transaction = |transactions: &mut Vec<TransactionAndEvents>| {
    let () = Core::end_transaction(transactions.last().unwrap().0);
    end_transaction_checks(transactions);
  };

  let signals_event = serai_abi::signals::Event::RetirementSignalRevoked {
    signal: {
      let mut signal = [0; 32];
      OsRng.fill_bytes(&mut signal);
      signal
    },
  };
  #[expect(clippy::cast_possible_truncation)]
  let random_event = || {
    let events = {
      use serai_abi::primitives::{network_id::*, validator_sets::*};
      [
        serai_abi::Event::Signals(signals_event.clone()),
        serai_abi::Event::ValidatorSets(serai_abi::validator_sets::Event::AcceptedHandover {
          set: ValidatorSet {
            network: NetworkId::Serai,
            session: Session(OsRng.next_u64() as u32),
          },
        }),
        serai_abi::Event::ValidatorSets(serai_abi::validator_sets::Event::Slashes(
          serai_abi::validator_sets::ReportedSlashes::ExternalValidatorSet(ExternalValidatorSet {
            network: ExternalNetworkId::Bitcoin,
            session: Session(OsRng.next_u64() as u32),
          }),
        )),
      ]
    };
    events[(OsRng.next_u64() as usize) % events.len()].clone()
  };

  // Update our state and apply checks for an already-emitted event
  let emitted_event = |transactions: &mut Vec<TransactionAndEvents>, event: serai_abi::Event| {
    transactions.last_mut().unwrap().1.push(event.clone());
    let encoding = borsh::to_vec(&event).unwrap();
    assert_eq!(
      System::events().last().unwrap().event,
      RuntimeEvent::Core(crate::Event::Event(encoding.clone()))
    );
    core_events(transactions);
  };

  // Fuzz a random transaction (and events)
  let fuzz_transaction = |transactions: &mut Vec<TransactionAndEvents>| {
    let fuzz_event = |transactions: &mut Vec<TransactionAndEvents>| {
      let event = random_event();

      let existing_events = System::events().len();
      let () = Core::emit_event(event.clone());
      assert_eq!(System::events().len(), existing_events + 1);

      emitted_event(transactions, event);
    };

    start_transaction(transactions);
    for _ in 0 .. (OsRng.next_u64() % 64) {
      fuzz_event(transactions);
    }
    end_transaction(transactions);
  };

  new_test_ext().execute_with(|| {
    // Run for a series of blocks
    let mut first = true;
    for i in 1u8 ..= u8::MAX {
      new_block();
      assert_eq!(System::block_number(), BlockNumberFor::<Test>::from(i));

      let mut transactions = vec![];

      // Simulate the block's transaction
      {
        let mut block_transaction_id = [0; 32];
        block_transaction_id[31] = i;
        push_transaction(&mut transactions, block_transaction_id);
        end_transaction_checks(&mut transactions);
      }

      // Fuzz a variety of transactions within this block
      for _ in 0 .. (OsRng.next_u64() % 16) {
        fuzz_transaction(&mut transactions);
      }

      // If this is the `first` iteration, also perform a unit test around
      // how `emit_event` accepts `Into<serai_abi::Event>`
      if first {
        first = false;

        start_transaction(&mut transactions);

        // `emit_event` should accept `serai_abi::signals::Event` here
        let existing_events = System::events().len();
        let () = Core::emit_event(signals_event.clone());
        assert_eq!(System::events().len(), existing_events + 1);

        // But the checks should pass as if we passed `serai_abi::Event`
        emitted_event(&mut transactions, serai_abi::Event::Signals(signals_event.clone()));

        end_transaction(&mut transactions);
      }

      end_block();
    }
  });
}

#[test]
fn event_outside_of_transaction() {
  new_test_ext().execute_with(|| {
    // Emitting an event outside of a transaction should panic
    use serai_abi::primitives::{
      network_id::NetworkId,
      validator_sets::{Session, ValidatorSet},
    };
    let event = serai_abi::validator_sets::Event::AcceptedHandover {
      set: ValidatorSet { network: NetworkId::Serai, session: Session(0) },
    };
    std::panic::catch_unwind(|| Core::emit_event(event)).unwrap_err();
  });
}

#[test]
fn ending_transaction_outside_of_transaction() {
  new_test_ext().execute_with(|| {
    // Ending a transaction, without having started one, should panic
    std::panic::catch_unwind(|| Core::end_transaction([0xff; 32])).unwrap_err();
  });
}

#[test]
fn simultaneously_starting_transactions() {
  new_test_ext().execute_with(|| {
    Core::start_transaction(0);
    // Starting multiple transactions simultaneously should panic
    std::panic::catch_unwind(|| Core::start_transaction(0)).unwrap_err();
  });
}
