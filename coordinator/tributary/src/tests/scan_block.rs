use core::marker::PhantomData;
use std::collections::HashMap;
use rand::{Rng, RngCore};
use rand_core::OsRng;
use serai_substrate_tests::{random_block_hash, random_serai_address};

use ciphersuite::group::GroupEncoding;
use dalek_ff_group::RistrettoPoint;

use serai_primitives::address::SeraiAddress;

use messages::sign::VariantSignId;

use dkg::Participant;

use serai_db::{Db, DbTxn, MemDb};

use serai_cosign_types::CosignIntent;
use serai_coordinator_substrate::NewSetInformation;

use tributary_sdk::{Block, BlockHeader, Transaction as TributaryTransaction, P2p};

use crate::{
  db::{
    AccumulatedWeight, ActivelyCosigning, CosignIntents as DbCosignIntents,
    LatestSubstrateBlockToCosign, Topic, TributaryDb,
  },
  tests::{default_test_validator_set, random_serai_address_and_key},
};
use crate::transaction::{SigningProtocolRound, Signed, Transaction};
use crate::{CosignIntents, DkgConfirmationMessages, ProcessorMessages, ScanBlock, SubstrateBlockPlans};

#[derive(Clone)]
struct MockP2p;
impl P2p for MockP2p {
  fn broadcast(&self, _: [u8; 32], _: Vec<u8>) -> impl Send + core::future::Future<Output = ()> {
    async move { unimplemented!() }
  }
}

fn get_test_validators_and_weights_setup(
) -> (Vec<(SeraiAddress, u16)>, Vec<SeraiAddress>, HashMap<SeraiAddress, u16>, u16) {
  let validator_data = vec![
    (random_serai_address(&mut OsRng), 1u16),
    (random_serai_address(&mut OsRng), 1),
    (random_serai_address(&mut OsRng), 1),
  ];
  let validators: Vec<SeraiAddress> = validator_data.iter().map(|(a, _)| *a).collect();

  let mut weights = HashMap::new();
  for (address, weight) in &validator_data {
    weights.insert(*address, *weight);
  }

  (validator_data, validators, weights, 3)
}

fn new_test_set_info(validators: &[(SeraiAddress, u16)]) -> NewSetInformation {
  let mut participant_indexes = HashMap::new();
  let mut reverse_lookup = HashMap::new();
  let mut i = 1u16;
  for (address, weight) in validators {
    let mut indices = Vec::new();
    for _ in 0 .. *weight {
      let p = Participant::new(i).unwrap();
      indices.push(p);
      reverse_lookup.insert(p, *address);
      i += 1;
    }
    participant_indexes.insert(*address, indices);
  }

  NewSetInformation {
    set: default_test_validator_set(),
    serai_block: random_block_hash(&mut OsRng).0,
    declaration_time: OsRng.next_u64(),
    threshold: OsRng.gen_range(0 ..= u16::MAX),
    validators: validators.to_vec(),
    evrf_public_keys: vec![],
    participant_indexes,
    participant_indexes_reverse_lookup: reverse_lookup,
  }
}

fn make_scan_block<'a, TDT: DbTxn>(
  txn: &'a mut TDT,
  set_info: &'a NewSetInformation,
  validators: &'a [SeraiAddress],
  total_weight: u16,
  validator_weights: &'a HashMap<SeraiAddress, u16>,
) -> ScanBlock<'a, MemDb, TDT, MockP2p> {
  ScanBlock {
    _td: PhantomData,
    _p2p: PhantomData,
    tributary_txn: txn,
    set: set_info,
    validators,
    total_weight,
    validator_weights,
  }
}

/// Create a Signed with the given signer key and a dummy signature.
fn make_signed(signer: RistrettoPoint) -> Signed {
  Signed { signer, ..Signed::default() }
}

mod potentially_start_cosign {
  use super::*;

  #[test]
  fn potentially_start_cosign() {
    let set = default_test_validator_set();
    let (validator_data, validators, weights, total_weight) =
      get_test_validators_and_weights_setup();
    let set_info = new_test_set_info(&validator_data);

    // No TributaryDb::latest_substrate_block_to_cosign block: no-op
    {
      let mut db = MemDb::new();
      let mut txn = db.txn();
      {
        let mut scan_block =
          make_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
        scan_block.potentially_start_cosign();
      }
      assert!(ActivelyCosigning::get(&mut txn, set).is_none());
    }

    // Already cosigning: should not replace the actively cosigning block
    {
      let mut db = MemDb::new();
      let initial_block_hash = random_block_hash(&mut OsRng);

      {
        let mut txn = db.txn();
        TributaryDb::start_cosigning(&mut txn, set, initial_block_hash, OsRng.next_u64());
        let new_block_hash = random_block_hash(&mut OsRng);
        LatestSubstrateBlockToCosign::set(&mut txn, set, &new_block_hash);
        txn.commit();
      }

      let mut txn = db.txn();
      {
        let mut scan_block =
          make_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
        scan_block.potentially_start_cosign();
      }

      // Did not replace initial_block_hash for new_block_hash
      assert_eq!(ActivelyCosigning::get(&mut txn, set), Some(initial_block_hash));
    }

    // Already cosigned: no-op
    {
      let mut db = MemDb::new();
      let initial_block_hash = random_block_hash(&mut OsRng);

      {
        let mut txn = db.txn();
        LatestSubstrateBlockToCosign::set(&mut txn, set, &initial_block_hash);
        TributaryDb::mark_cosigned(&mut txn, set, initial_block_hash);
        txn.commit();
      }

      let mut txn = db.txn();
      {
        let mut scan_block =
          make_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
        scan_block.potentially_start_cosign();
      }

      assert!(ActivelyCosigning::get(&mut txn, set).is_none());
    }

    // Ready to cosign: starts cosigning and sends processor message
    {
      let mut db = MemDb::new();
      let block_hash = random_block_hash(&mut OsRng);
      let mut global_session = [0; 32];
      OsRng.fill_bytes(global_session.as_mut());

      let intent =
        CosignIntent { global_session, block_number: OsRng.next_u64(), block_hash, notable: false };

      {
        let mut txn = db.txn();
        LatestSubstrateBlockToCosign::set(&mut txn, set, &block_hash);
        CosignIntents::provide(&mut txn, set, &intent);
        txn.commit();
      }

      let mut txn = db.txn();
      {
        let mut scan_block =
          make_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
        scan_block.potentially_start_cosign();
      }

      assert_eq!(ActivelyCosigning::get(&mut txn, set), Some(block_hash));
      assert!(ProcessorMessages::try_recv(&mut txn, set).is_some());
    }
  }

  #[test]
  #[should_panic(expected = "provided CosignIntent wasn't saved by its block hash")]
  fn potentially_start_cosign_panics_on_differing_intent_blockhash() {
    let set = default_test_validator_set();
    let (validator_data, validators, weights, total_weight) =
      get_test_validators_and_weights_setup();
    let set_info = new_test_set_info(&validator_data);

    let mut db = MemDb::new();
    let block_hash = random_block_hash(&mut OsRng);
    let mut global_session = [0; 32];
    OsRng.fill_bytes(global_session.as_mut());

    {
      let mut txn = db.txn();
      LatestSubstrateBlockToCosign::set(&mut txn, set, &block_hash);

      let new_block_hash = random_block_hash(&mut OsRng);
      DbCosignIntents::set(
        &mut txn,
        set,
        // Store the intent under block_hash (the key `CosignIntents::take` will look up)
        block_hash,
        &CosignIntent {
          global_session,
          block_number: OsRng.next_u64(),
          // but the intent's block_hash field is a new_block_hash
          block_hash: new_block_hash, // triggering the assert_eq!(intent.block_hash, latest_substrate_block_to_cosign) panic
          notable: false,
        },
      );
      txn.commit();
    }

    {
      let mut txn = db.txn();
      let mut scan_block =
        make_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
      scan_block.potentially_start_cosign();
    }
  }
}

#[test]
fn accumulate_dkg_confirmation() {
  // Use 3 validators with weight 1 each so threshold math is deterministic:
  // total_weight = 3, required_participation = 3 * 2 = 6 / 3 = 2 + 1 = 3
  let v0 = random_serai_address(&mut OsRng);
  let v1 = random_serai_address(&mut OsRng);
  let v2 = random_serai_address(&mut OsRng);
  let validator_data = vec![(v0, 1u16), (v1, 1), (v2, 1)];
  let validators = vec![v0, v1, v2];
  let weights: HashMap<SeraiAddress, u16> = validator_data.iter().copied().collect();
  let total_weight = 3u16;
  let set_info = new_test_set_info(&validator_data);
  let set = set_info.set;
  let topic = Topic::DkgConfirmation { attempt: 0, round: SigningProtocolRound::Preprocess };

  // Below threshold: returns None until enough weight accumulates
  {
    let mut db = MemDb::new();
    let mut txn = db.txn();

    let mut scan_block = make_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

    let block_number = OsRng.next_u64();

    let mut data0 = vec![0u8; 4];
    OsRng.fill_bytes(&mut data0);

    assert!(scan_block.accumulate_dkg_confirmation(block_number, topic, &data0, v0).is_none());

    let mut data1 = vec![0u8; 4];
    OsRng.fill_bytes(&mut data1);

    assert!(scan_block.accumulate_dkg_confirmation(block_number, topic, &data1, v1).is_none());

    txn.commit();
  }

  // Threshold crossed: third accumulation returns SignId + correctly mapped data
  {
    let mut db = MemDb::new();
    let mut txn = db.txn();

    let mut data0 = vec![0u8; 4];
    OsRng.fill_bytes(&mut data0);
    let mut data1 = vec![0u8; 4];
    OsRng.fill_bytes(&mut data1);
    let mut data2 = vec![0u8; 4];
    OsRng.fill_bytes(&mut data2);

    let result;
    {
      let mut scan_block =
        make_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

      assert!(scan_block.accumulate_dkg_confirmation(1, topic, &data0, v0).is_none());
      assert!(scan_block.accumulate_dkg_confirmation(1, topic, &data1, v1).is_none());

      result = scan_block.accumulate_dkg_confirmation(1, topic, &data2, v2);
    }
    let (sign_id, data_set) = result.unwrap();

    // SignId must match what dkg_confirmation_sign_id produces
    assert_eq!(sign_id, topic.dkg_confirmation_sign_id(set).unwrap());

    // Participants are 1-indexed by list position, not by weight-based indices
    assert_eq!(data_set.len(), 3);
    assert_eq!(data_set[&Participant::new(1).unwrap()], data0);
    assert_eq!(data_set[&Participant::new(2).unwrap()], data1);
    assert_eq!(data_set[&Participant::new(3).unwrap()], data2);
  }

  // Past threshold: further accumulations are no-ops
  {
    let mut db = MemDb::new();
    let mut txn = db.txn();

    let mut data0 = vec![0u8; 4];
    OsRng.fill_bytes(&mut data0);
    let mut data1 = vec![0u8; 4];
    OsRng.fill_bytes(&mut data1);
    let mut data2 = vec![0u8; 4];
    OsRng.fill_bytes(&mut data2);
    let mut data_extra = vec![0u8; 4];
    OsRng.fill_bytes(&mut data_extra);

    {
      let mut scan_block =
        make_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
      scan_block.accumulate_dkg_confirmation(1, topic, &data0, v0);
      scan_block.accumulate_dkg_confirmation(1, topic, &data1, v1);
      scan_block.accumulate_dkg_confirmation(1, topic, &data2, v2);

      // Already past threshold - this returns None
      assert!(scan_block.accumulate_dkg_confirmation(1, topic, &data_extra, v0).is_none());
    }
  }
}

mod handle_application_tx {
  use super::*;

  #[test]
  fn dont_handle_from_fatally_slashed() {
    let set = default_test_validator_set();
    let (validator_data, validators, weights, total_weight) =
      get_test_validators_and_weights_setup();
    let set_info = new_test_set_info(&validator_data);
    let default_signer = SeraiAddress(Signed::default().signer().to_bytes());

    let mut db = MemDb::new();

    // Don't handle transactions from those fatally slashed.
    {
      let mut txn = db.txn();
      TributaryDb::fatal_slash(&mut txn, set, default_signer, "test reason");
      txn.commit();
    }

    let mut txn = db.txn();
    let mut scan_block = make_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

    scan_block.handle_application_tx(
      OsRng.next_u64(),
      Transaction::DkgParticipation { participation: vec![1, 2, 3], signed: Signed::default() },
    );

    assert!(ProcessorMessages::try_recv(&mut txn, set).is_none());
  }

  #[test]
  fn handle_remove_participant_tx_type() {
    let set = default_test_validator_set();
    let (validator_data, validators, weights, total_weight) =
      get_test_validators_and_weights_setup();
    let set_info = new_test_set_info(&validator_data);
    let default_signer = SeraiAddress(Signed::default().signer().to_bytes());

    // The signer is fatally slashed if the participant voted to be removed is nonexistent
    {
      let mut db = MemDb::new();
      let mut txn = db.txn();
      let mut scan_block =
        make_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

      let nonexistent = random_serai_address(&mut OsRng);

      scan_block.handle_application_tx(
        OsRng.next_u64(),
        Transaction::RemoveParticipant { participant: nonexistent, signed: Signed::default() },
      );

      assert!(TributaryDb::is_fatally_slashed(&mut txn, set, default_signer));
    }

    // Valid RemoveParticipant with a signer who IS a validator accumulates weight
    {
      // Fresh db so the signer isn't fatally slashed from the sub-test above
      let mut db = MemDb::new();
      let mut txn = db.txn();

      // Generate a signer that's actually in the validator set
      let (signer_key, signer_addr) = random_serai_address_and_key(&mut OsRng);
      let signer_weight = 1u16;

      let mut extended_validator_data = validator_data.clone();
      extended_validator_data.push((signer_addr, signer_weight));
      let extended_validators: Vec<SeraiAddress> =
        extended_validator_data.iter().map(|(a, _)| *a).collect();
      let mut extended_weights = weights.clone();
      extended_weights.insert(signer_addr, signer_weight);
      let extended_total_weight = total_weight + signer_weight;
      let extended_set_info = new_test_set_info(&extended_validator_data);

      let mut scan_block = make_scan_block(
        &mut txn,
        &extended_set_info,
        &extended_validators,
        extended_total_weight,
        &extended_weights,
      );

      // Target one of the original validators (not the signer)
      let target = validators[OsRng.gen_range(0 ..= validators.len() - 1)];

      scan_block.handle_application_tx(
        OsRng.next_u64(),
        Transaction::RemoveParticipant { participant: target, signed: make_signed(signer_key) },
      );

      assert!(AccumulatedWeight::get(
        &mut txn,
        set,
        Topic::RemoveParticipant { participant: target }
      )
      .is_some());
    }

    // When enough validators vote to remove a participant, the threshold is crossed
    // and the participant is fatally slashed (DataSet::Participating branch)
    {
      let mut db = MemDb::new();
      let mut txn = db.txn();

      // All 3 validators need real keys so they can sign
      let (key0, addr0) = random_serai_address_and_key(&mut OsRng);
      let (key1, addr1) = random_serai_address_and_key(&mut OsRng);
      let (key2, addr2) = random_serai_address_and_key(&mut OsRng);

      let validator_data = vec![(addr0, 1u16), (addr1, 1), (addr2, 1)];
      let validators: Vec<SeraiAddress> = validator_data.iter().map(|(a, _)| *a).collect();
      let weights: HashMap<SeraiAddress, u16> = validator_data.iter().copied().collect();
      let set_info = new_test_set_info(&validator_data);

      let target = addr0;
      let block_number = OsRng.next_u64();

      // First two votes accumulate but don't cross the threshold
      {
        let mut scan_block = make_scan_block(&mut txn, &set_info, &validators, 3, &weights);
        scan_block.handle_application_tx(
          block_number,
          Transaction::RemoveParticipant { participant: target, signed: make_signed(key1) },
        );
        scan_block.handle_application_tx(
          block_number,
          Transaction::RemoveParticipant { participant: target, signed: make_signed(key2) },
        );
      }
      assert!(!TributaryDb::is_fatally_slashed(&mut txn, set, target));

      // Third vote crosses the threshold — target gets fatally slashed
      {
        let mut scan_block = make_scan_block(&mut txn, &set_info, &validators, 3, &weights);
        scan_block.handle_application_tx(
          block_number,
          Transaction::RemoveParticipant { participant: target, signed: make_signed(key0) },
        );
      }
      assert!(TributaryDb::is_fatally_slashed(&mut txn, set, target));
    }
  }

  #[test]
  fn handle_dkg_participation_tx_type() {
    let mut db = MemDb::new();
    let set = default_test_validator_set();

    // Use a real validator key so the signer exists in participant_indexes
    let (signer_key, signer_addr) = random_serai_address_and_key(&mut OsRng);
    let validator_data = vec![
      (signer_addr, 1u16),
      (random_serai_address(&mut OsRng), 1),
      (random_serai_address(&mut OsRng), 1),
    ];
    let validators: Vec<SeraiAddress> = validator_data.iter().map(|(a, _)| *a).collect();
    let weights: HashMap<SeraiAddress, u16> = validator_data.iter().copied().collect();
    let set_info = new_test_set_info(&validator_data);

    let mut txn = db.txn();
    let mut scan_block = make_scan_block(&mut txn, &set_info, &validators, 3, &weights);

    scan_block.handle_application_tx(
      OsRng.next_u64(),
      Transaction::DkgParticipation {
        participation: vec![1, 2, 3],
        signed: make_signed(signer_key),
      },
    );

    assert!(ProcessorMessages::try_recv(&mut txn, set).is_some());
  }

  #[test]
  fn handle_dkg_confirmation_preprocess_tx_type() {
    let set = default_test_validator_set();

    let (key0, addr0) = random_serai_address_and_key(&mut OsRng);
    let (key1, addr1) = random_serai_address_and_key(&mut OsRng);
    let (key2, addr2) = random_serai_address_and_key(&mut OsRng);
    let validator_data = vec![(addr0, 1u16), (addr1, 1), (addr2, 1)];
    let validators: Vec<SeraiAddress> = validator_data.iter().map(|(a, _)| *a).collect();
    let weights: HashMap<SeraiAddress, u16> = validator_data.iter().copied().collect();
    let set_info = new_test_set_info(&validator_data);

    // Below threshold: no DkgConfirmationMessages sent
    {
      let mut db = MemDb::new();
      let mut txn = db.txn();
      let mut scan_block = make_scan_block(&mut txn, &set_info, &validators, 3, &weights);

      scan_block.handle_application_tx(
        OsRng.next_u64(),
        Transaction::DkgConfirmationPreprocess {
          attempt: OsRng.next_u32(),
          preprocess: [1u8; 64],
          signed: make_signed(key0),
        },
      );

      assert!(DkgConfirmationMessages::try_recv(&mut txn, set).is_none());
    }

    // Threshold crossed: sends DkgConfirmationMessages (Preprocesses)
    {
      let mut db = MemDb::new();
      let mut txn = db.txn();
      {
        let mut scan_block = make_scan_block(&mut txn, &set_info, &validators, 3, &weights);
        for (key, preprocess) in [(key0, [1u8; 64]), (key1, [2u8; 64]), (key2, [3u8; 64])] {
          scan_block.handle_application_tx(
            1,
            Transaction::DkgConfirmationPreprocess {
              attempt: 0,
              preprocess,
              signed: make_signed(key),
            },
          );
        }
      }

      assert!(DkgConfirmationMessages::try_recv(&mut txn, set).is_some());
    }
  }

  #[test]
  fn handle_dkg_confirmation_share_tx_type() {
    let set = default_test_validator_set();

    let (key0, addr0) = random_serai_address_and_key(&mut OsRng);
    let (_, addr1) = random_serai_address_and_key(&mut OsRng);
    let (_, addr2) = random_serai_address_and_key(&mut OsRng);
    let validator_data = vec![(addr0, 1u16), (addr1, 1), (addr2, 1)];
    let validators: Vec<SeraiAddress> = validator_data.iter().map(|(a, _)| *a).collect();
    let weights: HashMap<SeraiAddress, u16> = validator_data.iter().copied().collect();
    let set_info = new_test_set_info(&validator_data);

    // Share without preceding preprocess participation → fatal slash
    // (the accumulate preceding_topic check slashes the signer)
    {
      let mut db = MemDb::new();
      let mut txn = db.txn();
      let mut scan_block = make_scan_block(&mut txn, &set_info, &validators, 3, &weights);

      scan_block.handle_application_tx(
        1,
        Transaction::DkgConfirmationShare {
          attempt: 0,
          share: [10u8; 32],
          signed: make_signed(key0),
        },
      );

      assert!(TributaryDb::is_fatally_slashed(&mut txn, set, addr0));
    }
  }

  /// Verify that the full preprocess→share flow works for DkgConfirmation.
  ///
  /// Previously, this panicked because `accumulate<[u8; 32]>` (share) used typed deserialization
  /// on the preceding preprocess topic stored as `[u8; 64]`. Fixed by using a raw key-existence
  /// check for the preceding topic instead.
  #[test]
  fn dkg_confirmation_preprocess_then_share_flow() {
    let set = default_test_validator_set();

    let (key0, addr0) = random_serai_address_and_key(&mut OsRng);
    let (key1, addr1) = random_serai_address_and_key(&mut OsRng);
    let (key2, addr2) = random_serai_address_and_key(&mut OsRng);
    let validator_data = vec![(addr0, 1u16), (addr1, 1), (addr2, 1)];
    let validators: Vec<SeraiAddress> = validator_data.iter().map(|(a, _)| *a).collect();
    let weights: HashMap<SeraiAddress, u16> = validator_data.iter().copied().collect();
    let set_info = new_test_set_info(&validator_data);

    let mut db = MemDb::new();
    let mut txn = db.txn();

    // All 3 validators submit preprocesses (threshold crossed → DkgConfirmationMessages sent)
    {
      let mut scan_block = make_scan_block(&mut txn, &set_info, &validators, 3, &weights);
      for (key, preprocess) in [(key0, [1u8; 64]), (key1, [2u8; 64]), (key2, [3u8; 64])] {
        scan_block.handle_application_tx(
          1,
          Transaction::DkgConfirmationPreprocess {
            attempt: 0,
            preprocess,
            signed: make_signed(key),
          },
        );
      }
    }
    assert!(DkgConfirmationMessages::try_recv(&mut txn, set).is_some());

    // All 3 validators submit shares (threshold crossed → DkgConfirmationMessages sent)
    {
      let mut scan_block = make_scan_block(&mut txn, &set_info, &validators, 3, &weights);
      for (key, share) in [(key0, [10u8; 32]), (key1, [20u8; 32]), (key2, [30u8; 32])] {
        scan_block.handle_application_tx(
          1,
          Transaction::DkgConfirmationShare { attempt: 0, share, signed: make_signed(key) },
        );
      }
    }
    assert!(DkgConfirmationMessages::try_recv(&mut txn, set).is_some());
  }

  #[test]
  fn handle_cosign_tx_type() {
    let set = default_test_validator_set();
    let (validator_data, validators, weights, total_weight) =
      get_test_validators_and_weights_setup();
    let set_info = new_test_set_info(&validator_data);

    let block_hash = random_block_hash(&mut OsRng);
    let mut global_session = [0u8; 32];
    OsRng.fill_bytes(&mut global_session);

    let intent =
      CosignIntent { global_session, block_number: OsRng.next_u64(), block_hash, notable: false };

    // Sets LatestSubstrateBlockToCosign and starts cosigning
    {
      let mut db = MemDb::new();
      {
        let mut txn = db.txn();
        CosignIntents::provide(&mut txn, set, &intent);
        txn.commit();
      }

      let mut txn = db.txn();
      let mut scan_block =
        make_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

      scan_block.handle_application_tx(1, Transaction::Cosign { substrate_block_hash: block_hash });

      assert_eq!(LatestSubstrateBlockToCosign::get(&mut txn, set), Some(block_hash));
      assert_eq!(ActivelyCosigning::get(&mut txn, set), Some(block_hash));
      assert!(ProcessorMessages::try_recv(&mut txn, set).is_some());
    }

    // When already cosigning, updates LatestSubstrateBlockToCosign but doesn't replace active
    {
      let mut db = MemDb::new();
      let first_hash = random_block_hash(&mut OsRng);
      let second_hash = random_block_hash(&mut OsRng);

      {
        let mut txn = db.txn();
        TributaryDb::start_cosigning(&mut txn, set, first_hash, 1);
        txn.commit();
      }

      let mut txn = db.txn();
      let mut scan_block =
        make_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

      scan_block
        .handle_application_tx(1, Transaction::Cosign { substrate_block_hash: second_hash });

      assert_eq!(LatestSubstrateBlockToCosign::get(&mut txn, set), Some(second_hash));
      assert_eq!(ActivelyCosigning::get(&mut txn, set), Some(first_hash));
    }
  }

  #[test]
  fn handle_cosigned_tx_type() {
    let set = default_test_validator_set();
    let (validator_data, validators, weights, total_weight) =
      get_test_validators_and_weights_setup();
    let set_info = new_test_set_info(&validator_data);

    // Marks block as cosigned
    {
      let mut db = MemDb::new();
      let block_hash = random_block_hash(&mut OsRng);
      let mut txn = db.txn();

      assert!(!TributaryDb::cosigned(&mut txn, set, block_hash));

      let mut scan_block =
        make_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

      scan_block
        .handle_application_tx(1, Transaction::Cosigned { substrate_block_hash: block_hash });

      assert!(TributaryDb::cosigned(&mut txn, set, block_hash));
    }

    // Finishes active cosign when matching block
    {
      let mut db = MemDb::new();
      let block_hash = random_block_hash(&mut OsRng);

      {
        let mut txn = db.txn();
        TributaryDb::start_cosigning(&mut txn, set, block_hash, 1);
        txn.commit();
      }

      let mut txn = db.txn();
      assert_eq!(ActivelyCosigning::get(&mut txn, set), Some(block_hash));

      let mut scan_block =
        make_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

      scan_block
        .handle_application_tx(1, Transaction::Cosigned { substrate_block_hash: block_hash });

      assert!(ActivelyCosigning::get(&mut txn, set).is_none());
    }

    // Does not finish active cosign when block doesn't match
    {
      let mut db = MemDb::new();
      let active_hash = random_block_hash(&mut OsRng);
      let other_hash = random_block_hash(&mut OsRng);

      {
        let mut txn = db.txn();
        TributaryDb::start_cosigning(&mut txn, set, active_hash, 1);
        txn.commit();
      }

      let mut txn = db.txn();
      let mut scan_block =
        make_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

      scan_block
        .handle_application_tx(1, Transaction::Cosigned { substrate_block_hash: other_hash });

      assert_eq!(ActivelyCosigning::get(&mut txn, set), Some(active_hash));
      assert!(TributaryDb::cosigned(&mut txn, set, other_hash));
    }
  }

  #[test]
  fn handle_substrate_block_tx_type() {
    let set = default_test_validator_set();
    let (validator_data, validators, weights, total_weight) =
      get_test_validators_and_weights_setup();
    let set_info = new_test_set_info(&validator_data);

    let mut db = MemDb::new();
    let block_hash = random_block_hash(&mut OsRng);
    let plans = vec![[10u8; 32], [20u8; 32]];

    {
      let mut txn = db.txn();
      SubstrateBlockPlans::set(&mut txn, set, block_hash, &plans);
      txn.commit();
    }

    let mut txn = db.txn();
    let mut scan_block = make_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

    scan_block.handle_application_tx(1, Transaction::SubstrateBlock { hash: block_hash });

    for plan in &plans {
      let topic = Topic::Sign {
        id: VariantSignId::Transaction(*plan),
        attempt: 0,
        round: SigningProtocolRound::Preprocess,
      };
      assert!(AccumulatedWeight::get(&mut txn, set, topic).is_some());
    }
  }

  #[test]
  fn handle_batch_tx_type() {
    let set = default_test_validator_set();
    let (validator_data, validators, weights, total_weight) =
      get_test_validators_and_weights_setup();
    let set_info = new_test_set_info(&validator_data);

    let mut db = MemDb::new();
    let batch_hash = [42u8; 32];

    let mut txn = db.txn();
    let mut scan_block = make_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

    scan_block.handle_application_tx(1, Transaction::Batch { hash: batch_hash });

    let topic = Topic::Sign {
      id: VariantSignId::Batch(batch_hash),
      attempt: 0,
      round: SigningProtocolRound::Preprocess,
    };
    assert!(AccumulatedWeight::get(&mut txn, set, topic).is_some());
  }

  #[test]
  fn handle_sign_tx_type() {
    let set = default_test_validator_set();

    let (key0, addr0) = random_serai_address_and_key(&mut OsRng);
    let (key1, addr1) = random_serai_address_and_key(&mut OsRng);
    let (key2, addr2) = random_serai_address_and_key(&mut OsRng);
    let validator_data = vec![(addr0, 1u16), (addr1, 1), (addr2, 1)];
    let validators: Vec<SeraiAddress> = validator_data.iter().map(|(a, _)| *a).collect();
    let weights: HashMap<SeraiAddress, u16> = validator_data.iter().copied().collect();
    let set_info = new_test_set_info(&validator_data);

    let sign_id = VariantSignId::Transaction([42; 32]);
    let topic = Topic::Sign { id: sign_id, attempt: 0, round: SigningProtocolRound::Preprocess };

    // Wrong data length: signer has weight 1 but submits 2 entries → fatal slash
    {
      let mut db = MemDb::new();
      let mut txn = db.txn();
      TributaryDb::recognize_topic(&mut txn, set, topic);

      let mut scan_block = make_scan_block(&mut txn, &set_info, &validators, 3, &weights);
      scan_block.handle_application_tx(
        1,
        Transaction::Sign {
          id: sign_id,
          attempt: 0,
          round: SigningProtocolRound::Preprocess,
          data: vec![vec![1], vec![2]],
          signed: make_signed(key0),
        },
      );

      assert!(TributaryDb::is_fatally_slashed(&mut txn, set, addr0));
    }

    // Valid data: threshold crossing sends ProcessorMessage
    {
      let mut db = MemDb::new();
      let mut txn = db.txn();
      TributaryDb::recognize_topic(&mut txn, set, topic);

      {
        let mut scan_block = make_scan_block(&mut txn, &set_info, &validators, 3, &weights);
        for key in [key0, key1, key2] {
          scan_block.handle_application_tx(
            1,
            Transaction::Sign {
              id: sign_id,
              attempt: 0,
              round: SigningProtocolRound::Preprocess,
              data: vec![vec![1, 2, 3]],
              signed: make_signed(key),
            },
          );
        }
      }

      assert!(ProcessorMessages::try_recv(&mut txn, set).is_some());
    }
  }

  #[test]
  fn handle_slash_report_tx_type() {
    let set = default_test_validator_set();

    let (key0, addr0) = random_serai_address_and_key(&mut OsRng);
    let (_, addr1) = random_serai_address_and_key(&mut OsRng);
    let (_, addr2) = random_serai_address_and_key(&mut OsRng);
    let validator_data = vec![(addr0, 1u16), (addr1, 1), (addr2, 1)];
    let validators: Vec<SeraiAddress> = validator_data.iter().map(|(a, _)| *a).collect();
    let weights: HashMap<SeraiAddress, u16> = validator_data.iter().copied().collect();
    let set_info = new_test_set_info(&validator_data);

    // Wrong length: 3 validators but only 2 slash points → fatal slash
    {
      let mut db = MemDb::new();
      let mut txn = db.txn();
      let mut scan_block = make_scan_block(&mut txn, &set_info, &validators, 3, &weights);

      scan_block.handle_application_tx(
        1,
        Transaction::SlashReport { slash_points: vec![0, 0], signed: make_signed(key0) },
      );

      assert!(TributaryDb::is_fatally_slashed(&mut txn, set, addr0));
    }

    // Valid length: accumulates weight
    {
      let mut db = MemDb::new();
      let mut txn = db.txn();
      let mut scan_block = make_scan_block(&mut txn, &set_info, &validators, 3, &weights);

      scan_block.handle_application_tx(
        1,
        Transaction::SlashReport { slash_points: vec![0, 0, 0], signed: make_signed(key0) },
      );

      assert!(AccumulatedWeight::get(&mut txn, set, Topic::SlashReport).is_some());
    }

    // Threshold crossed: computes median slash report and sends SignSlashReport message.
    // Uses 4 validators so f = (4-1)/3 = 1, allowing up to 1 slashed validator.
    {
      let mut db = MemDb::new();
      let mut txn = db.txn();

      let (key0, addr0) = random_serai_address_and_key(&mut OsRng);
      let (key1, addr1) = random_serai_address_and_key(&mut OsRng);
      let (key2, addr2) = random_serai_address_and_key(&mut OsRng);
      let (_, addr3) = random_serai_address_and_key(&mut OsRng);
      let validator_data = vec![(addr0, 1u16), (addr1, 1), (addr2, 1), (addr3, 1)];
      let validators: Vec<SeraiAddress> = validator_data.iter().map(|(a, _)| *a).collect();
      let weights: HashMap<SeraiAddress, u16> = validator_data.iter().copied().collect();
      let set_info = new_test_set_info(&validator_data);

      // Each reporter says: first 3 validators have 0 points, 4th has 100
      // required_participation = 4*2/3+1 = 3, so 3 submissions cross the threshold
      {
        let mut scan_block = make_scan_block(&mut txn, &set_info, &validators, 4, &weights);
        for key in [key0, key1, key2] {
          scan_block.handle_application_tx(
            1,
            Transaction::SlashReport { slash_points: vec![0, 0, 0, 100], signed: make_signed(key) },
          );
        }
      }

      assert!(ProcessorMessages::try_recv(&mut txn, set).is_some());
    }
  }

  mod fuzz_slash_report {
    use super::*;
    use proptest::prelude::*;

    /// Independently compute the expected slash report that `handle_application_tx` should
    /// produce when `DataSet::Participating` is reached, mirroring the production logic.
    ///
    /// Returns `None` if `f == 0` (the slash report would be empty and nothing is sent).
    fn expected_slash_report(num_validators: usize, reports: &[Vec<u32>]) -> Option<Vec<u32>> {
      let f = (num_validators - 1) / 3;
      if f == 0 {
        return None;
      }

      // Compute the median for each validator position across all reporters
      let mut medians = Vec::with_capacity(num_validators);
      for i in 0 .. num_validators {
        let mut values: Vec<u32> = reports.iter().map(|r| r[i]).collect();
        values.sort_unstable();
        let median_index =
          if (values.len() % 2) == 1 { values.len() / 2 } else { (values.len() / 2) - 1 };
        medians.push(values[median_index]);
      }

      // Find worst validator in the supermajority and amortize
      let mut sorted = medians.clone();
      sorted.sort_unstable();
      let amortization = sorted[num_validators - f - 1];

      let amortized: Vec<u32> = medians.iter().map(|p| p.saturating_sub(amortization)).collect();

      // Filter to non-zero entries only
      let result: Vec<u32> = amortized.into_iter().filter(|&p| p > 0).collect();
      Some(result)
    }

    /// Generate `count` slash report vectors, each of length `num_validators`.
    /// Values are drawn from a small set including 0, small values, large values, and u32::MAX
    /// to exercise the Fatal/Points/zero filtering paths.
    fn slash_points_strategy(
      num_validators: usize,
      count: usize,
    ) -> impl Strategy<Value = Vec<Vec<u32>>> {
      let values = prop::collection::vec(
        prop_oneof![
          3 => Just(0u32),
          3 => 1..100u32,
          2 => 100..10_000u32,
          1 => Just(u32::MAX),
        ],
        num_validators,
      );
      prop::collection::vec(values, count)
    }

    proptest! {
      #![proptest_config(ProptestConfig::with_cases(200))]

      /// Fuzz the SlashReport → Participating path with randomized slash point vectors.
      ///
      /// Uses 4 validators (f=1) so the threshold-crossing path is reachable.
      /// All 4 submit identical reports so the median equals the input.
      #[test]
      fn fuzz_slash_report_participating_4_validators(
        slash_points in slash_points_strategy(4, 1).prop_map(|mut v| v.remove(0)),
      ) {
        let set = default_test_validator_set();

        let (key0, addr0) = random_serai_address_and_key(&mut OsRng);
        let (key1, addr1) = random_serai_address_and_key(&mut OsRng);
        let (key2, addr2) = random_serai_address_and_key(&mut OsRng);
        let (key3, addr3) = random_serai_address_and_key(&mut OsRng);
        let validator_data = vec![(addr0, 1u16), (addr1, 1), (addr2, 1), (addr3, 1)];
        let validators: Vec<SeraiAddress> = validator_data.iter().map(|(a, _)| *a).collect();
        let weights: HashMap<SeraiAddress, u16> = validator_data.iter().copied().collect();
        let set_info = new_test_set_info(&validator_data);

        let mut db = MemDb::new();
        let mut txn = db.txn();

        // All 4 validators submit the same slash_points
        // required_participation = 4*2/3+1 = 3, so 3 cross the threshold.
        // The 4th submission is a NOP (past threshold).
        let reports: Vec<Vec<u32>> = vec![slash_points.clone(); 3];
        let expected = expected_slash_report(4, &reports);

        {
          let mut scan_block = make_scan_block(&mut txn, &set_info, &validators, 4, &weights);
          for (key, _) in [(key0, &addr0), (key1, &addr1), (key2, &addr2), (key3, &addr3)] {
            scan_block.handle_application_tx(
              1,
              Transaction::SlashReport {
                slash_points: slash_points.clone(),
                signed: make_signed(key),
              },
            );
          }
        }

        match expected {
          Some(result) if !result.is_empty() => {
            // Non-empty slash report → message should be sent
            prop_assert!(
              ProcessorMessages::try_recv(&mut txn, set).is_some(),
              "expected ProcessorMessage for non-empty slash report {:?}",
              result
            );
          }
          _ => {
            // Empty or f==0 → no message sent (slash report is empty, nothing to sign)
            // The code still sends the message even for empty reports due to the assert
            // passing with len=0 <= f. Verify it gets sent regardless.
            //
            // With our fix, Points(0) are filtered, so if all amortized values are 0,
            // the slash_report is empty. The assert passes (0 <= f=1), and the code still
            // recognizes the topic and sends the message.
            let msg = ProcessorMessages::try_recv(&mut txn, set);
            // The handler always sends a message when Participating is reached
            prop_assert!(msg.is_some(), "expected ProcessorMessage even for empty slash report");
          }
        }

        // Verify the SlashReport signing topic was recognized
        let sign_topic = Topic::Sign {
          id: VariantSignId::SlashReport,
          attempt: 0,
          round: SigningProtocolRound::Preprocess,
        };
        prop_assert!(
          AccumulatedWeight::get(&mut txn, set, sign_topic).is_some(),
          "SlashReport sign topic should be recognized"
        );
      }

      /// Fuzz with varying reporter opinions (not all identical).
      /// Uses 7 validators (f=2) for a richer median calculation.
      #[test]
      fn fuzz_slash_report_diverse_opinions_7_validators(
        reports in slash_points_strategy(7, 5),
      ) {
        let set = default_test_validator_set();

        // 7 validators, f = (7-1)/3 = 2
        let keys_addrs: Vec<(RistrettoPoint, SeraiAddress)> =
          (0 .. 7).map(|_| random_serai_address_and_key(&mut OsRng)).collect();
        let validator_data: Vec<(SeraiAddress, u16)> =
          keys_addrs.iter().map(|(_, addr)| (*addr, 1u16)).collect();
        let validators: Vec<SeraiAddress> = validator_data.iter().map(|(a, _)| *a).collect();
        let weights: HashMap<SeraiAddress, u16> = validator_data.iter().copied().collect();
        let set_info = new_test_set_info(&validator_data);

        // required_participation = 7*2/3+1 = 5
        // We have 5 reports from 5 different validators to cross the threshold
        let expected = expected_slash_report(7, &reports[..5]);

        let mut db = MemDb::new();
        let mut txn = db.txn();

        {
          let mut scan_block = make_scan_block(&mut txn, &set_info, &validators, 7, &weights);
          for (i, report) in reports.iter().enumerate() {
            let (key, _) = keys_addrs[i];
            scan_block.handle_application_tx(
              1,
              Transaction::SlashReport {
                slash_points: report.clone(),
                signed: make_signed(key),
              },
            );
          }
        }

        // Verify the expected result
        match expected {
          Some(result) => {
            prop_assert!(result.len() <= 2, "slash report len {} should be <= f=2", result.len());
          }
          None => {
            // f == 0, which can't happen with 7 validators
            unreachable!();
          }
        }

        // Participating path was reached → message and topic recognition
        prop_assert!(ProcessorMessages::try_recv(&mut txn, set).is_some());
        let sign_topic = Topic::Sign {
          id: VariantSignId::SlashReport,
          attempt: 0,
          round: SigningProtocolRound::Preprocess,
        };
        prop_assert!(AccumulatedWeight::get(&mut txn, set, sign_topic).is_some());
      }

      /// Fuzz the wrong-length path: slash_points.len() != validators.len() → fatal slash
      #[test]
      fn fuzz_slash_report_wrong_length(
        num_validators in 4usize..10,
        wrong_len in 1usize..20,
      ) {
        prop_assume!(wrong_len != num_validators);

        let set = default_test_validator_set();

        let keys_addrs: Vec<(RistrettoPoint, SeraiAddress)> =
          (0 .. num_validators).map(|_| random_serai_address_and_key(&mut OsRng)).collect();
        let validator_data: Vec<(SeraiAddress, u16)> =
          keys_addrs.iter().map(|(_, addr)| (*addr, 1u16)).collect();
        let validators: Vec<SeraiAddress> = validator_data.iter().map(|(a, _)| *a).collect();
        let weights: HashMap<SeraiAddress, u16> = validator_data.iter().copied().collect();
        let set_info = new_test_set_info(&validator_data);
        let total_weight = num_validators as u16;

        let mut db = MemDb::new();
        let mut txn = db.txn();

        let (signer_key, signer_addr) = keys_addrs[0];

        {
          let mut scan_block =
            make_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
          scan_block.handle_application_tx(
            1,
            Transaction::SlashReport {
              slash_points: vec![0; wrong_len],
              signed: make_signed(signer_key),
            },
          );
        }

        prop_assert!(
          TributaryDb::is_fatally_slashed(&mut txn, set, signer_addr),
          "signer should be fatally slashed for wrong-length slash report"
        );
        prop_assert!(
          ProcessorMessages::try_recv(&mut txn, set).is_none(),
          "no message should be sent for wrong-length slash report"
        );
      }
    }
  }
}

mod handle_block {
  use super::*;

  #[test]
  fn processes_application_transactions() {
    let mut db = MemDb::new();
    let set = default_test_validator_set();
    let batch_hash = [42; 32];
    let (validator_data, validators, weights, total_weight) =
      get_test_validators_and_weights_setup();
    let set_info = new_test_set_info(&validator_data);

    let block = Block {
      header: BlockHeader { parent: [0; 32], transactions: [0; 32] },
      transactions: vec![TributaryTransaction::Application(Transaction::Batch {
        hash: batch_hash,
      })],
    };

    let mut txn = db.txn();
    let scan_block = make_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

    scan_block.handle_block(1, block);
    txn.commit();

    let topic = Topic::Sign {
      id: VariantSignId::Batch(batch_hash),
      attempt: 0,
      round: SigningProtocolRound::Preprocess,
    };
    assert!(TributaryDb::recognized(&db, set, topic));
  }

  #[test]
  fn empty_block_only_calls_start_of_block() {
    let mut db = MemDb::new();
    let set = default_test_validator_set();
    let (validator_data, validators, weights, total_weight) =
      get_test_validators_and_weights_setup();
    let set_info = new_test_set_info(&validator_data);

    let block = Block {
      header: BlockHeader { parent: [0; 32], transactions: [0; 32] },
      transactions: vec![],
    };

    let mut txn = db.txn();
    let scan_block = make_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

    scan_block.handle_block(1, block);
    txn.commit();

    // No messages, no state changes beyond start_of_block
    let mut txn = db.txn();
    assert!(ProcessorMessages::try_recv(&mut txn, set).is_none());
  }

  #[test]
  fn multiple_application_txs_in_one_block() {
    let mut db = MemDb::new();
    let set = default_test_validator_set();
    let batch_hash_a = [10; 32];
    let batch_hash_b = [20; 32];
    let (validator_data, validators, weights, total_weight) =
      get_test_validators_and_weights_setup();
    let set_info = new_test_set_info(&validator_data);

    let block = Block {
      header: BlockHeader { parent: [0; 32], transactions: [0; 32] },
      transactions: vec![
        TributaryTransaction::Application(Transaction::Batch { hash: batch_hash_a }),
        TributaryTransaction::Application(Transaction::Batch { hash: batch_hash_b }),
      ],
    };

    let mut txn = db.txn();
    let scan_block = make_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

    scan_block.handle_block(1, block);
    txn.commit();

    for hash in [batch_hash_a, batch_hash_b] {
      let topic = Topic::Sign {
        id: VariantSignId::Batch(hash),
        attempt: 0,
        round: SigningProtocolRound::Preprocess,
      };
      assert!(TributaryDb::recognized(&db, set, topic));
    }
  }
}
