use core::marker::PhantomData;
use std::collections::HashMap;
use rand::RngCore;
use rand_core::OsRng;
use serai_primitives::test_helpers::{
  random_block_hash, random_block_number, random_bytes_32, random_serai_address, random_vec_of_len,
};

use ciphersuite::{group::GroupEncoding, WrappedGroup};
use dalek_ff_group::{Ristretto, RistrettoPoint};
use schnorr::SchnorrSignature;

use serai_primitives::address::SeraiAddress;

use messages::sign::VariantSignId;

use dkg::Participant;

use serai_db::{Db, DbTxn, MemDb};

use serai_cosign_types::CosignIntent;
use serai_coordinator_substrate::NewSetInformation;

use tributary_sdk::{
  Block, BlockHeader, Transaction as TributaryTransaction, Evidence, tendermint::tx::TendermintTx,
};

use crate::{
  CosignIntents, DkgConfirmationMessages, ProcessorMessages, ScanBlock, SubstrateBlockPlans,
  db::{
    AccumulatedWeight, ActivelyCosigning, CosignIntents as DbCosignIntents,
    LatestSubstrateBlockToCosign, Topic, TributaryDb,
  },
  transaction::{SigningProtocolRound, Signed, Transaction},
  tests::{
    all_signed_transactions_with, assert_cosigning_invariants, MockP2p, default_test_validator_set,
    expected_topic_after_start_cosigning, setup_test_validators_and_weights,
    setup_test_validators_and_weights_with_keys, random_serai_address_and_key, new_test_set_info,
  },
};

fn new_scan_block<'a, TDT: DbTxn>(
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

/// Create a Signed with the given signer key and a random signature.
fn new_signed(signer: RistrettoPoint) -> Signed {
  Signed {
    signer,
    signature: SchnorrSignature {
      R: Ristretto::generator() * <Ristretto as WrappedGroup>::F::random(&mut OsRng),
      s: <Ristretto as WrappedGroup>::F::random(&mut OsRng),
    },
  }
}

#[test]
fn potentially_start_cosign() {
  let (validator_data, validators, weights, total_weight) = setup_test_validators_and_weights();
  let set_info = new_test_set_info(&validator_data);
  let set = set_info.set;

  // Already actively cosigning: should not replace the actively cosigning block
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
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
      scan_block.potentially_start_cosign();
    }

    // Did not replace initial_block_hash for new_block_hash
    assert_eq!(ActivelyCosigning::get(&mut txn, set), Some(initial_block_hash));
  }

  // No TributaryDb::latest_substrate_block_to_cosign block: no-op
  {
    let mut db = MemDb::new();
    let mut txn = db.txn();
    {
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
      scan_block.potentially_start_cosign();
    }
    assert!(ActivelyCosigning::get(&mut txn, set).is_none());
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
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
      scan_block.potentially_start_cosign();
    }

    assert!(ActivelyCosigning::get(&mut txn, set).is_none());
  }

  // Ready to cosign: starts cosigning and sends processor message
  {
    let mut db = MemDb::new();
    let block_hash = random_block_hash(&mut OsRng);
    let global_session = random_bytes_32(&mut OsRng);

    let intent = CosignIntent {
      global_session,
      block_number: random_block_number(&mut OsRng),
      block_hash,
      notable: false,
    };

    {
      let mut txn = db.txn();
      LatestSubstrateBlockToCosign::set(&mut txn, set, &block_hash);
      CosignIntents::provide(&mut txn, set, &intent);
      txn.commit();
    }

    let mut txn = db.txn();
    {
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
      scan_block.potentially_start_cosign();
    }

    assert_cosigning_invariants(&mut txn, set, block_hash, intent.block_number);
    assert!(ProcessorMessages::try_recv(&mut txn, set).is_some());
  }

  // Panics when stored intent's block_hash differs from latest_substrate_block_to_cosign
  {
    let mut db = MemDb::new();
    let block_hash = random_block_hash(&mut OsRng);
    let global_session = random_bytes_32(&mut OsRng);

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
          block_number: random_block_number(&mut OsRng),
          // but the intent's block_hash field is a new_block_hash
          block_hash: new_block_hash,
          notable: false,
        },
      );
      txn.commit();
    }

    let result = std::panic::catch_unwind(move || {
      let mut txn = db.txn();
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
      scan_block.potentially_start_cosign();
    });
    let err = result.expect_err("should panic on differing intent block hash");
    let msg = err.downcast_ref::<String>().expect("panic payload should be a String");
    assert!(
      msg.contains("provided CosignIntent wasn't saved by its block hash"),
      "unexpected panic message: {msg}"
    );
  }
}

#[test]
fn accumulate_dkg_confirmation() {
  let (validator_data, validators, weights, total_weight) = setup_test_validators_and_weights();
  let (v1, v2, v3) = (validators[0], validators[1], validators[2]);
  let set_info = new_test_set_info(&validator_data);
  let set = set_info.set;
  let topic = Topic::DkgConfirmation { attempt: 0, round: SigningProtocolRound::Preprocess };

  // Panics if the topic isn't DkgConfirmation
  {
    let mut db = MemDb::new();
    let mut txn = db.txn();

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
      scan_block.accumulate_dkg_confirmation(
        random_block_number(&mut OsRng),
        Topic::RemoveParticipant { participant: random_serai_address(&mut OsRng) },
        &random_vec_of_len(&mut OsRng, 4),
        validators[0],
      );
    }));

    assert!(result.is_err(), "should panic when called with a non-DkgConfirmation topic");
  }

  // Threshold crossed: third accumulation returns SignId + correctly mapped data
  {
    let mut db = MemDb::new();
    let mut txn = db.txn();
    let block_number = random_block_number(&mut OsRng);

    {
      let data1 = random_vec_of_len(&mut OsRng, 4);
      let data2 = random_vec_of_len(&mut OsRng, 4);
      let data3 = random_vec_of_len(&mut OsRng, 4);

      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

      assert!(scan_block.accumulate_dkg_confirmation(block_number, topic, &data1, v1).is_none());
      assert!(scan_block.accumulate_dkg_confirmation(block_number, topic, &data2, v2).is_none());
      let result = scan_block.accumulate_dkg_confirmation(block_number, topic, &data3, v3);

      let (sign_id, data_set) = result.expect("third accumulation should cross threshold");

      assert_eq!(
        sign_id,
        topic.dkg_confirmation_sign_id(set).unwrap(),
        "SignId must match what dkg_confirmation_sign_id produces"
      );

      // Participants are 1-indexed by list position, not by weight-based indices
      assert_eq!(data_set.len(), 3);
      assert_eq!(data_set[&Participant::new(1).unwrap()], data1);
      assert_eq!(data_set[&Participant::new(2).unwrap()], data2);
      assert_eq!(data_set[&Participant::new(3).unwrap()], data3);
    }

    // Past threshold: further accumulations from a new validator are no-ops
    {
      // Add a 4th validator so we have a fresh signer after threshold is crossed.
      // total_weight=4, required_participation = 3, so v0+v1+v2 cross threshold.
      let v4 = random_serai_address(&mut OsRng);
      let mut validator_data_4 = validator_data.clone();
      validator_data_4.push((v4, 1));
      let validators_4: Vec<SeraiAddress> = validator_data_4.iter().map(|(a, _)| *a).collect();
      let mut weights_4 = weights.clone();
      weights_4.insert(v4, 1);
      let set_info_4 = new_test_set_info(&validator_data_4);

      let data4 = random_vec_of_len(&mut OsRng, 4);

      {
        let mut scan_block = new_scan_block(&mut txn, &set_info_4, &validators_4, 4, &weights_4);
        assert!(
          scan_block.accumulate_dkg_confirmation(block_number, topic, &data4, v4).is_none(),
          "accumulation after threshold should be a NOP"
        );
      }
    }
  }
}

mod handle_application_tx {
  use super::*;

  #[test]
  fn dont_handle_signed_kind_from_fatally_slashed() {
    let set = default_test_validator_set();
    let (validator_data, validators, weights, total_weight) = setup_test_validators_and_weights();
    let set_info = new_test_set_info(&validator_data);
    let default_signer = SeraiAddress(Signed::default().signer().to_bytes());

    let mut db = MemDb::new();

    {
      let mut txn = db.txn();
      TributaryDb::fatal_slash(&mut txn, set, default_signer, "test reason");
      txn.commit();
    }

    for tx in all_signed_transactions_with(Signed::default()) {
      let mut txn = db.txn();
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

      scan_block.handle_application_tx(random_block_number(&mut OsRng), tx.clone());

      assert!(
        ProcessorMessages::try_recv(&mut txn, set).is_none(),
        "fatally slashed signer should be ignored for {tx:?}"
      );
    }
  }

  #[test]
  fn remove_participant() {
    let set = default_test_validator_set();
    let (validator_data, validators, weights, total_weight) = setup_test_validators_and_weights();
    let set_info = new_test_set_info(&validator_data);
    let default_signer = SeraiAddress(Signed::default().signer().to_bytes());

    // The signer is fatally slashed if the participant voted to be removed is nonexistent
    {
      let mut db = MemDb::new();
      let mut txn = db.txn();
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

      let nonexistent = random_serai_address(&mut OsRng);

      scan_block.handle_application_tx(
        random_block_number(&mut OsRng),
        Transaction::RemoveParticipant { participant: nonexistent, signed: Signed::default() },
      );

      assert!(TributaryDb::is_fatally_slashed(&mut txn, set, default_signer));
    }

    // Valid RemoveParticipant accumulates weight and eventually crosses threshold
    {
      // All validators have real keys so they can sign
      let (key0, addr0) = random_serai_address_and_key(&mut OsRng);
      let (key1, addr1) = random_serai_address_and_key(&mut OsRng);
      let (key2, addr2) = random_serai_address_and_key(&mut OsRng);

      let validator_data = vec![(addr0, 1u16), (addr1, 1), (addr2, 1)];
      let validators: Vec<SeraiAddress> = validator_data.iter().map(|(a, _)| *a).collect();
      let weights: HashMap<SeraiAddress, u16> = validator_data.iter().copied().collect();
      let set_info = new_test_set_info(&validator_data);

      let target = addr0;
      let block_number = random_block_number(&mut OsRng);

      let mut db = MemDb::new();
      let mut txn = db.txn();

      // First vote: topic is recognized, target not yet slashed
      {
        let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, 3, &weights);
        scan_block.handle_application_tx(
          block_number,
          Transaction::RemoveParticipant { participant: target, signed: new_signed(key0) },
        );
      }
      assert!(
        TributaryDb::recognized(&mut txn, set, Topic::RemoveParticipant { participant: target }),
        "RemoveParticipant topic should be recognized after handling the tx"
      );
      assert!(
        !TributaryDb::is_fatally_slashed(&mut txn, set, target),
        "target should not be fatally slashed after one vote"
      );

      // Threshold crossed, target gets fatally slashed
      {
        let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, 3, &weights);
        scan_block.handle_application_tx(
          block_number,
          Transaction::RemoveParticipant { participant: target, signed: new_signed(key1) },
        );
        scan_block.handle_application_tx(
          block_number,
          Transaction::RemoveParticipant { participant: target, signed: new_signed(key2) },
        );
      }
      assert!(
        TributaryDb::is_fatally_slashed(&mut txn, set, target),
        "target should be fatally slashed after threshold is crossed"
      );
    }
  }

  #[test]
  fn dkg_participation() {
    let mut db = MemDb::new();

    let set = default_test_validator_set();
    let (keys_addrs, validator_data, validators, weights, total_weight) =
      setup_test_validators_and_weights_with_keys();
    let set_info = new_test_set_info(&validator_data);
    let (signer_key, _) = keys_addrs[0];

    let mut txn = db.txn();

    {
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
      scan_block.handle_application_tx(
        random_block_number(&mut OsRng),
        Transaction::DkgParticipation {
          participation: vec![1, 2, 3],
          signed: new_signed(signer_key),
        },
      );
    }

    assert!(ProcessorMessages::try_recv(&mut txn, set).is_some());
  }

  #[test]
  fn dkg_confirmation_preprocess() {
    let set = default_test_validator_set();
    let (keys_addrs, validator_data, validators, weights, total_weight) =
      setup_test_validators_and_weights_with_keys();
    let set_info = new_test_set_info(&validator_data);
    let (key0, key1, key2) = (keys_addrs[0].0, keys_addrs[1].0, keys_addrs[2].0);

    // Below threshold: no DkgConfirmationMessages sent
    {
      let mut db = MemDb::new();
      let mut txn = db.txn();
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

      scan_block.handle_application_tx(
        random_block_number(&mut OsRng),
        Transaction::DkgConfirmationPreprocess {
          attempt: OsRng.next_u32(),
          preprocess: [1u8; 64],
          signed: new_signed(key0),
        },
      );

      assert!(DkgConfirmationMessages::try_recv(&mut txn, set).is_none());
    }

    // Threshold crossed: sends DkgConfirmationMessages (Preprocesses)
    {
      let mut db = MemDb::new();
      let mut txn = db.txn();
      {
        let mut scan_block =
          new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
        for (key, preprocess) in [(key0, [1u8; 64]), (key1, [2u8; 64]), (key2, [3u8; 64])] {
          scan_block.handle_application_tx(
            1,
            Transaction::DkgConfirmationPreprocess {
              attempt: 0,
              preprocess,
              signed: new_signed(key),
            },
          );
        }
      }

      assert!(DkgConfirmationMessages::try_recv(&mut txn, set).is_some());
    }
  }

  #[test]
  fn dkg_confirmation_share() {
    let set = default_test_validator_set();
    let (keys_addrs, validator_data, validators, weights, total_weight) =
      setup_test_validators_and_weights_with_keys();
    let set_info = new_test_set_info(&validator_data);
    let (key0, addr0) = keys_addrs[0];

    // Share without preceding preprocess participation -> fatal slash
    // (the accumulate preceding_topic check slashes the signer)
    {
      let mut db = MemDb::new();
      let mut txn = db.txn();
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

      scan_block.handle_application_tx(
        1,
        Transaction::DkgConfirmationShare {
          attempt: 0,
          share: [10u8; 32],
          signed: new_signed(key0),
        },
      );

      assert!(TributaryDb::is_fatally_slashed(&mut txn, set, addr0));
    }
  }

  /// Verify that the full preprocess->share flow works for DkgConfirmation.
  ///
  /// Previously, this panicked because `accumulate<[u8; 32]>` (share) used typed deserialization
  /// on the preceding preprocess topic stored as `[u8; 64]`. Fixed by using a raw key-existence
  /// check for the preceding topic instead.
  #[test]
  fn dkg_confirmation_preprocess_then_share_flow() {
    let set = default_test_validator_set();
    let (keys_addrs, validator_data, validators, weights, total_weight) =
      setup_test_validators_and_weights_with_keys();
    let set_info = new_test_set_info(&validator_data);
    let (key0, key1, key2) = (keys_addrs[0].0, keys_addrs[1].0, keys_addrs[2].0);

    let mut db = MemDb::new();
    let mut txn = db.txn();

    // All 3 validators submit preprocesses (threshold crossed -> DkgConfirmationMessages sent)
    {
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
      for (key, preprocess) in [(key0, [1u8; 64]), (key1, [2u8; 64]), (key2, [3u8; 64])] {
        scan_block.handle_application_tx(
          1,
          Transaction::DkgConfirmationPreprocess {
            attempt: 0,
            preprocess,
            signed: new_signed(key),
          },
        );
      }
    }
    assert!(DkgConfirmationMessages::try_recv(&mut txn, set).is_some());

    // All 3 validators submit shares (threshold crossed -> DkgConfirmationMessages sent)
    {
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
      for (key, share) in [(key0, [10u8; 32]), (key1, [20u8; 32]), (key2, [30u8; 32])] {
        scan_block.handle_application_tx(
          1,
          Transaction::DkgConfirmationShare { attempt: 0, share, signed: new_signed(key) },
        );
      }
    }
    assert!(DkgConfirmationMessages::try_recv(&mut txn, set).is_some());
  }

  #[test]
  fn cosign() {
    let set = default_test_validator_set();
    let (validator_data, validators, weights, total_weight) = setup_test_validators_and_weights();
    let set_info = new_test_set_info(&validator_data);

    let block_hash = random_block_hash(&mut OsRng);
    let global_session = random_bytes_32(&mut OsRng);

    let intent = CosignIntent {
      global_session,
      block_number: random_block_number(&mut OsRng),
      block_hash,
      notable: false,
    };

    // Sets LatestSubstrateBlockToCosign and starts cosigning
    {
      let mut db = MemDb::new();
      {
        let mut txn = db.txn();
        CosignIntents::provide(&mut txn, set, &intent);
        txn.commit();
      }

      let mut txn = db.txn();
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

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
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

      scan_block
        .handle_application_tx(1, Transaction::Cosign { substrate_block_hash: second_hash });

      assert_eq!(LatestSubstrateBlockToCosign::get(&mut txn, set), Some(second_hash));
      assert_eq!(ActivelyCosigning::get(&mut txn, set), Some(first_hash));
    }
  }

  #[test]
  fn cosigned() {
    let set = default_test_validator_set();
    let (validator_data, validators, weights, total_weight) = setup_test_validators_and_weights();
    let set_info = new_test_set_info(&validator_data);

    // Marks block as cosigned
    {
      let mut db = MemDb::new();
      let block_hash = random_block_hash(&mut OsRng);
      let mut txn = db.txn();

      assert!(!TributaryDb::cosigned(&mut txn, set, block_hash));

      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

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

      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

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
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

      scan_block
        .handle_application_tx(1, Transaction::Cosigned { substrate_block_hash: other_hash });

      assert_eq!(ActivelyCosigning::get(&mut txn, set), Some(active_hash));
      assert!(TributaryDb::cosigned(&mut txn, set, other_hash));
    }
  }

  #[test]
  fn substrate_block() {
    let set = default_test_validator_set();
    let (validator_data, validators, weights, total_weight) = setup_test_validators_and_weights();
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
    let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

    scan_block.handle_application_tx(1, Transaction::SubstrateBlock { hash: block_hash });

    for plan in &plans {
      let topic = expected_topic_after_start_cosigning(VariantSignId::Transaction(*plan));
      assert!(AccumulatedWeight::get(&mut txn, set, topic).is_some());
    }
  }

  #[test]
  fn batch() {
    let set = default_test_validator_set();
    let (validator_data, validators, weights, total_weight) = setup_test_validators_and_weights();
    let set_info = new_test_set_info(&validator_data);

    let mut db = MemDb::new();
    let batch_hash = [42u8; 32];

    let mut txn = db.txn();
    let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

    scan_block.handle_application_tx(1, Transaction::Batch { hash: batch_hash });

    let topic = expected_topic_after_start_cosigning(VariantSignId::Batch(batch_hash));
    assert!(AccumulatedWeight::get(&mut txn, set, topic).is_some());
  }

  #[test]
  fn sign() {
    let set = default_test_validator_set();
    let (keys_addrs, validator_data, validators, weights, total_weight) =
      setup_test_validators_and_weights_with_keys();
    let set_info = new_test_set_info(&validator_data);
    let (key0, addr0) = keys_addrs[0];
    let (key1, key2) = (keys_addrs[1].0, keys_addrs[2].0);

    let sign_id = VariantSignId::Transaction([42; 32]);
    let topic = expected_topic_after_start_cosigning(sign_id);

    // Wrong data length: signer has weight 1 but submits 2 entries -> fatal slash
    {
      let mut db = MemDb::new();
      let mut txn = db.txn();
      TributaryDb::recognize_topic(&mut txn, set, topic);

      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
      scan_block.handle_application_tx(
        1,
        Transaction::Sign {
          id: sign_id,
          attempt: 0,
          round: SigningProtocolRound::Preprocess,
          data: vec![vec![1], vec![2]],
          signed: new_signed(key0),
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
        let mut scan_block =
          new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
        for key in [key0, key1, key2] {
          scan_block.handle_application_tx(
            1,
            Transaction::Sign {
              id: sign_id,
              attempt: 0,
              round: SigningProtocolRound::Preprocess,
              data: vec![vec![1, 2, 3]],
              signed: new_signed(key),
            },
          );
        }
      }

      assert!(ProcessorMessages::try_recv(&mut txn, set).is_some());
    }
  }

  /// Exercises the Sign Share -> Participating path (line 559: `Shares { id, shares: data_set }`).
  /// Requires first accumulating preprocesses to threshold (which recognizes the Share topic
  /// and stores preceding data), then accumulating shares to threshold.
  #[test]
  fn sign_share_sends_shares_message() {
    let set = default_test_validator_set();
    let (keys_addrs, validator_data, validators, weights, total_weight) =
      setup_test_validators_and_weights_with_keys();
    let set_info = new_test_set_info(&validator_data);
    let (key0, key1, key2) = (keys_addrs[0].0, keys_addrs[1].0, keys_addrs[2].0);

    let sign_id = VariantSignId::Transaction([42; 32]);
    let preprocess_topic = expected_topic_after_start_cosigning(sign_id);
    let share_topic = Topic::Sign { id: sign_id, attempt: 0, round: SigningProtocolRound::Share };

    let mut db = MemDb::new();
    let mut txn = db.txn();

    // Recognize the Preprocess topic
    TributaryDb::recognize_topic(&mut txn, set, preprocess_topic);

    // Step 1: All validators submit preprocesses, crossing threshold.
    // This auto-recognizes the Share topic (succeeding_topic) and stores preprocess data.
    {
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
      for key in [key0, key1, key2] {
        scan_block.handle_application_tx(
          1,
          Transaction::Sign {
            id: sign_id,
            attempt: 0,
            round: SigningProtocolRound::Preprocess,
            data: vec![vec![1, 2, 3]],
            signed: new_signed(key),
          },
        );
      }
    }

    // Drain the Preprocesses message from step 1
    assert!(ProcessorMessages::try_recv(&mut txn, set).is_some());

    // Share topic should now be recognized
    assert!(AccumulatedWeight::get(&mut txn, set, share_topic).is_some());

    // Step 2: All validators submit shares, crossing threshold -> sends Shares message.
    {
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
      for key in [key0, key1, key2] {
        scan_block.handle_application_tx(
          2,
          Transaction::Sign {
            id: sign_id,
            attempt: 0,
            round: SigningProtocolRound::Share,
            data: vec![vec![4, 5, 6]],
            signed: new_signed(key),
          },
        );
      }
    }

    // The Shares message should have been sent
    let msg = ProcessorMessages::try_recv(&mut txn, set);
    assert!(msg.is_some(), "expected Shares processor message");

    // No validators should be slashed
    for v in &validators {
      assert!(!TributaryDb::is_fatally_slashed(&mut txn, set, *v));
    }
  }

  #[test]
  fn slash_report() {
    let set = default_test_validator_set();
    let (keys_addrs, validator_data, validators, weights, total_weight) =
      setup_test_validators_and_weights_with_keys();
    let set_info = new_test_set_info(&validator_data);
    let (key0, addr0) = keys_addrs[0];

    // Wrong length: 3 validators but only 2 slash points -> fatal slash
    {
      let mut db = MemDb::new();
      let mut txn = db.txn();
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

      scan_block.handle_application_tx(
        1,
        Transaction::SlashReport { slash_points: vec![0, 0], signed: new_signed(key0) },
      );

      assert!(TributaryDb::is_fatally_slashed(&mut txn, set, addr0));
    }

    // Valid length: accumulates weight
    {
      let mut db = MemDb::new();
      let mut txn = db.txn();
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

      scan_block.handle_application_tx(
        1,
        Transaction::SlashReport { slash_points: vec![0, 0, 0], signed: new_signed(key0) },
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
        let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, 4, &weights);
        for key in [key0, key1, key2] {
          scan_block.handle_application_tx(
            1,
            Transaction::SlashReport { slash_points: vec![0, 0, 0, 100], signed: new_signed(key) },
          );
        }
      }

      assert!(ProcessorMessages::try_recv(&mut txn, set).is_some());
    }
  }

  /// Exercises the even-length median branch (`(this_validator.len() / 2) - 1`) in
  /// the SlashReport handler by using 5 validators where `required_participation = 4` (even).
  #[test]
  fn slash_report_even_reporter_count_median() {
    let set = default_test_validator_set();

    // 5 validators of weight 1 -> required_participation = 5*2/3+1 = 4
    let keys_addrs: Vec<(RistrettoPoint, SeraiAddress)> =
      (0 .. 5).map(|_| random_serai_address_and_key(&mut OsRng)).collect();
    let validator_data: Vec<(SeraiAddress, u16)> =
      keys_addrs.iter().map(|(_, addr)| (*addr, 1u16)).collect();
    let validators: Vec<SeraiAddress> = validator_data.iter().map(|(a, _)| *a).collect();
    let weights: HashMap<SeraiAddress, u16> = validator_data.iter().copied().collect();
    let set_info = new_test_set_info(&validator_data);

    let mut db = MemDb::new();
    let mut txn = db.txn();

    // 4 reporters submit different opinions about validator 4 (index 4).
    // Reports (for all 5 validator positions):
    //   reporter 0: [0, 0, 0, 0, 10]
    //   reporter 1: [0, 0, 0, 0, 20]
    //   reporter 2: [0, 0, 0, 0, 30]
    //   reporter 3: [0, 0, 0, 0, 40]
    //
    // Sorted values for validator 4: [10, 20, 30, 40] (len=4, even)
    // Even median index: (4 / 2) - 1 = 1 -> median = 20
    //
    // f = (5-1)/3 = 1, amortization baseline = sorted_medians[5-1-1] = sorted_medians[3] = 0
    // amortized: [0, 0, 0, 0, 20]. Non-zero entries: [20] for validator 4.
    let slash_reports = vec![
      vec![0u32, 0, 0, 0, 10],
      vec![0, 0, 0, 0, 20],
      vec![0, 0, 0, 0, 30],
      vec![0, 0, 0, 0, 40],
    ];

    {
      let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, 5, &weights);
      for (i, report) in slash_reports.iter().enumerate() {
        let (key, _) = keys_addrs[i];
        scan_block.handle_application_tx(
          1,
          Transaction::SlashReport { slash_points: report.clone(), signed: new_signed(key) },
        );
      }
    }

    // Threshold was crossed with 4 reporters (even) -> even median branch exercised.
    // Verify the signing topic was recognized and a message was sent.
    let sign_topic = expected_topic_after_start_cosigning(VariantSignId::SlashReport);
    assert!(
      AccumulatedWeight::get(&mut txn, set, sign_topic).is_some(),
      "SlashReport sign topic should be recognized"
    );

    let msg = ProcessorMessages::try_recv(&mut txn, set);
    assert!(msg.is_some(), "expected SignSlashReport processor message");
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

      /// Fuzz the SlashReport -> Participating path with randomized slash point vectors.
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
          let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, 4, &weights);
          for (key, _) in [(key0, &addr0), (key1, &addr1), (key2, &addr2), (key3, &addr3)] {
            scan_block.handle_application_tx(
              1,
              Transaction::SlashReport {
                slash_points: slash_points.clone(),
                signed: new_signed(key),
              },
            );
          }
        }

        match expected {
          Some(result) if !result.is_empty() => {
            // Non-empty slash report -> message should be sent
            prop_assert!(
              ProcessorMessages::try_recv(&mut txn, set).is_some(),
              "expected ProcessorMessage for non-empty slash report {:?}",
              result
            );
          }
          _ => {
            // Empty or f==0 -> no message sent (slash report is empty, nothing to sign)
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
        let sign_topic = expected_topic_after_start_cosigning(VariantSignId::SlashReport);
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
          let mut scan_block = new_scan_block(&mut txn, &set_info, &validators, 7, &weights);
          for (i, report) in reports.iter().enumerate() {
            let (key, _) = keys_addrs[i];
            scan_block.handle_application_tx(
              1,
              Transaction::SlashReport {
                slash_points: report.clone(),
                signed: new_signed(key),
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

        // Participating path was reached -> message and topic recognition
        prop_assert!(ProcessorMessages::try_recv(&mut txn, set).is_some());
        let sign_topic = expected_topic_after_start_cosigning(VariantSignId::SlashReport);
        prop_assert!(AccumulatedWeight::get(&mut txn, set, sign_topic).is_some());
      }

      /// Fuzz the wrong-length path: slash_points.len() != validators.len() -> fatal slash
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
            new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);
          scan_block.handle_application_tx(
            1,
            Transaction::SlashReport {
              slash_points: vec![0; wrong_len],
              signed: new_signed(signer_key),
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
    let batch_hash = random_bytes_32(&mut OsRng);
    let (validator_data, validators, weights, total_weight) = setup_test_validators_and_weights();
    let set_info = new_test_set_info(&validator_data);

    let block = Block {
      header: BlockHeader {
        parent: random_bytes_32(&mut OsRng),
        transactions: random_bytes_32(&mut OsRng),
      },
      transactions: vec![TributaryTransaction::Application(Transaction::Batch {
        hash: batch_hash,
      })],
    };

    {
      let mut txn = db.txn();
      let scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

      scan_block.handle_block(1, block);
      txn.commit();
    }

    let expected_topic = expected_topic_after_start_cosigning(VariantSignId::Batch(batch_hash));
    assert!(TributaryDb::recognized(&db, set, expected_topic));
  }

  #[test]
  fn empty_block_only_calls_start_of_block() {
    let mut db = MemDb::new();
    let set = default_test_validator_set();
    let (validator_data, validators, weights, total_weight) = setup_test_validators_and_weights();
    let set_info = new_test_set_info(&validator_data);

    let block = Block {
      header: BlockHeader {
        parent: random_bytes_32(&mut OsRng),
        transactions: random_bytes_32(&mut OsRng),
      },
      transactions: vec![],
    };

    let mut txn = db.txn();
    let scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

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
    let (validator_data, validators, weights, total_weight) = setup_test_validators_and_weights();
    let set_info = new_test_set_info(&validator_data);

    let block = Block {
      header: BlockHeader {
        parent: random_bytes_32(&mut OsRng),
        transactions: random_bytes_32(&mut OsRng),
      },
      transactions: vec![
        TributaryTransaction::Application(Transaction::Batch { hash: batch_hash_a }),
        TributaryTransaction::Application(Transaction::Batch { hash: batch_hash_b }),
      ],
    };

    let mut txn = db.txn();
    let scan_block = new_scan_block(&mut txn, &set_info, &validators, total_weight, &weights);

    scan_block.handle_block(1, block);
    txn.commit();

    for hash in [batch_hash_a, batch_hash_b] {
      let topic = expected_topic_after_start_cosigning(VariantSignId::Batch(hash));
      assert!(TributaryDb::recognized(&db, set, topic));
    }
  }

  /// Construct a borsh-encoded `SignedMessage` for `TendermintNetwork<MemDb, Transaction, MockP2p>`.
  ///
  /// The network's types are: ValidatorId = [u8; 32], Block = TendermintBlock, Signature = [u8; 64].
  /// We manually build the borsh encoding rather than depending on the internal tendermint types.
  fn make_signed_message_bytes(sender: [u8; 32]) -> Vec<u8> {
    let mut bytes = Vec::new();
    // Message fields:
    bytes.extend_from_slice(&sender); // sender: [u8; 32]
    bytes.extend_from_slice(&0u64.to_le_bytes()); // block: BlockNumber(0)
    bytes.extend_from_slice(&0u32.to_le_bytes()); // round: RoundNumber(0)
    bytes.push(1); // Data::Prevote variant index
    bytes.push(0); // Option::None (no block id)
                   // Signature:
    bytes.extend_from_slice(&[0u8; 64]); // sig: [u8; 64]
    bytes
  }

  #[test]
  fn slash_evidence_invalid_precommit() {
    let mut db = MemDb::new();
    let set = default_test_validator_set();
    let (_, addr0) = random_serai_address_and_key(&mut OsRng);
    let validator_data = vec![(addr0, 1u16)];
    let validators: Vec<SeraiAddress> = validator_data.iter().map(|(a, _)| *a).collect();
    let weights: HashMap<SeraiAddress, u16> = validator_data.iter().copied().collect();
    let set_info = new_test_set_info(&validator_data);

    let evidence_bytes = make_signed_message_bytes(addr0.0);
    let block = Block {
      header: BlockHeader {
        parent: random_bytes_32(&mut OsRng),
        transactions: random_bytes_32(&mut OsRng),
      },
      transactions: vec![TributaryTransaction::Tendermint(TendermintTx::SlashEvidence(
        Evidence::InvalidPrecommit(evidence_bytes),
      ))],
    };

    let mut txn = db.txn();
    let scan_block = new_scan_block(&mut txn, &set_info, &validators, 1, &weights);
    scan_block.handle_block(1, block);
    txn.commit();

    assert!(TributaryDb::is_fatally_slashed(&db, set, addr0));
  }

  #[test]
  fn slash_evidence_invalid_valid_round() {
    let mut db = MemDb::new();
    let set = default_test_validator_set();
    let (_, addr0) = random_serai_address_and_key(&mut OsRng);
    let validator_data = vec![(addr0, 1u16)];
    let validators: Vec<SeraiAddress> = validator_data.iter().map(|(a, _)| *a).collect();
    let weights: HashMap<SeraiAddress, u16> = validator_data.iter().copied().collect();
    let set_info = new_test_set_info(&validator_data);

    let evidence_bytes = make_signed_message_bytes(addr0.0);
    let block = Block {
      header: BlockHeader {
        parent: random_bytes_32(&mut OsRng),
        transactions: random_bytes_32(&mut OsRng),
      },
      transactions: vec![TributaryTransaction::Tendermint(TendermintTx::SlashEvidence(
        Evidence::InvalidValidRound(evidence_bytes),
      ))],
    };

    let mut txn = db.txn();
    let scan_block = new_scan_block(&mut txn, &set_info, &validators, 1, &weights);
    scan_block.handle_block(1, block);
    txn.commit();

    assert!(TributaryDb::is_fatally_slashed(&db, set, addr0));
  }

  #[test]
  fn slash_evidence_conflicting_messages() {
    let mut db = MemDb::new();
    let set = default_test_validator_set();
    let (_, addr0) = random_serai_address_and_key(&mut OsRng);
    let validator_data = vec![(addr0, 1u16)];
    let validators: Vec<SeraiAddress> = validator_data.iter().map(|(a, _)| *a).collect();
    let weights: HashMap<SeraiAddress, u16> = validator_data.iter().copied().collect();
    let set_info = new_test_set_info(&validator_data);

    // Both messages have the same sender; the slash uses the first message's sender
    let first = make_signed_message_bytes(addr0.0);
    let second = make_signed_message_bytes(addr0.0);
    let block = Block {
      header: BlockHeader {
        parent: random_bytes_32(&mut OsRng),
        transactions: random_bytes_32(&mut OsRng),
      },
      transactions: vec![TributaryTransaction::Tendermint(TendermintTx::SlashEvidence(
        Evidence::ConflictingMessages(first, second),
      ))],
    };

    let mut txn = db.txn();
    let scan_block = new_scan_block(&mut txn, &set_info, &validators, 1, &weights);
    scan_block.handle_block(1, block);
    txn.commit();

    assert!(TributaryDb::is_fatally_slashed(&db, set, addr0));
  }

  /// Verifies handle_block processes both Tendermint and Application transactions in one block.
  #[test]
  fn mixed_tendermint_and_application_txs() {
    let mut db = MemDb::new();
    let set = default_test_validator_set();
    let (_, addr0) = random_serai_address_and_key(&mut OsRng);
    let (_, addr1) = random_serai_address_and_key(&mut OsRng);
    let validator_data = vec![(addr0, 1u16), (addr1, 1)];
    let validators: Vec<SeraiAddress> = validator_data.iter().map(|(a, _)| *a).collect();
    let weights: HashMap<SeraiAddress, u16> = validator_data.iter().copied().collect();
    let set_info = new_test_set_info(&validator_data);

    let batch_hash = [99; 32];
    let evidence_bytes = make_signed_message_bytes(addr0.0);

    let block = Block {
      header: BlockHeader {
        parent: random_bytes_32(&mut OsRng),
        transactions: random_bytes_32(&mut OsRng),
      },
      transactions: vec![
        // Tendermint SlashEvidence first
        TributaryTransaction::Tendermint(TendermintTx::SlashEvidence(Evidence::InvalidPrecommit(
          evidence_bytes,
        ))),
        // Then an Application transaction
        TributaryTransaction::Application(Transaction::Batch { hash: batch_hash }),
      ],
    };

    let mut txn = db.txn();
    let scan_block = new_scan_block(&mut txn, &set_info, &validators, 2, &weights);
    scan_block.handle_block(1, block);
    txn.commit();

    // Tendermint evidence slashed addr0
    assert!(TributaryDb::is_fatally_slashed(&db, set, addr0));
    // Application tx was still processed
    let topic = expected_topic_after_start_cosigning(VariantSignId::Batch(batch_hash));
    assert!(TributaryDb::recognized(&db, set, topic));
  }
}
