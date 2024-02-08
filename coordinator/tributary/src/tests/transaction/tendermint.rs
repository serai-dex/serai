use std::sync::Arc;

use zeroize::Zeroizing;
use rand::{RngCore, rngs::OsRng};

use ciphersuite::{Ristretto, Ciphersuite, group::ff::Field};

use scale::Encode;

use tendermint::{
  time::CanonicalInstant,
  round::RoundData,
  Data, commit_msg, Evidence,
  ext::{RoundNumber, Commit, Signer as SignerTrait},
};

use serai_db::MemDb;

use crate::{
  ReadWrite,
  tendermint::{
    tx::{TendermintTx, verify_tendermint_tx},
    TendermintBlock, Signer, Validators, TendermintNetwork,
  },
  tests::{
    p2p::DummyP2p, SignedTransaction, random_evidence_tx, tendermint_meta, signed_from_data,
  },
};

type N = TendermintNetwork<MemDb, SignedTransaction, DummyP2p>;

#[tokio::test]
async fn serialize_tendermint() {
  // make a tendermint tx with random evidence
  let (_, signer, _, _) = tendermint_meta().await;
  let tx = random_evidence_tx::<N>(signer.into(), TendermintBlock(vec![])).await;
  let res = TendermintTx::read::<&[u8]>(&mut tx.serialize().as_ref()).unwrap();
  assert_eq!(res, tx);
}

#[tokio::test]
async fn invalid_valid_round() {
  // signer
  let (_, signer, signer_id, validators) = tendermint_meta().await;
  let commit = |_: u64| -> Option<Commit<Arc<Validators>>> {
    Some(Commit::<Arc<Validators>> { end_time: 0, validators: vec![], signature: vec![] })
  };

  let valid_round_tx = |valid_round| {
    let signer = signer.clone();
    async move {
      let data = Data::Proposal(valid_round, TendermintBlock(vec![]));
      let signed = signed_from_data::<N>(signer.clone().into(), signer_id, 0, 0, data).await;
      (signed.clone(), TendermintTx::SlashEvidence(Evidence::InvalidValidRound(signed.encode())))
    }
  };

  // This should be invalid evidence if a valid valid round is specified
  let (_, tx) = valid_round_tx(None).await;
  assert!(verify_tendermint_tx::<N>(&tx, &validators, commit).is_err());

  // If an invalid valid round is specified (>= current), this should be invalid evidence
  let (mut signed, tx) = valid_round_tx(Some(RoundNumber(0))).await;

  // should pass
  verify_tendermint_tx::<N>(&tx, &validators, commit).unwrap();

  // change the signature
  let mut random_sig = [0u8; 64];
  OsRng.fill_bytes(&mut random_sig);
  signed.sig = random_sig;
  let tx = TendermintTx::SlashEvidence(Evidence::InvalidValidRound(signed.encode()));

  // should fail
  assert!(verify_tendermint_tx::<N>(&tx, &validators, commit).is_err());
}

#[tokio::test]
async fn invalid_precommit_signature() {
  let (_, signer, signer_id, validators) = tendermint_meta().await;
  let commit = |i: u64| -> Option<Commit<Arc<Validators>>> {
    assert_eq!(i, 0);
    Some(Commit::<Arc<Validators>> { end_time: 0, validators: vec![], signature: vec![] })
  };

  let precommit = |precommit| {
    let signer = signer.clone();
    async move {
      let signed =
        signed_from_data::<N>(signer.clone().into(), signer_id, 1, 0, Data::Precommit(precommit))
          .await;
      (signed.clone(), TendermintTx::SlashEvidence(Evidence::InvalidPrecommit(signed.encode())))
    }
  };

  // Empty Precommit should fail.
  assert!(verify_tendermint_tx::<N>(&precommit(None).await.1, &validators, commit).is_err());

  // valid precommit signature should fail.
  let block_id = [0x22u8; 32];
  let last_end_time =
    RoundData::<N>::new(RoundNumber(0), CanonicalInstant::new(commit(0).unwrap().end_time))
      .end_time();
  let commit_msg = commit_msg(last_end_time.canonical(), block_id.as_ref());

  assert!(verify_tendermint_tx::<N>(
    &precommit(Some((block_id, signer.clone().sign(&commit_msg).await))).await.1,
    &validators,
    commit
  )
  .is_err());

  // any other signature can be used as evidence.
  {
    let (mut signed, tx) = precommit(Some((block_id, signer.sign(&[]).await))).await;
    verify_tendermint_tx::<N>(&tx, &validators, commit).unwrap();

    // So long as we can authenticate where it came from
    let mut random_sig = [0u8; 64];
    OsRng.fill_bytes(&mut random_sig);
    signed.sig = random_sig;
    let tx = TendermintTx::SlashEvidence(Evidence::InvalidPrecommit(signed.encode()));
    assert!(verify_tendermint_tx::<N>(&tx, &validators, commit).is_err());
  }
}

#[tokio::test]
async fn evidence_with_prevote() {
  let (_, signer, signer_id, validators) = tendermint_meta().await;
  let commit = |_: u64| -> Option<Commit<Arc<Validators>>> {
    Some(Commit::<Arc<Validators>> { end_time: 0, validators: vec![], signature: vec![] })
  };

  let prevote = |block_id| {
    let signer = signer.clone();
    async move {
      // it should fail for all reasons.
      let mut txs = vec![];
      txs.push(TendermintTx::SlashEvidence(Evidence::InvalidPrecommit(
        signed_from_data::<N>(signer.clone().into(), signer_id, 0, 0, Data::Prevote(block_id))
          .await
          .encode(),
      )));
      txs.push(TendermintTx::SlashEvidence(Evidence::InvalidValidRound(
        signed_from_data::<N>(signer.clone().into(), signer_id, 0, 0, Data::Prevote(block_id))
          .await
          .encode(),
      )));
      // Since these require a second message, provide this one again
      // ConflictingMessages can be fired for actually conflicting Prevotes however
      txs.push(TendermintTx::SlashEvidence(Evidence::ConflictingMessages(
        signed_from_data::<N>(signer.clone().into(), signer_id, 0, 0, Data::Prevote(block_id))
          .await
          .encode(),
        signed_from_data::<N>(signer.clone().into(), signer_id, 0, 0, Data::Prevote(block_id))
          .await
          .encode(),
      )));
      txs
    }
  };

  // No prevote message alone should be valid as slash evidence at this time
  for prevote in prevote(None).await {
    assert!(verify_tendermint_tx::<N>(&prevote, &validators, commit).is_err());
  }
  for prevote in prevote(Some([0x22u8; 32])).await {
    assert!(verify_tendermint_tx::<N>(&prevote, &validators, commit).is_err());
  }
}

#[tokio::test]
async fn conflicting_msgs_evidence_tx() {
  let (genesis, signer, signer_id, validators) = tendermint_meta().await;
  let commit = |i: u64| -> Option<Commit<Arc<Validators>>> {
    assert_eq!(i, 0);
    Some(Commit::<Arc<Validators>> { end_time: 0, validators: vec![], signature: vec![] })
  };

  // Block b, round n
  let signed_for_b_r = |block, round, data| {
    let signer = signer.clone();
    async move { signed_from_data::<N>(signer.clone().into(), signer_id, block, round, data).await }
  };

  // Proposal
  {
    // non-conflicting data should fail
    let signed_1 = signed_for_b_r(0, 0, Data::Proposal(None, TendermintBlock(vec![0x11]))).await;
    let tx = TendermintTx::SlashEvidence(Evidence::ConflictingMessages(
      signed_1.encode(),
      signed_1.encode(),
    ));
    assert!(verify_tendermint_tx::<N>(&tx, &validators, commit).is_err());

    // conflicting data should pass
    let signed_2 = signed_for_b_r(0, 0, Data::Proposal(None, TendermintBlock(vec![0x22]))).await;
    let tx = TendermintTx::SlashEvidence(Evidence::ConflictingMessages(
      signed_1.encode(),
      signed_2.encode(),
    ));
    verify_tendermint_tx::<N>(&tx, &validators, commit).unwrap();

    // Except if it has a distinct round number, as we don't check cross-round conflicts
    // (except for Precommit)
    let signed_2 = signed_for_b_r(0, 1, Data::Proposal(None, TendermintBlock(vec![0x22]))).await;
    let tx = TendermintTx::SlashEvidence(Evidence::ConflictingMessages(
      signed_1.encode(),
      signed_2.encode(),
    ));
    verify_tendermint_tx::<N>(&tx, &validators, commit).unwrap_err();

    // Proposals for different block numbers should also fail as evidence
    let signed_2 = signed_for_b_r(1, 0, Data::Proposal(None, TendermintBlock(vec![0x22]))).await;
    let tx = TendermintTx::SlashEvidence(Evidence::ConflictingMessages(
      signed_1.encode(),
      signed_2.encode(),
    ));
    verify_tendermint_tx::<N>(&tx, &validators, commit).unwrap_err();
  }

  // Prevote
  {
    // non-conflicting data should fail
    let signed_1 = signed_for_b_r(0, 0, Data::Prevote(Some([0x11; 32]))).await;
    let tx = TendermintTx::SlashEvidence(Evidence::ConflictingMessages(
      signed_1.encode(),
      signed_1.encode(),
    ));
    assert!(verify_tendermint_tx::<N>(&tx, &validators, commit).is_err());

    // conflicting data should pass
    let signed_2 = signed_for_b_r(0, 0, Data::Prevote(Some([0x22; 32]))).await;
    let tx = TendermintTx::SlashEvidence(Evidence::ConflictingMessages(
      signed_1.encode(),
      signed_2.encode(),
    ));
    verify_tendermint_tx::<N>(&tx, &validators, commit).unwrap();

    // Except if it has a distinct round number, as we don't check cross-round conflicts
    // (except for Precommit)
    let signed_2 = signed_for_b_r(0, 1, Data::Prevote(Some([0x22; 32]))).await;
    let tx = TendermintTx::SlashEvidence(Evidence::ConflictingMessages(
      signed_1.encode(),
      signed_2.encode(),
    ));
    verify_tendermint_tx::<N>(&tx, &validators, commit).unwrap_err();

    // Proposals for different block numbers should also fail as evidence
    let signed_2 = signed_for_b_r(1, 0, Data::Prevote(Some([0x22; 32]))).await;
    let tx = TendermintTx::SlashEvidence(Evidence::ConflictingMessages(
      signed_1.encode(),
      signed_2.encode(),
    ));
    verify_tendermint_tx::<N>(&tx, &validators, commit).unwrap_err();
  }

  // msgs from different senders should fail
  {
    let signed_1 = signed_for_b_r(0, 0, Data::Proposal(None, TendermintBlock(vec![0x11]))).await;

    let signer_2 =
      Signer::new(genesis, Zeroizing::new(<Ristretto as Ciphersuite>::F::random(&mut OsRng)));
    let signed_id_2 = signer_2.validator_id().await.unwrap();
    let signed_2 = signed_from_data::<N>(
      signer_2.into(),
      signed_id_2,
      0,
      0,
      Data::Proposal(None, TendermintBlock(vec![0x22])),
    )
    .await;

    let tx = TendermintTx::SlashEvidence(Evidence::ConflictingMessages(
      signed_1.encode(),
      signed_2.encode(),
    ));

    // update schema so that we don't fail due to invalid signature
    let signer_pub =
      <Ristretto as Ciphersuite>::read_G::<&[u8]>(&mut signer_id.as_slice()).unwrap();
    let signer_pub_2 =
      <Ristretto as Ciphersuite>::read_G::<&[u8]>(&mut signed_id_2.as_slice()).unwrap();
    let validators =
      Arc::new(Validators::new(genesis, vec![(signer_pub, 1), (signer_pub_2, 1)]).unwrap());

    assert!(verify_tendermint_tx::<N>(&tx, &validators, commit).is_err());
  }

  // msgs with different steps should fail
  {
    let signed_1 = signed_for_b_r(0, 0, Data::Proposal(None, TendermintBlock(vec![]))).await;
    let signed_2 = signed_for_b_r(0, 0, Data::Prevote(None)).await;
    let tx = TendermintTx::SlashEvidence(Evidence::ConflictingMessages(
      signed_1.encode(),
      signed_2.encode(),
    ));
    assert!(verify_tendermint_tx::<N>(&tx, &validators, commit).is_err());
  }
}
