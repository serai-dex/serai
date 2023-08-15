use std::sync::Arc;

use crate::{
  tendermint::{
    tx::{TendermintTx, verify_tendermint_tx},
    Validators, TendermintNetwork, TendermintBlock, Signer,
  },
  ReadWrite,
  tests::{
    random_evidence_tx, random_vote_tx, SignedTransaction, p2p::DummyP2p, new_genesis, signer,
    tx_from_evidence, signed_from_data,
  },
  async_sequential,
};

use ciphersuite::{Ristretto, Ciphersuite, group::ff::Field};
use schnorr::SchnorrSignature;

use blake2::{Blake2s256, Digest};
use rand::{RngCore, rngs::OsRng};

use zeroize::Zeroizing;

use serai_db::MemDb;

use tendermint::{
  Data,
  ext::{RoundNumber, Commit, Signer as SignerTrait},
  commit_msg,
  round::RoundData,
  time::CanonicalInstant,
};

type N = TendermintNetwork<MemDb, SignedTransaction, DummyP2p>;

#[test]
fn vote_tx() {
  let genesis = new_genesis();
  let mut tx = random_vote_tx(&mut OsRng, genesis);

  let commit = |_: u32| -> Option<Commit<Arc<Validators>>> {
    Some(Commit::<Arc<Validators>> { end_time: 0, validators: vec![], signature: vec![] })
  };
  let validators = Arc::new(Validators::new(genesis, vec![]).unwrap());

  // should pass
  assert!(verify_tendermint_tx::<N>(&tx, genesis, validators.clone(), commit).is_ok());

  if let TendermintTx::SlashVote(vote) = &mut tx {
    vote.sig.signature = SchnorrSignature::read(&mut [0; 64].as_slice()).unwrap();
  } else {
    panic!("SlashVote TX wasn't SlashVote");
  }

  // should fail
  assert!(verify_tendermint_tx::<N>(&tx, genesis, validators, commit).is_err());
}

async_sequential!(
  async fn serialize_tendermint() {
    // make a tendermint tx with random evidence
    let (genesis, signer, _, _) = signer().await;
    let tx = random_evidence_tx::<N>(signer.into(), TendermintBlock(vec![])).await;
    let res = TendermintTx::read::<&[u8]>(&mut tx.serialize().as_ref()).unwrap();
    assert_eq!(res, tx);

    // with vote tx
    let vote_tx = random_vote_tx(&mut OsRng, genesis);
    let vote_res = TendermintTx::read::<&[u8]>(&mut vote_tx.serialize().as_ref()).unwrap();
    assert_eq!(vote_res, vote_tx);
  }

  async fn msg_signature() {
    // signer
    let (genesis, signer, signer_id, validators) = signer().await;
    let commit = |_: u32| -> Option<Commit<Arc<Validators>>> {
      Some(Commit::<Arc<Validators>> { end_time: 0, validators: vec![], signature: vec![] })
    };

    // msg
    let data = Data::Proposal(Some(RoundNumber(0)), TendermintBlock(vec![]));
    let mut signed = signed_from_data::<N>(signer.into(), signer_id, 0, 0, data).await;
    let mut tx = tx_from_evidence::<N>(vec![signed.clone()]);

    // should pass
    assert!(verify_tendermint_tx::<N>(&tx, genesis, validators.clone(), commit).is_ok());

    // change the signature
    let mut random_sig = [0u8; 64];
    OsRng.fill_bytes(&mut random_sig);
    signed.sig = random_sig;
    tx = tx_from_evidence::<N>(vec![signed]);

    // should fail
    assert!(verify_tendermint_tx::<N>(&tx, genesis, validators, commit).is_err());
  }

  async fn proposal_evidence_tx() {
    // signer
    let (genesis, signer, signer_id, validators) = signer().await;
    let commit = |_: u32| -> Option<Commit<Arc<Validators>>> {
      Some(Commit::<Arc<Validators>> { end_time: 0, validators: vec![], signature: vec![] })
    };

    // msg as valid evidence
    let mut data = Data::Proposal(Some(RoundNumber(0)), TendermintBlock(vec![]));
    let mut signed = signed_from_data::<N>(signer.clone().into(), signer_id, 0, 0, data).await;
    let mut tx = tx_from_evidence::<N>(vec![signed]);

    // should pass
    assert!(verify_tendermint_tx::<N>(&tx, genesis, validators.clone(), commit).is_ok());

    // invalid evidence(msg round number is bigger than vr)
    data = Data::Proposal(Some(RoundNumber(0)), TendermintBlock(vec![]));
    signed = signed_from_data::<N>(signer.into(), signer_id, 0, 1, data).await;
    tx = tx_from_evidence::<N>(vec![signed]);

    // should fail
    assert!(verify_tendermint_tx::<N>(&tx, genesis, validators, commit).is_err());
  }

  async fn precommit_evidence_tx() {
    let (genesis, signer, signer_id, validators) = signer().await;
    let commit = |_: u32| -> Option<Commit<Arc<Validators>>> {
      Some(Commit::<Arc<Validators>> {
        end_time: 1686040916,
        validators: vec![],
        signature: vec![],
      })
    };
    let block_id = [0u8; 32];

    // calculate the end time of the round 0
    let last_end_time =
      RoundData::<N>::new(RoundNumber(0), CanonicalInstant::new(commit(0).unwrap().end_time))
        .end_time();
    let commit_msg = commit_msg(last_end_time.canonical(), block_id.as_ref());

    // valid precommit msg should fail.
    {
      let sig = signer.sign(&commit_msg).await;
      let signed = signed_from_data::<N>(
        signer.clone().into(),
        signer_id,
        1,
        0,
        Data::Precommit(Some((block_id, sig))),
      )
      .await;
      let tx = tx_from_evidence::<N>(vec![signed]);

      assert!(verify_tendermint_tx::<N>(&tx, genesis, validators.clone(), commit).is_err());
    }

    // any other commit(invalid) can be used as evidence.
    {
      let sig = signer.sign(&Blake2s256::digest(commit_msg)).await;
      let signed = signed_from_data::<N>(
        signer.clone().into(),
        signer_id,
        1,
        0,
        Data::Precommit(Some((block_id, sig))),
      )
      .await;
      let tx = tx_from_evidence::<N>(vec![signed]);

      assert!(verify_tendermint_tx::<N>(&tx, genesis, validators.clone(), commit).is_ok());
    }

    // Empty Precommit should fail.
    {
      let signed =
        signed_from_data::<N>(signer.into(), signer_id, 1, 0, Data::Precommit(None)).await;
      let tx = tx_from_evidence::<N>(vec![signed]);

      assert!(verify_tendermint_tx::<N>(&tx, genesis, validators, commit).is_err());
    }
  }

  async fn prevote_evidence_tx() {
    let (genesis, signer, signer_id, validators) = signer().await;
    let commit = |_: u32| -> Option<Commit<Arc<Validators>>> {
      Some(Commit::<Arc<Validators>> { end_time: 0, validators: vec![], signature: vec![] })
    };
    let block_id = [0u8; 32];

    let signed =
      signed_from_data::<N>(signer.into(), signer_id, 0, 0, Data::Prevote(Some(block_id))).await;
    let tx = tx_from_evidence::<N>(vec![signed]);

    // prevote can't be used as evidence
    assert!(verify_tendermint_tx::<N>(&tx, genesis, validators, commit).is_err());
  }

  async fn conflicting_msgs_evidence_tx() {
    let (genesis, signer, signer_id, validators) = signer().await;
    let commit = |_: u32| -> Option<Commit<Arc<Validators>>> {
      Some(Commit::<Arc<Validators>> { end_time: 0, validators: vec![], signature: vec![] })
    };

    // non-conflicting data should fail(Proposal)
    {
      let signed_1 = signed_from_data::<N>(
        signer.clone().into(),
        signer_id,
        0,
        0,
        Data::Proposal(Some(RoundNumber(0)), TendermintBlock(vec![0x11])),
      )
      .await;
      let signed_2 = signed_from_data::<N>(
        signer.clone().into(),
        signer_id,
        0,
        0,
        Data::Proposal(Some(RoundNumber(0)), TendermintBlock(vec![0x11])),
      )
      .await;
      let tx = tx_from_evidence::<N>(vec![signed_1, signed_2]);

      assert!(verify_tendermint_tx::<N>(&tx, genesis, validators.clone(), commit).is_err());
    }

    // conflicting data should pass(Proposal)
    {
      let signed_1 = signed_from_data::<N>(
        signer.clone().into(),
        signer_id,
        0,
        0,
        Data::Proposal(Some(RoundNumber(0)), TendermintBlock(vec![0x11])),
      )
      .await;
      let signed_2 = signed_from_data::<N>(
        signer.clone().into(),
        signer_id,
        0,
        0,
        Data::Proposal(Some(RoundNumber(0)), TendermintBlock(vec![0x22])),
      )
      .await;
      let tx = tx_from_evidence::<N>(vec![signed_1, signed_2]);

      assert!(verify_tendermint_tx::<N>(&tx, genesis, validators.clone(), commit).is_ok());
    }

    // non-conflicting data should fail(Prevote)
    {
      let block_id_1 = [0u8; 32];
      let block_id_2 = block_id_1;
      let signed_1 = signed_from_data::<N>(
        signer.clone().into(),
        signer_id,
        0,
        0,
        Data::Prevote(Some(block_id_1)),
      )
      .await;
      let signed_2 = signed_from_data::<N>(
        signer.clone().into(),
        signer_id,
        0,
        0,
        Data::Prevote(Some(block_id_2)),
      )
      .await;
      let tx = tx_from_evidence::<N>(vec![signed_1, signed_2]);

      assert!(verify_tendermint_tx::<N>(&tx, genesis, validators.clone(), commit).is_err());
    }

    // conflicting data should pass(Prevote)
    {
      let block_id_1 = [0u8; 32];
      let block_id_2 = [1u8; 32];
      let signed_1 = signed_from_data::<N>(
        signer.clone().into(),
        signer_id,
        0,
        0,
        Data::Prevote(Some(block_id_1)),
      )
      .await;
      let signed_2 = signed_from_data::<N>(
        signer.clone().into(),
        signer_id,
        0,
        0,
        Data::Prevote(Some(block_id_2)),
      )
      .await;
      let tx = tx_from_evidence::<N>(vec![signed_1, signed_2]);

      assert!(verify_tendermint_tx::<N>(&tx, genesis, validators.clone(), commit).is_ok());
    }

    // non-conflicting data should fail irrespective of round number(Precommit)
    {
      let block_id_1 = [0u8; 32];
      let block_id_2 = block_id_1;
      let sig = signer.sign(&block_id_1).await; // signature doesn't matter
      let signed_1 = signed_from_data::<N>(
        signer.clone().into(),
        signer_id,
        0,
        0,
        Data::Precommit(Some((block_id_1, sig))),
      )
      .await;
      let signed_2 = signed_from_data::<N>(
        signer.clone().into(),
        signer_id,
        0,
        1,
        Data::Precommit(Some((block_id_2, sig))),
      )
      .await;
      let tx = tx_from_evidence::<N>(vec![signed_1, signed_2]);

      assert!(verify_tendermint_tx::<N>(&tx, genesis, validators.clone(), commit).is_err());
    }

    // conflicting data should pass irrespective of round number(Precommit)
    {
      let block_id_1 = [0u8; 32];
      let block_id_2 = [1u8; 32];
      let sig = signer.sign(&block_id_1).await; // signature doesn't matter
      let signed_1 = signed_from_data::<N>(
        signer.clone().into(),
        signer_id,
        0,
        0,
        Data::Precommit(Some((block_id_1, sig))),
      )
      .await;
      let signed_2 = signed_from_data::<N>(
        signer.clone().into(),
        signer_id,
        0,
        1,
        Data::Precommit(Some((block_id_2, sig))),
      )
      .await;
      let tx = tx_from_evidence::<N>(vec![signed_1, signed_2]);

      assert!(verify_tendermint_tx::<N>(&tx, genesis, validators.clone(), commit).is_ok());
    }

    // msgs to different block numbers should fail
    {
      let data = Data::Proposal(Some(RoundNumber(0)), TendermintBlock(vec![]));
      let signed_1 =
        signed_from_data::<N>(signer.clone().into(), signer_id, 0, 0, data.clone()).await;
      let signed_2 =
        signed_from_data::<N>(signer.clone().into(), signer_id, 1, 0, data.clone()).await;
      let tx = tx_from_evidence::<N>(vec![signed_1, signed_2]);

      assert!(verify_tendermint_tx::<N>(&tx, genesis, validators.clone(), commit).is_err());
    }

    // msgs from different senders should fail
    {
      let data = Data::Proposal(Some(RoundNumber(0)), TendermintBlock(vec![]));
      let signed_1 =
        signed_from_data::<N>(signer.clone().into(), signer_id, 0, 0, data.clone()).await;

      let signer_2 =
        Signer::new(genesis, Zeroizing::new(<Ristretto as Ciphersuite>::F::random(&mut OsRng)));
      let signed_id_2 = signer_2.validator_id().await.unwrap();
      let signed_2 = signed_from_data::<N>(signer_2.into(), signed_id_2, 0, 0, data.clone()).await;

      let tx = tx_from_evidence::<N>(vec![signed_1, signed_2]);

      // update schema so that we don't fail due to invalid signature
      let signer_g =
        <Ristretto as Ciphersuite>::read_G::<&[u8]>(&mut signer_id.as_slice()).unwrap();
      let signer_g_2 =
        <Ristretto as Ciphersuite>::read_G::<&[u8]>(&mut signed_id_2.as_slice()).unwrap();
      let validators =
        Arc::new(Validators::new(genesis, vec![(signer_g, 1), (signer_g_2, 1)]).unwrap());

      assert!(verify_tendermint_tx::<N>(&tx, genesis, validators, commit).is_err());
    }

    //  msgs with different round number should fail even with conflicting data
    {
      let signed_1 = signed_from_data::<N>(
        signer.clone().into(),
        signer_id,
        0,
        0,
        Data::Prevote(Some([0u8; 32])),
      )
      .await;
      let signed_2 = signed_from_data::<N>(
        signer.clone().into(),
        signer_id,
        0,
        1,
        Data::Prevote(Some([1u8; 32])),
      )
      .await;
      let tx = tx_from_evidence::<N>(vec![signed_1, signed_2]);

      assert!(verify_tendermint_tx::<N>(&tx, genesis, validators.clone(), commit).is_err());
    }

    // msgs with different steps should fail
    {
      let signed_1 = signed_from_data::<N>(
        signer.clone().into(),
        signer_id,
        0,
        0,
        Data::Proposal(Some(RoundNumber(0)), TendermintBlock(vec![])),
      )
      .await;
      let signed_2 = signed_from_data::<N>(
        signer.clone().into(),
        signer_id,
        0,
        0,
        Data::Prevote(Some([0u8; 32])),
      )
      .await;
      let tx = tx_from_evidence::<N>(vec![signed_1, signed_2]);

      assert!(verify_tendermint_tx::<N>(&tx, genesis, validators.clone(), commit).is_err());
    }
  }
);
