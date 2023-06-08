use std::sync::Arc;

use crate::{
  tendermint::{tx::{TendermintTx, verify_tendermint_tx}, Validators, TendermintNetwork, TendermintBlock, Signer}, ReadWrite,
  tests::{random_evidence_tx, random_vote_tx, SignedTransaction, p2p::LocalP2p}
};

use ciphersuite::{Ristretto, Ciphersuite, group::ff::Field};
use blake2::{Blake2s256, Digest};
use rand::{RngCore, rngs::OsRng};
use scale::Encode;

use schnorr::SchnorrSignature;
use zeroize::Zeroizing;

use serai_db::MemDb;

use tendermint::{
  SignedMessage, Message, Data, DataFor,
  ext::{RoundNumber, BlockNumber, Signer as SignerTrait, Commit, Network, SignatureScheme},
  SignedMessageFor, commit_msg, round::RoundData, time::CanonicalInstant
};

use lazy_static::lazy_static;

use tokio::sync::Mutex;

type N = TendermintNetwork<MemDb, SignedTransaction, LocalP2p>;

lazy_static! {
  pub static ref SEQUENTIAL: Mutex<()> = Mutex::new(());
}

macro_rules! async_sequential {
  ($(async fn $name: ident() $body: block)*) => {
    $(
      #[tokio::test]
      async fn $name() {
        let guard = SEQUENTIAL.lock().await;
        let local = tokio::task::LocalSet::new();
        local.run_until(async move {
          if let Err(err) = tokio::task::spawn_local(async move { $body }).await {
            drop(guard);
            Err(err).unwrap()
          }
        }).await;
      }
    )*
  }
}

async fn signer() -> ([u8; 32], Signer, [u8; 32], Arc<Validators>) {
  // signer
  let mut genesis = [0; 32];
  OsRng.fill_bytes(&mut genesis);
  let signer = Signer::new(genesis, Zeroizing::new(<Ristretto as Ciphersuite>::F::random(&mut OsRng)));
  let validator_id = signer.validator_id().await.unwrap();

  // schema
  let signer_g = <Ristretto as Ciphersuite>::read_G::<&[u8]>(&mut validator_id.as_slice()).unwrap();
  let validators = Arc::new(Validators::new(genesis, vec![(signer_g, 1)]).unwrap());

  (genesis, signer, validator_id, validators)
}

fn encode_evidence<N: Network>(ev: Vec<SignedMessageFor<N>>) -> Vec<u8> {
  let mut data = vec![];
  data.extend(u8::to_le_bytes(u8::try_from(ev.len()).unwrap()));
  for msg in ev {
    let encoded = msg.encode();
    data.extend(u32::to_le_bytes(u32::try_from(encoded.len()).unwrap()));
    data.extend(encoded);
  }
  data
}

fn tx_from_evidence<N: Network>(ev: Vec<SignedMessageFor<N>>) -> TendermintTx {
  let evidence = encode_evidence::<N>(ev);
  TendermintTx::SlashEvidence(evidence)
}

async fn signed_from_data<N: Network>(
  signer: <N::SignatureScheme as SignatureScheme>::Signer,
  signer_id: N::ValidatorId,
  block_number: u64,
  round_number: u32,
  data: DataFor<N>
) -> SignedMessageFor<N> {
  let msg = Message{ sender: signer_id, block: BlockNumber(block_number), round: RoundNumber(round_number), data };
  let sig = signer.sign(&msg.encode()).await;
  SignedMessage{ msg, sig }
}

#[test]
fn serialize_tendermint() {
  // make a tendermint tx with random evidence
  let tx = random_evidence_tx(&mut OsRng);
  let res = TendermintTx::read::<&[u8]>(&mut  tx.serialize().as_ref()).unwrap();
  assert_eq!(res, tx);

  // with vote tx
  let (_, vote_tx) = random_vote_tx(&mut OsRng);
  let vote_res = TendermintTx::read::<&[u8]>(&mut  vote_tx.serialize().as_ref()).unwrap();
  assert_eq!(vote_res, vote_tx);
}

#[test]
fn vote_tx() {
  let (genesis, mut tx) = random_vote_tx(&mut OsRng);

  let commit = |_: u32| -> Option<Commit<Arc<Validators>>> {
    Some(Commit::<Arc<Validators>> {end_time: 0, validators: vec![], signature: vec![] })
  };
  let validators = Arc::new(Validators::new(genesis, vec![]).unwrap());

  // should pass
  assert!(verify_tendermint_tx::<N>(&tx, genesis, validators.clone(), commit).is_ok());
  
  if let TendermintTx::SlashVote(vote) = &mut tx {
    vote.sig.signature = SchnorrSignature::default();
  }
  
  // should fail
  assert!(verify_tendermint_tx::<N>(&tx, genesis, validators, commit).is_err());
}

async_sequential!(

  async fn msg_signature() {
    // signer
    let (genesis, signer, signer_id, validators) = signer().await;
    let commit = |_: u32| -> Option<Commit<Arc<Validators>>> {
      Some(Commit::<Arc<Validators>> {end_time: 0, validators: vec![], signature: vec![] })
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
      Some(Commit::<Arc<Validators>> {end_time: 0, validators: vec![], signature: vec![] })
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
      Some(Commit::<Arc<Validators>> {end_time: 1686040916, validators: vec![], signature: vec![] })
    };
    let block_id = [0u8; 32];

    // calculate the end time of the round 0
    let last_end_time = RoundData::<N>::new(RoundNumber(0), CanonicalInstant::new(commit(0).unwrap().end_time)).end_time();
    let commit_msg = commit_msg(last_end_time.canonical(), block_id.as_ref());

    // valid precommit msg should fail.
    {
      let sig = signer.sign(&commit_msg).await;
      let signed = signed_from_data::<N>(signer.clone().into(), signer_id, 1, 0,  Data::Precommit(Some((block_id, sig)))).await;
      let tx = tx_from_evidence::<N>(vec![signed]);

      assert!(verify_tendermint_tx::<N>(&tx, genesis, validators.clone(), commit).is_err());
    }

    // any other commit(invalid) can be used as evidence.
    {
      let sig = signer.sign(&Blake2s256::digest(commit_msg).to_vec()).await;
      let signed = signed_from_data::<N>(signer.clone().into(), signer_id, 1, 0,  Data::Precommit(Some((block_id, sig)))).await;
      let tx = tx_from_evidence::<N>(vec![signed]);

      assert!(verify_tendermint_tx::<N>(&tx, genesis, validators.clone(), commit).is_ok());
    }

    // Empty Precommit should fail.
    {
      let signed = signed_from_data::<N>(signer.into(), signer_id, 1, 0, Data::Precommit(None)).await;
      let tx = tx_from_evidence::<N>(vec![signed]);

      assert!(verify_tendermint_tx::<N>(&tx, genesis, validators, commit).is_err());
    }
  }

  async fn prevote_evidence_tx() {
    let (genesis, signer, signer_id, validators) = signer().await;
    let commit = |_: u32| -> Option<Commit<Arc<Validators>>> {
      Some(Commit::<Arc<Validators>> {end_time: 0, validators: vec![], signature: vec![] })
    };
    let block_id = [0u8; 32];

    let signed = signed_from_data::<N>(signer.into(), signer_id, 0, 0, Data::Prevote(Some(block_id))).await;
    let tx = tx_from_evidence::<N>(vec![signed]);

    // prevote can't be used as evidence
    assert!(verify_tendermint_tx::<N>(&tx, genesis, validators, commit).is_err());
  }

  async fn conflicting_msgs_evidence_tx() {
    let (genesis, signer, signer_id, validators) = signer().await;
    let commit = |_: u32| -> Option<Commit<Arc<Validators>>> {
      Some(Commit::<Arc<Validators>> {end_time: 0, validators: vec![], signature: vec![] })
    };

    // non-conflicting data should fail(Proposal)
    {
      let signed_1 = signed_from_data::<N>(signer.clone().into(), signer_id, 0, 0, Data::Proposal(Some(RoundNumber(0)), TendermintBlock(vec![0x11]))).await;
      let signed_2 = signed_from_data::<N>(signer.clone().into(), signer_id, 0, 0, Data::Proposal(Some(RoundNumber(0)), TendermintBlock(vec![0x11]))).await;
      let tx = tx_from_evidence::<N>(vec![signed_1, signed_2]);

      assert!(verify_tendermint_tx::<N>(&tx, genesis, validators.clone(), commit).is_err());
    }

    // conflicting data should pass(Proposal)
    {
      let signed_1 = signed_from_data::<N>(signer.clone().into(), signer_id, 0, 0, Data::Proposal(Some(RoundNumber(0)), TendermintBlock(vec![0x11]))).await;
      let signed_2 = signed_from_data::<N>(signer.clone().into(), signer_id, 0, 0, Data::Proposal(Some(RoundNumber(0)), TendermintBlock(vec![0x22]))).await;
      let tx = tx_from_evidence::<N>(vec![signed_1, signed_2]);

      assert!(verify_tendermint_tx::<N>(&tx, genesis, validators.clone(), commit).is_ok());
    }

    // non-conflicting data should fail(Prevote)
    {
      let block_id_1 = [0u8; 32];
      let block_id_2 = block_id_1.clone();
      let signed_1 = signed_from_data::<N>(signer.clone().into(), signer_id, 0, 0, Data::Prevote(Some(block_id_1))).await;
      let signed_2 = signed_from_data::<N>(signer.clone().into(), signer_id, 0, 0, Data::Prevote(Some(block_id_2))).await;
      let tx = tx_from_evidence::<N>(vec![signed_1, signed_2]);

      assert!(verify_tendermint_tx::<N>(&tx, genesis, validators.clone(), commit).is_err());
    }

    // conflicting data should pass(Prevote)
    {
      let block_id_1 = [0u8; 32];
      let block_id_2 = [1u8; 32];
      let signed_1 = signed_from_data::<N>(signer.clone().into(), signer_id, 0, 0, Data::Prevote(Some(block_id_1))).await;
      let signed_2 = signed_from_data::<N>(signer.clone().into(), signer_id, 0, 0, Data::Prevote(Some(block_id_2))).await;
      let tx = tx_from_evidence::<N>(vec![signed_1, signed_2]);

      assert!(verify_tendermint_tx::<N>(&tx, genesis, validators.clone(), commit).is_ok());
    }

    // non-conflicting data should fail irrespective of round number(Precommit)
    {
      let block_id_1 = [0u8; 32];
      let block_id_2 = block_id_1.clone();
      let sig = signer.sign(&block_id_1).await; // signature doesn't matter
      let signed_1 = signed_from_data::<N>(signer.clone().into(), signer_id, 0, 0, Data::Precommit(Some((block_id_1, sig)))).await;
      let signed_2 = signed_from_data::<N>(signer.clone().into(), signer_id, 0, 1, Data::Precommit(Some((block_id_2, sig)))).await;
      let tx = tx_from_evidence::<N>(vec![signed_1, signed_2]);

      assert!(verify_tendermint_tx::<N>(&tx, genesis, validators.clone(), commit).is_err());
    }

    // conflicting data should pass irrespective of round number(Precommit)
    {
      let block_id_1 = [0u8; 32];
      let block_id_2 = [1u8; 32];
      let sig = signer.sign(&block_id_1).await; // signature doesn't matter
      let signed_1 = signed_from_data::<N>(signer.clone().into(), signer_id, 0, 0, Data::Precommit(Some((block_id_1, sig)))).await;
      let signed_2 = signed_from_data::<N>(signer.clone().into(), signer_id, 0, 1, Data::Precommit(Some((block_id_2, sig)))).await;
      let tx = tx_from_evidence::<N>(vec![signed_1, signed_2]);

      assert!(verify_tendermint_tx::<N>(&tx, genesis, validators.clone(), commit).is_ok());
    }

    // msgs to different block numbers should fail
    {
      let data = Data::Proposal(Some(RoundNumber(0)), TendermintBlock(vec![]));
      let signed_1 = signed_from_data::<N>(signer.clone().into(), signer_id, 0, 0, data.clone()).await;
      let signed_2 = signed_from_data::<N>(signer.clone().into(), signer_id, 1, 0, data.clone()).await;
      let tx = tx_from_evidence::<N>(vec![signed_1, signed_2]);

      assert!(verify_tendermint_tx::<N>(&tx, genesis, validators.clone(), commit).is_err());
    }

    // msgs from different senders should fail
    {
      let data = Data::Proposal(Some(RoundNumber(0)), TendermintBlock(vec![]));
      let signed_1 = signed_from_data::<N>(signer.clone().into(), signer_id, 0, 0, data.clone()).await;

      let signer_2 = Signer::new(genesis, Zeroizing::new(<Ristretto as Ciphersuite>::F::random(&mut OsRng)));
      let signed_id_2 = signer_2.validator_id().await.unwrap();
      let signed_2 = signed_from_data::<N>(signer_2.into(), signed_id_2, 0, 0, data.clone()).await;

      let tx = tx_from_evidence::<N>(vec![signed_1, signed_2]);

      // update schema so that we don't fail due to invalid signature
      let signer_g = <Ristretto as Ciphersuite>::read_G::<&[u8]>(&mut signer_id.as_slice()).unwrap();
      let signer_g_2 = <Ristretto as Ciphersuite>::read_G::<&[u8]>(&mut signed_id_2.as_slice()).unwrap();
      let validators = Arc::new(Validators::new(genesis, vec![(signer_g, 1), (signer_g_2, 1)]).unwrap());

      assert!(verify_tendermint_tx::<N>(&tx, genesis, validators, commit).is_err());
    }

    //  msgs with different round number should fail even with conflicting data
    {
      let signed_1 = signed_from_data::<N>(signer.clone().into(), signer_id, 0, 0, Data::Prevote(Some([0u8; 32]))).await;
      let signed_2 = signed_from_data::<N>(signer.clone().into(), signer_id, 0, 1, Data::Prevote(Some([1u8; 32]))).await;
      let tx = tx_from_evidence::<N>(vec![signed_1, signed_2]);

      assert!(verify_tendermint_tx::<N>(&tx, genesis, validators.clone(), commit).is_err());
    }

    // msgs with different steps should fail
    {
      let signed_1 = signed_from_data::<N>(signer.clone().into(), signer_id, 0, 0, Data::Proposal(Some(RoundNumber(0)), TendermintBlock(vec![]))).await;
      let signed_2 = signed_from_data::<N>(signer.clone().into(), signer_id, 0, 0, Data::Prevote(Some([0u8; 32]))).await;
      let tx = tx_from_evidence::<N>(vec![signed_1, signed_2]);

      assert!(verify_tendermint_tx::<N>(&tx, genesis, validators.clone(), commit).is_err());
    }
  }
);
