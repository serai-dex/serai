use core::ops::Deref as _;

use rand::{CryptoRng, RngCore, rngs::OsRng};
use schnorr::SchnorrSignature;
use zeroize::Zeroizing;

use ciphersuite::{group::Group as _, *};
use dalek_ff_group::Ristretto;

use serai_primitives::{validator_sets::KeyShares, address::SeraiAddress};
use serai_substrate_tests::{random_serai_address, random_block_hash};

use messages::sign::VariantSignId;

use tributary_sdk::{
  ReadWrite,
  tests::new_genesis,
  transaction::{Transaction as TransactionTrait, TransactionError, TransactionKind},
};

use crate::db::Topic;
use crate::transaction::{SigningProtocolRound, Signed, Transaction};

fn random_key<R: RngCore + CryptoRng>(rng: &mut R) -> Zeroizing<<Ristretto as WrappedGroup>::F> {
  Zeroizing::new(<Ristretto as WrappedGroup>::F::random(&mut *rng))
}

fn random_signed<R: RngCore + CryptoRng>(rng: &mut R) -> Signed {
  let signed = tributary_sdk::tests::random_signed(&mut *rng);
  Signed { signer: signed.signer, signature: signed.signature }
}

/// One of each signed transaction kind with default signatures.
fn all_signed_transactions() -> Vec<Transaction> {
  vec![
    Transaction::RemoveParticipant {
      participant: random_serai_address(&mut OsRng),
      signed: random_signed(&mut OsRng),
    },
    Transaction::DkgParticipation {
      participation: vec![1, 2, 3],
      signed: random_signed(&mut OsRng),
    },
    Transaction::DkgConfirmationPreprocess {
      attempt: 0,
      preprocess: [1; 64],
      signed: random_signed(&mut OsRng),
    },
    Transaction::DkgConfirmationShare {
      attempt: 0,
      share: [1; 32],
      signed: random_signed(&mut OsRng),
    },
    Transaction::Sign {
      id: VariantSignId::Transaction([0; 32]),
      attempt: 0,
      round: SigningProtocolRound::Preprocess,
      data: vec![vec![1, 2, 3]],
      signed: random_signed(&mut OsRng),
    },
    Transaction::Sign {
      id: VariantSignId::Transaction([0; 32]),
      attempt: 0,
      round: SigningProtocolRound::Share,
      data: vec![vec![1, 2, 3]],
      signed: random_signed(&mut OsRng),
    },
    Transaction::SlashReport { slash_points: vec![0, 1, 2], signed: random_signed(&mut OsRng) },
  ]
}

/// One of each provided transaction kind.
fn all_provided_transactions() -> Vec<Transaction> {
  vec![
    Transaction::Cosign { substrate_block_hash: random_block_hash(&mut OsRng) },
    Transaction::Cosigned { substrate_block_hash: random_block_hash(&mut OsRng) },
    Transaction::SubstrateBlock { hash: random_block_hash(&mut OsRng) },
    Transaction::Batch { hash: random_block_hash(&mut OsRng).0 },
  ]
}

/// One of each of all transaction kinds.
fn all_transactions() -> Vec<Transaction> {
  let mut txs = all_signed_transactions();
  txs.extend(all_provided_transactions());
  txs
}

fn all_signing_protocol_rounds() -> Vec<SigningProtocolRound> {
  vec![SigningProtocolRound::Preprocess, SigningProtocolRound::Share]
}

#[test]
fn signing_protocol_round_nonce() {
  assert_eq!(SigningProtocolRound::Preprocess.nonce(), 0);
  assert_eq!(SigningProtocolRound::Share.nonce(), 1);
}

mod signed {
  use super::*;

  #[test]
  fn default_signer_is_identity() {
    let default_signed = Signed::default();
    let identity = <Ristretto as WrappedGroup>::G::identity();
    assert_eq!(default_signed.signer(), identity);
    assert_eq!(
      default_signed.signature,
      SchnorrSignature { R: identity, s: <Ristretto as WrappedGroup>::F::ZERO }
    );
  }

  #[test]
  fn to_tributary_signed_matches_signed() {
    let signed = random_signed(&mut OsRng);
    for round in all_signing_protocol_rounds() {
      let tributary_signed = signed.clone().to_tributary_signed(round);
      assert_eq!(signed.signer(), tributary_signed.signer);
      assert_eq!(signed.signature, tributary_signed.signature);
      assert_eq!(tributary_signed.nonce, round.nonce());
    }
  }

  #[test]
  fn signed_borsh_serialize_and_deserialize() {
    use std::io::{self, Read, Write};
    use borsh::{BorshSerialize, BorshDeserialize};

    // Should work
    {
      let signed = random_signed(&mut OsRng);

      let serialized = borsh::to_vec(&signed).unwrap();
      let mut manual_buf = Vec::new();
      signed.serialize(&mut manual_buf).unwrap();
      assert_eq!(serialized, manual_buf);

      let deserialized: Signed = borsh::from_slice(&serialized).unwrap();
      let mut cursor = std::io::Cursor::new(&serialized);
      assert_eq!(deserialized, Signed::deserialize_reader(&mut cursor).unwrap());

      assert_eq!(signed, deserialized);
    }

    // Writer failure returns error
    {
      struct FailingWriter;
      impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
          Err(io::Error::new(io::ErrorKind::Other, "simulated write failure"))
        }
        fn flush(&mut self) -> io::Result<()> {
          Ok(())
        }
      }

      let mut writer = FailingWriter;

      let result = random_signed(&mut OsRng).serialize(&mut writer);
      assert!(result.is_err());
      assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Other);
    }

    // Reader failure returns error
    {
      struct FailingReader;
      impl Read for FailingReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
          Err(io::Error::new(io::ErrorKind::UnexpectedEof, "simulated read failure"))
        }
      }

      let mut failing_reader = FailingReader;
      let result = Signed::deserialize_reader(&mut failing_reader);
      assert!(result.is_err());
      assert_eq!(result.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    }

    // Errors with incomplete data
    {
      let serialized = borsh::to_vec(&random_signed(&mut OsRng)).unwrap();
      let truncated = &serialized[.. 5];
      let mut cursor = std::io::Cursor::new(truncated);
      let result = Signed::deserialize_reader(&mut cursor);
      assert!(result.is_err());
    }
  }
}

#[test]
fn readwrite_transaction() {
  let key = random_key(&mut OsRng);
  let genesis = new_genesis();

  for mut tx in all_transactions() {
    let serialized = ReadWrite::serialize(&tx);
    let deserialized = Transaction::read(&mut serialized.as_slice()).unwrap();
    assert_eq!(tx, deserialized, "ReadWrite failed for {tx:?}");

    match tx.kind() {
      TransactionKind::Signed(_, _) => {
        tx.sign(&mut OsRng, genesis, &key);
        let serialized = ReadWrite::serialize(&tx);
        let deserialized = Transaction::read(&mut serialized.as_slice()).unwrap();
        assert_eq!(tx, deserialized, "ReadWrite failed after signing for {tx:?}");
      }
      _ => {}
    }
  }
}

mod kind {
  use super::*;

  #[test]
  fn signed_transactions_matches_kind_and_nonce_and_sig() {
    let key = random_key(&mut OsRng);
    let genesis = new_genesis();

    for mut tx in all_signed_transactions() {
      tx.sign(&mut OsRng, genesis, &key);
      let sig_hash = tx.sig_hash(genesis);

      match tx.kind() {
        TransactionKind::Signed(_, signed) => {
          assert!(
            signed.signature.verify(signed.signer, sig_hash),
            "Signature verification failed for {tx:?}"
          );

          let nonce = signed.nonce;
          match tx {
            Transaction::RemoveParticipant { participant: _, signed: _ } => {
              assert_eq!(nonce, SigningProtocolRound::Preprocess.nonce())
            }
            Transaction::DkgParticipation { participation: _, signed: _ } => {
              assert_eq!(nonce, SigningProtocolRound::Preprocess.nonce())
            }
            Transaction::DkgConfirmationPreprocess { attempt: _, preprocess: _, signed: _ } => {
              assert_eq!(nonce, SigningProtocolRound::Share.nonce())
            }
            Transaction::DkgConfirmationShare { attempt: _, share: _, signed: _ } => {
              assert_eq!(nonce, SigningProtocolRound::Share.nonce())
            }
            Transaction::Sign { id: _, attempt: _, round, data: _, signed: _ } => {
              assert_eq!(nonce, round.nonce())
            }
            Transaction::SlashReport { slash_points: _, signed: _ } => {
              assert_eq!(nonce, SigningProtocolRound::Preprocess.nonce())
            }
            _ => panic!("Expected Signed kind for {tx:?}"),
          }
        }
        _ => panic!("Expected Signed kind for {tx:?}"),
      }
    }
  }

  #[test]
  fn provided_transactions_kind() {
    let expected: Vec<(&str, Transaction)> = vec![
      ("Cosign", Transaction::Cosign { substrate_block_hash: random_block_hash(&mut OsRng) }),
      ("Cosigned", Transaction::Cosigned { substrate_block_hash: random_block_hash(&mut OsRng) }),
      ("SubstrateBlock", Transaction::SubstrateBlock { hash: random_block_hash(&mut OsRng) }),
      ("Batch", Transaction::Batch { hash: random_block_hash(&mut OsRng).0 }),
    ];

    for (order, tx) in expected {
      match tx.kind() {
        TransactionKind::Provided(actual_order) => {
          assert_eq!(actual_order, order, "Wrong order for {tx:?}");
        }
        other => panic!("Expected Provided kind, got {other:?} for {tx:?}"),
      }
    }
  }
}

mod hash {
  use super::*;

  #[test]
  fn hash_is_deterministic() {
    let key = random_key(&mut OsRng);
    let genesis = new_genesis();

    for tx_template in all_signed_transactions() {
      assert_eq!(
        tx_template.hash(),
        tx_template.hash(),
        "Hash not deterministic for {tx_template:?}"
      );

      let mut tx1 = tx_template.clone();
      let mut tx2 = tx_template;

      tx1.sign(&mut OsRng, genesis, &key);
      tx2.sign(&mut OsRng, genesis, &key);

      // Signing produces different random nonces and different signatures, but the hash strips the signature
      assert_eq!(tx1.hash(), tx2.hash(), "Hashes should be equal despite different signatures");
    }
  }

  #[test]
  fn hash_differs_for_distinct_transactions() {
    let txs = all_transactions();
    for i in 0 .. txs.len() {
      for j in (i + 1) .. txs.len() {
        assert_ne!(
          txs[i].hash(),
          txs[j].hash(),
          "Distinct TXs should have different hashes: {:?} vs {:?}",
          txs[i],
          txs[j]
        );
      }
    }
  }
}

#[test]
fn tx_verify() {
  // All default transactions are valid
  {
    for tx in all_transactions() {
      assert_eq!(tx.verify(), Ok(()), "verify() rejected valid tx: {tx:?}");
    }
  }

  {
    // Transaction::Sign with data == KeyShares::MAX_PER_SET passes
    assert_eq!(
      Transaction::Sign {
        id: VariantSignId::Transaction([0; 32]),
        attempt: 0,
        round: SigningProtocolRound::Preprocess,
        data: vec![vec![]; usize::from(KeyShares::MAX_PER_SET)],
        signed: Signed::default(),
      }
      .verify(),
      Ok(())
    );
    // Transaction::Sign with data > KeyShares::MAX_PER_SET fails
    assert_eq!(
      Transaction::Sign {
        id: VariantSignId::Transaction([0; 32]),
        attempt: 0,
        round: SigningProtocolRound::Preprocess,
        data: vec![vec![]; usize::from(KeyShares::MAX_PER_SET) + 1],
        signed: Signed::default(),
      }
      .verify(),
      Err(TransactionError::InvalidContent)
    );
  }

  {
    // Transaction::SlashReport with slash_points == KeyShares::MAX_PER_SET passes
    let slash_at = Transaction::SlashReport {
      slash_points: vec![0; usize::from(KeyShares::MAX_PER_SET)],
      signed: Signed::default(),
    };
    assert_eq!(slash_at.verify(), Ok(()));

    // Transaction::SlashReport with slash_points == KeyShares::MAX_PER_SET fails
    let slash_over = Transaction::SlashReport {
      slash_points: vec![0; usize::from(KeyShares::MAX_PER_SET) + 1],
      signed: Signed::default(),
    };
    assert_eq!(slash_over.verify(), Err(TransactionError::InvalidContent));
  }
}

#[test]
fn topic_returns_correct_mapping() {
  let participant = SeraiAddress([1; 32]);

  // RemoveParticipant → Some(RemoveParticipant)
  let tx = Transaction::RemoveParticipant { participant, signed: Signed::default() };
  assert_eq!(tx.topic(), Some(Topic::RemoveParticipant { participant }));

  // DkgParticipation → None
  let tx = Transaction::DkgParticipation { participation: vec![], signed: Signed::default() };
  assert_eq!(tx.topic(), None);

  // DkgConfirmationPreprocess → DkgConfirmation with Preprocess round
  let tx = Transaction::DkgConfirmationPreprocess {
    attempt: 5,
    preprocess: [0; 64],
    signed: Signed::default(),
  };
  assert_eq!(
    tx.topic(),
    Some(Topic::DkgConfirmation { attempt: 5, round: SigningProtocolRound::Preprocess })
  );

  // DkgConfirmationShare → DkgConfirmation with Share round
  let tx =
    Transaction::DkgConfirmationShare { attempt: 3, share: [0; 32], signed: Signed::default() };
  assert_eq!(
    tx.topic(),
    Some(Topic::DkgConfirmation { attempt: 3, round: SigningProtocolRound::Share })
  );

  // Provided transactions → None
  for tx in all_provided_transactions() {
    assert_eq!(tx.topic(), None, "Provided tx should have no topic: {tx:?}");
  }

  // Sign → Topic::Sign preserving all fields
  let id = VariantSignId::Batch([9; 32]);
  let tx = Transaction::Sign {
    id,
    attempt: 2,
    round: SigningProtocolRound::Share,
    data: vec![],
    signed: Signed::default(),
  };
  assert_eq!(tx.topic(), Some(Topic::Sign { id, attempt: 2, round: SigningProtocolRound::Share }));

  // SlashReport → Topic::SlashReport
  let tx = Transaction::SlashReport { slash_points: vec![], signed: Signed::default() };
  assert_eq!(tx.topic(), Some(Topic::SlashReport));
}

mod sign {
  use super::*;

  #[test]
  fn tx_sign() {
    let key = random_key(&mut OsRng);
    let expected_signer = Ristretto::generator() * key.deref();
    let genesis = new_genesis();

    // Sets correct signer and produces verifiable signature
    for mut tx in all_signed_transactions() {
      tx.sign(&mut OsRng, genesis, &key);
      let sig_hash = tx.sig_hash(genesis);

      if let TransactionKind::Signed(_, trib_signed) = tx.kind() {
        assert_eq!(trib_signed.signer, expected_signer, "Wrong signer for {tx:?}");
        assert!(
          trib_signed.signature.verify(trib_signed.signer, sig_hash),
          "Signature verification failed for {tx:?}"
        );
      }
    }

    // Wrong genesis fails verification
    {
      let mut tx = Transaction::RemoveParticipant {
        participant: SeraiAddress([1; 32]),
        signed: Signed::default(),
      };
      tx.sign(&mut OsRng, new_genesis(), &key);

      let wrong_challenge = tx.sig_hash([1; 32]);
      if let TransactionKind::Signed(_, trib_signed) = tx.kind() {
        assert!(
          !trib_signed.signature.verify(trib_signed.signer, wrong_challenge),
          "Signature should not verify with wrong genesis"
        );
      }
    }
  }

  #[test]
  #[should_panic(expected = "signing Cosign transaction (provided)")]
  fn sign_panics_on_cosign() {
    let key = random_key(&mut OsRng);
    let mut tx = Transaction::Cosign { substrate_block_hash: random_block_hash(&mut OsRng) };
    tx.sign(&mut OsRng, new_genesis(), &key);
  }

  #[test]
  #[should_panic(expected = "signing Cosigned transaction (provided)")]
  fn sign_panics_on_cosigned() {
    let key = random_key(&mut OsRng);
    let mut tx = Transaction::Cosigned { substrate_block_hash: random_block_hash(&mut OsRng) };
    tx.sign(&mut OsRng, new_genesis(), &key);
  }

  #[test]
  #[should_panic(expected = "signing SubstrateBlock transaction (provided)")]
  fn sign_panics_on_substrate_block() {
    let key = random_key(&mut OsRng);
    let mut tx = Transaction::SubstrateBlock { hash: random_block_hash(&mut OsRng) };
    tx.sign(&mut OsRng, new_genesis(), &key);
  }

  #[test]
  #[should_panic(expected = "signing Batch transaction (provided)")]
  fn sign_panics_on_batch() {
    let key = random_key(&mut OsRng);
    let mut tx = Transaction::Batch { hash: random_block_hash(&mut OsRng).0 };
    tx.sign(&mut OsRng, new_genesis(), &key);
  }
}
