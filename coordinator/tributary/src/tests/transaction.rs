use core::ops::Deref as _;
use std::{
  io::{self, Cursor, Read, Write},
  collections::HashSet,
};

use rand_core::OsRng;
use blake2::{digest::typenum::U32, Digest as _, Blake2b};
use ciphersuite::group::{ff::PrimeField as _, Group as _};
use dalek_ff_group::Ristretto;

use borsh::{BorshDeserialize as _, BorshSerialize as _};

use messages::sign::VariantSignId;
use serai_primitives::validator_sets::KeyShares;
use tributary_sdk::{
  ReadWrite,
  transaction::{TransactionKind, TransactionError},
};

use super::*;

fn all_signing_protocol_rounds() -> Vec<SigningProtocolRound> {
  vec![SigningProtocolRound::Preprocess, SigningProtocolRound::Share]
}

#[test]
fn signing_protocol_round_nonce() {
  for (i, round) in all_signing_protocol_rounds().into_iter().enumerate() {
    assert_eq!(round.nonce(), u32::try_from(i).unwrap(), "Wrong nonce for {round:?}");
  }
}

mod signed {
  use super::*;

  #[test]
  fn borsh_serialize_and_deserialize() {
    // Check the format of `Signed`
    {
      let signed = random_signed(&mut OsRng);
      let serialized = borsh::to_vec(&signed).unwrap();

      // `signer || R || s`
      let mut expected: Vec<u8> = Vec::new();
      expected.extend(signed.signer.to_bytes().as_ref());
      expected.extend(signed.signature.R.to_bytes().as_ref());
      expected.extend(signed.signature.s.to_repr().as_ref());
      assert_eq!(serialized, expected, "serialized format should be `signer || R || s`");

      let deserialized: Signed = borsh::from_slice(&serialized).unwrap();
      assert_eq!(signed, deserialized, "round-trip should preserve the original Signed");
    }

    // Should serialize
    {
      let signed = random_signed(&mut OsRng);

      let serialized = borsh::to_vec(&signed).unwrap();
      let mut manual_buf = Vec::new();
      signed.serialize(&mut manual_buf).unwrap();
      assert_eq!(
        serialized, manual_buf,
        "borsh::to_vec and manual serialize should produce identical bytes"
      );

      let deserialized: Signed = borsh::from_slice(&serialized).unwrap();
      assert_eq!(
        deserialized,
        Signed::deserialize_reader(&mut serialized.as_slice()).unwrap(),
        "borsh::from_slice and Signed::deserialize_reader should produce identical results"
      );

      assert_eq!(signed, deserialized, "round-trip should preserve the original Signed");
    }

    // Check writer failure propagation
    {
      struct FailingWriter;
      impl Write for FailingWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
          Err(io::Error::other("simulated write failure"))
        }
        fn flush(&mut self) -> io::Result<()> {
          Ok(())
        }
      }

      let result = random_signed(&mut OsRng).serialize(&mut FailingWriter);
      assert!(result.is_err(), "serialize into a failing writer should error");
      assert_eq!(
        result.unwrap_err().kind(),
        io::ErrorKind::Other,
        "write error kind should be Other"
      );
    }

    // Check reader failure propagation
    {
      struct FailingReader;
      impl Read for FailingReader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
          Err(io::Error::new(io::ErrorKind::UnexpectedEof, "simulated read failure"))
        }
      }

      let result = Signed::deserialize_reader(&mut FailingReader);
      assert!(result.is_err(), "deserialize from a failing reader should error");
      assert_eq!(
        result.unwrap_err().kind(),
        io::ErrorKind::UnexpectedEof,
        "read error kind should be UnexpectedEof"
      );
    }

    // Check incomplete data is rejected (signer read_G fails)
    {
      let serialized = borsh::to_vec(&random_signed(&mut OsRng)).unwrap();
      let truncated = &serialized[.. 5];
      let result = Signed::deserialize_reader(&mut &*truncated);
      assert!(result.is_err(), "truncated data should fail to deserialize");
    }

    // Check missing signature data is rejected (SchnorrSignature::read fails)
    {
      let serialized = borsh::to_vec(&random_signed(&mut OsRng)).unwrap();
      let signer_only = &serialized[.. 32];
      let result = Signed::deserialize_reader(&mut &*signer_only);
      assert!(result.is_err(), "signer-only data without signature should fail to deserialize");
    }
  }

  #[test]
  fn to_tributary_signed_matches_signed() {
    let signed = random_signed(&mut OsRng);
    for round in all_signing_protocol_rounds() {
      let tributary_signed = signed.to_tributary_signed(round.nonce());
      assert_eq!(signed.signer(), tributary_signed.signer);
      assert_eq!(signed.signature, tributary_signed.signature);
      assert_eq!(tributary_signed.nonce, round.nonce());
    }
  }

  #[test]
  fn default_signer_is_identity() {
    let default_signed = Signed::default();
    let identity = <Ristretto as WrappedGroup>::G::identity();
    assert_eq!(default_signed.signer(), identity);
    assert_eq!(default_signed.signature.R, identity);
    assert_eq!(default_signed.signature.s, <Ristretto as WrappedGroup>::F::ZERO);
  }
}

#[allow(clippy::module_inception)]
mod transaction {
  use super::*;

  mod readwrite {
    use super::*;

    #[test]
    fn serialize_and_deserialize() {
      for mut tx in all_transactions() {
        let serialized = ReadWrite::serialize(&tx);

        let expected = match &tx {
          Transaction::RemoveParticipant { participant, signed } => {
            let mut expected = vec![0u8];
            expected.extend(&participant.0);
            expected.extend(borsh::to_vec(signed).unwrap());
            expected
          }
          Transaction::DkgParticipation { participation, signed } => {
            let mut expected = vec![1u8];
            expected.extend(&u32::try_from(participation.len()).unwrap().to_le_bytes());
            expected.extend(participation);
            expected.extend(borsh::to_vec(signed).unwrap());
            expected
          }
          Transaction::DkgConfirmationPreprocess { attempt, preprocess, signed } => {
            let mut expected = vec![2u8];
            expected.extend(&attempt.to_le_bytes());
            expected.extend(preprocess);
            expected.extend(borsh::to_vec(signed).unwrap());
            expected
          }
          Transaction::DkgConfirmationShare { attempt, share, signed } => {
            let mut expected = vec![3u8];
            expected.extend(&attempt.to_le_bytes());
            expected.extend(share);
            expected.extend(borsh::to_vec(signed).unwrap());
            expected
          }
          Transaction::Cosign { substrate_block_hash } => {
            let mut expected = vec![4u8];
            expected.extend(&substrate_block_hash.0);
            expected
          }
          Transaction::Cosigned { substrate_block_hash } => {
            let mut expected = vec![5u8];
            expected.extend(&substrate_block_hash.0);
            expected
          }
          Transaction::SubstrateBlock { hash } => {
            let mut expected = vec![6u8];
            expected.extend(&hash.0);
            expected
          }
          Transaction::Batch { hash } => {
            let mut expected = vec![7u8];
            expected.extend(hash);
            expected
          }
          Transaction::Sign { id, attempt, round, data, signed } => {
            let mut expected = vec![8u8];
            // Independently encode VariantSignId
            match id {
              VariantSignId::Cosign(v) => {
                expected.push(0u8);
                expected.extend(&v.to_le_bytes());
              }
              VariantSignId::Batch(h) => {
                expected.push(1u8);
                expected.extend(h);
              }
              VariantSignId::SlashReport => {
                expected.push(2u8);
              }
              VariantSignId::Transaction(h) => {
                expected.push(3u8);
                expected.extend(h);
              }
            }
            expected.extend(&attempt.to_le_bytes());
            match round {
              SigningProtocolRound::Preprocess => expected.push(0u8),
              SigningProtocolRound::Share => expected.push(1u8),
            }
            expected.extend(&u32::try_from(data.len()).unwrap().to_le_bytes());
            for d in data {
              expected.extend(&u32::try_from(d.len()).unwrap().to_le_bytes());
              expected.extend(d);
            }
            expected.extend(borsh::to_vec(signed).unwrap());
            expected
          }
          Transaction::SlashReport { slash_points, signed } => {
            let mut expected = vec![9u8];
            expected.extend(&u32::try_from(slash_points.len()).unwrap().to_le_bytes());
            for &p in slash_points {
              expected.extend(&p.to_le_bytes());
            }
            expected.extend(borsh::to_vec(signed).unwrap());
            expected
          }
        };

        assert_eq!(serialized, expected, "format mismatch for {tx:?}");

        let deserialized = Transaction::read(&mut serialized.as_slice()).unwrap();
        assert_eq!(tx, deserialized);

        if let TransactionKind::Signed(_, _) = tx.kind() {
          tx.sign(&mut OsRng, random_bytes(&mut OsRng), &random_key(&mut OsRng));
          let serialized = ReadWrite::serialize(&tx);
          let deserialized = Transaction::read(&mut serialized.as_slice()).unwrap();
          assert_eq!(tx, deserialized, "ReadWrite failed after signing for {tx:?}");
        }
      }
    }

    /// Regression test: `Transaction::read` must use `deserialize_reader`, not `borsh::from_reader`
    ///
    /// `borsh::from_reader` asserts the reader is exhausted after deserialization. When multiple
    /// transactions are serialized into a single stream (as happens in `Block::read`), the first
    /// `from_reader` call would fail because subsequent transactions' bytes remain in the reader.
    #[test]
    fn sequential_reads_from_shared_reader() {
      let txs = all_transactions();

      let mut buf = Vec::new();
      buf.extend(&u32::try_from(txs.len()).unwrap().to_le_bytes());
      for tx in &txs {
        tx.write(&mut buf).unwrap();
      }

      let mut cursor = Cursor::new(&buf);
      let mut count = [0u8; 4];
      cursor.read_exact(&mut count).unwrap();

      for (i, expected) in txs.iter().enumerate() {
        let actual = Transaction::read(&mut cursor)
          .unwrap_or_else(|e| panic!("failed to read transaction {i} from shared reader: {e}"));
        assert_eq!(&actual, expected, "transaction {i} mismatch after sequential read");
      }

      let mut leftover = [0u8; 1];
      assert_eq!(
        cursor.read(&mut leftover).unwrap(),
        0,
        "reader should be exhausted after reading all transactions"
      );
    }
  }

  mod kind {
    use super::*;

    #[test]
    fn signed_transactions_match_kind_and_nonce_and_sig() {
      let key = random_key(&mut OsRng);
      let genesis = random_bytes(&mut OsRng);

      /// Borsh-encodes a byte-string label: `len(4 LE) || label`
      fn borsh_label(label: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(&u32::try_from(label.len()).unwrap().to_le_bytes());
        out.extend(label);
        out
      }

      let mut orders = HashSet::new();
      for mut tx in all_signed_transactions_and_attempts(random_signed(&mut OsRng)) {
        tx.sign(&mut OsRng, genesis, &key);

        let (expected_order, expected_nonce) = match &tx {
          Transaction::RemoveParticipant { participant, .. } => {
            let mut order = borsh_label(b"RemoveParticipant");
            order.extend(&participant.0);
            (order, 0)
          }
          Transaction::DkgParticipation { .. } => (borsh_label(b"DkgParticipation"), 0),
          Transaction::DkgConfirmationPreprocess { attempt, .. } => {
            let mut order = borsh_label(b"DkgConfirmation");
            order.extend(&attempt.to_le_bytes());
            (order, 0)
          }
          Transaction::DkgConfirmationShare { attempt, .. } => {
            let mut order = borsh_label(b"DkgConfirmation");
            order.extend(&attempt.to_le_bytes());
            (order, 1)
          }
          Transaction::Sign { id, attempt, round, .. } => {
            let mut order = borsh_label(b"Sign");
            // Independently encode VariantSignId
            match id {
              VariantSignId::Cosign(v) => {
                order.push(0u8);
                order.extend(&v.to_le_bytes());
              }
              VariantSignId::Batch(h) => {
                order.push(1u8);
                order.extend(h);
              }
              VariantSignId::SlashReport => {
                order.push(2u8);
              }
              VariantSignId::Transaction(h) => {
                order.push(3u8);
                order.extend(h);
              }
            }
            order.extend(&attempt.to_le_bytes());
            let nonce = match round {
              SigningProtocolRound::Preprocess => 0,
              SigningProtocolRound::Share => 1,
            };
            (order, nonce)
          }
          Transaction::SlashReport { .. } => (borsh_label(b"SlashReport"), 0),
          other @ (Transaction::Cosign { .. } |
          Transaction::Cosigned { .. } |
          Transaction::SubstrateBlock { .. } |
          Transaction::Batch { .. }) => {
            unreachable!("all_signed_transactions_and_attempts returned non-signed tx: {other:?}")
          }
        };
        orders.insert((expected_order.clone(), expected_nonce));

        match tx.kind() {
          TransactionKind::Signed(order, signed) => {
            assert_eq!(order, expected_order, "Wrong order bytes for {tx:?}");
            assert_eq!(signed.nonce, expected_nonce, "Wrong nonce for {tx:?}");
            assert!(
              signed.signature.verify(signed.signer, tx.sig_hash(genesis)),
              "Signature verification failed for {tx:?}"
            );
          }
          other @ (TransactionKind::Provided(_) | TransactionKind::Unsigned) => {
            panic!("Expected Signed kind, got {other:?} for {tx:?}")
          }
        }
      }
      assert_eq!(orders.len(), 11);
    }

    #[test]
    fn provided_transactions_kind() {
      let mut orders = HashSet::new();
      for tx in all_provided_transactions() {
        let expected_order = match &tx {
          Transaction::Cosign { .. } => "Cosign",
          Transaction::Cosigned { .. } => "Cosigned",
          Transaction::SubstrateBlock { .. } => "SubstrateBlock",
          Transaction::Batch { .. } => "Batch",
          other @ (Transaction::RemoveParticipant { .. } |
          Transaction::DkgParticipation { .. } |
          Transaction::DkgConfirmationPreprocess { .. } |
          Transaction::DkgConfirmationShare { .. } |
          Transaction::Sign { .. } |
          Transaction::SlashReport { .. }) => {
            panic!("all_provided_transactions returned non-provided tx: {other:?}")
          }
        };
        orders.insert(expected_order);

        match tx.kind() {
          TransactionKind::Provided(actual_order) => {
            assert_eq!(actual_order, expected_order, "Wrong order for {tx:?}");
          }
          other @ (TransactionKind::Unsigned | TransactionKind::Signed(..)) => {
            panic!("Expected Provided kind, got {other:?} for {tx:?}")
          }
        }
      }
      assert_eq!(orders.len(), 4);
    }
  }

  mod hash {
    use super::*;

    #[test]
    fn hash_format_and_determinism() {
      let key = random_key(&mut OsRng);
      let genesis = random_bytes(&mut OsRng);

      for tx in all_transactions() {
        assert_eq!(tx.hash(), tx.hash(), "Hash not deterministic for {tx:?}");

        let serialized = ReadWrite::serialize(&tx);

        let (hash_input, is_signed) = match &tx {
          // Signed txs: strip the last 64 bytes (signature R || s)
          Transaction::RemoveParticipant { signed, .. } |
          Transaction::DkgParticipation { signed, .. } |
          Transaction::DkgConfirmationPreprocess { signed, .. } |
          Transaction::DkgConfirmationShare { signed, .. } |
          Transaction::Sign { signed, .. } |
          Transaction::SlashReport { signed, .. } => {
            // Verify the stripped bytes are exactly the signature
            let sig_bytes = signed.signature.serialize();
            assert_eq!(
              &serialized[serialized.len() - 64 ..],
              sig_bytes.as_slice(),
              "last 64 bytes should be signature R || s for {tx:?}"
            );
            (&serialized[.. serialized.len() - 64], true)
          }
          // Provided txs: hash the full serialization
          Transaction::Cosign { .. } |
          Transaction::Cosigned { .. } |
          Transaction::SubstrateBlock { .. } |
          Transaction::Batch { .. } => (&serialized[..], false),
        };

        let expected_hash: [u8; 32] = Blake2b::<U32>::digest(hash_input).into();
        assert_eq!(tx.hash(), expected_hash, "Hash format mismatch for {tx:?}");

        // For signed txs: different signatures should produce the same hash
        if is_signed {
          let mut tx1 = tx.clone();
          let mut tx2 = tx.clone();
          tx1.sign(&mut OsRng, genesis, &key);
          tx2.sign(&mut OsRng, genesis, &key);
          assert_eq!(
            tx1.hash(),
            tx2.hash(),
            "Hashes should be equal despite different nonces and signatures"
          );
          assert_ne!(ReadWrite::serialize(&tx1), ReadWrite::serialize(&tx2));
        }
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
  fn verify() {
    let max = usize::from(KeyShares::MAX_PER_SET);

    for tx in all_transactions() {
      // All default transactions should be valid
      assert_eq!(tx.verify(), Ok(()), "verify() rejected valid tx: {tx:?}");

      // Test boundary conditions per variant
      match &tx {
        // No additional validation beyond structure
        Transaction::RemoveParticipant { .. } |
        Transaction::DkgParticipation { .. } |
        Transaction::DkgConfirmationPreprocess { .. } |
        Transaction::DkgConfirmationShare { .. } |
        Transaction::Cosign { .. } |
        Transaction::Cosigned { .. } |
        Transaction::SubstrateBlock { .. } |
        Transaction::Batch { .. } => {}

        // Sign: data.len() must be <= KeyShares::MAX_PER_SET
        Transaction::Sign { id, attempt, round, signed, .. } => {
          let with_data = |data| Transaction::Sign {
            id: *id,
            attempt: *attempt,
            round: *round,
            data,
            signed: *signed,
          };
          assert_eq!(with_data(Vec::new()).verify(), Ok(()));
          let random_len = usize::try_from(OsRng.next_u32()).unwrap() % max;
          assert_eq!(with_data(vec![vec![]; random_len]).verify(), Ok(()));
          assert_eq!(with_data(vec![vec![]; max]).verify(), Ok(()));
          assert_eq!(
            with_data(vec![vec![]; max + 1]).verify(),
            Err(TransactionError::InvalidContent)
          );
        }

        // SlashReport: slash_points.len() must be <= KeyShares::MAX_PER_SET
        Transaction::SlashReport { signed, .. } => {
          let with_points =
            |points| Transaction::SlashReport { slash_points: points, signed: *signed };
          assert_eq!(with_points(vec![]).verify(), Ok(()));
          let random_len = usize::try_from(OsRng.next_u32()).unwrap() % max;
          assert_eq!(with_points(vec![0; random_len]).verify(), Ok(()));
          assert_eq!(with_points(vec![0; max]).verify(), Ok(()));
          assert_eq!(with_points(vec![0; max + 1]).verify(), Err(TransactionError::InvalidContent));
        }
      }
    }
  }

  #[test]
  fn topic() {
    for tx in all_transactions() {
      let expected = match &tx {
        Transaction::RemoveParticipant { participant, .. } => {
          Some(Topic::RemoveParticipant { participant: *participant })
        }
        Transaction::DkgParticipation { .. } |
        Transaction::Cosign { .. } |
        Transaction::Cosigned { .. } |
        Transaction::SubstrateBlock { .. } |
        Transaction::Batch { .. } => None,
        Transaction::DkgConfirmationPreprocess { attempt, .. } => Some(Topic::DkgConfirmation {
          attempt: *attempt,
          round: SigningProtocolRound::Preprocess,
        }),
        Transaction::DkgConfirmationShare { attempt, .. } => {
          Some(Topic::DkgConfirmation { attempt: *attempt, round: SigningProtocolRound::Share })
        }
        Transaction::Sign { id, attempt, round, .. } => {
          Some(Topic::Sign { id: *id, attempt: *attempt, round: *round })
        }
        Transaction::SlashReport { .. } => Some(Topic::SlashReport),
      };
      assert_eq!(tx.topic(), expected, "Wrong topic for {tx:?}");
    }
  }

  mod sign {
    use super::*;

    #[test]
    fn tx_sign() {
      let key = random_key(&mut OsRng);
      let expected_signer = Ristretto::generator() * key.deref();
      let genesis = random_bytes(&mut OsRng);

      // Sets correct signer and produces verifiable signature
      for mut tx in all_signed_transactions_and_attempts(random_signed(&mut OsRng)) {
        tx.sign(&mut OsRng, genesis, &key);
        let TransactionKind::Signed(order, tributary_signed) = tx.kind() else {
          panic!("non-signed TX from `all_signed_transactions_and_attempts`")
        };
        let sig_hash = tx.sig_hash(genesis);
        assert_eq!(
          sig_hash,
          <Ristretto as WrappedGroup>::F::from_bytes_mod_order_wide(
            &blake2::Blake2b512::digest(
              [
                b"Tributary Signed Transaction",
                genesis.as_slice(),
                &tx.hash(),
                order.as_slice(),
                tributary_signed.signature.R.to_bytes().as_slice(),
              ]
              .concat(),
            )
            .into(),
          )
        );

        assert_eq!(tributary_signed.signer, expected_signer, "Wrong signer for {tx:?}");
        assert_ne!(tributary_signed.signature.R, <Ristretto as WrappedGroup>::G::identity());
        assert!(
          tributary_signed.signature.verify(tributary_signed.signer, sig_hash),
          "Signature verification failed for {tx:?}"
        );
      }

      // Wrong genesis fails verification
      {
        let mut tx = Transaction::RemoveParticipant {
          participant: random_serai_address(&mut OsRng),
          signed: random_signed(&mut OsRng),
        };
        let genesis = random_bytes(&mut OsRng);
        tx.sign(&mut OsRng, genesis, &key);

        let mut wrong_genesis = random_bytes(&mut OsRng);
        // guaranteed to be the wrong genesis
        if wrong_genesis == genesis {
          wrong_genesis[0] ^= 1;
        }
        let wrong_challenge = tx.sig_hash(wrong_genesis);
        if let TransactionKind::Signed(_, tributary_signed) = tx.kind() {
          assert!(
            !tributary_signed.signature.verify(tributary_signed.signer, wrong_challenge),
            "Signature should not verify with wrong genesis"
          );
        }
      }
    }

    #[test]
    #[should_panic(expected = "signing Cosign transaction (provided)")]
    fn panics_on_cosign() {
      let key = random_key(&mut OsRng);
      let mut tx = Transaction::Cosign { substrate_block_hash: random_block_hash(&mut OsRng) };
      tx.sign(&mut OsRng, random_bytes(&mut OsRng), &key);
    }

    #[test]
    #[should_panic(expected = "signing Cosigned transaction (provided)")]
    fn panics_on_cosigned() {
      let key = random_key(&mut OsRng);
      let mut tx = Transaction::Cosigned { substrate_block_hash: random_block_hash(&mut OsRng) };
      tx.sign(&mut OsRng, random_bytes(&mut OsRng), &key);
    }

    #[test]
    #[should_panic(expected = "signing SubstrateBlock transaction (provided)")]
    fn panics_on_substrate_block() {
      let key = random_key(&mut OsRng);
      let mut tx = Transaction::SubstrateBlock { hash: random_block_hash(&mut OsRng) };
      tx.sign(&mut OsRng, random_bytes(&mut OsRng), &key);
    }

    #[test]
    #[should_panic(expected = "signing Batch transaction (provided)")]
    fn panics_on_batch() {
      let key = random_key(&mut OsRng);
      let mut tx = Transaction::Batch { hash: random_block_hash(&mut OsRng).0 };
      tx.sign(&mut OsRng, random_bytes(&mut OsRng), &key);
    }
  }
}
