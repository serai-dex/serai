use core::num::NonZero;
use core::{
  pin::pin,
  task::{Poll, Waker, Context},
  future::Future as _,
};

use rand_core::{TryRngCore as _, OsRng};

use super::*;

#[cfg(feature = "alloc")]
#[test]
fn equivocating_prevote() {
  for _ in 0 .. 128 {
    let mut first_block = [0; 32];
    OsRng.try_fill_bytes(&mut first_block).unwrap();
    let first_block = ((OsRng.try_next_u64().unwrap() & 1) == 1).then_some(first_block);

    let mut second_block = [0; 32];
    OsRng.try_fill_bytes(&mut second_block).unwrap();
    let second_block =
      (first_block.is_none() || ((OsRng.try_next_u64().unwrap() & 1) == 1)).then_some(second_block);

    assert_ne!(first_block, second_block);

    let equivocating_data =
      EquivocatingData::<Signature, AggregateSignature, OpaqueBlockHash<'_>>::Prevote {
        first_block: first_block.as_ref().map(|block| OpaqueBlockHash(block.as_slice())),
        second_block: second_block.as_ref().map(|block| OpaqueBlockHash(block.as_slice())),
      };
    let (first_data, second_data) = equivocating_data.split();
    assert!(
      first_data ==
        Data::Prevote {
          block: first_block.as_ref().map(|block| OpaqueBlockHash(block.as_slice()))
        },
      "first `Data` split into was incorrect"
    );
    assert!(
      second_data ==
        Data::Prevote {
          block: second_block.as_ref().map(|block| OpaqueBlockHash(block.as_slice()))
        },
      "second `Data` split into was incorrect"
    );
    assert!(first_data != second_data, "entirely different prevotes were considered equal");

    let mut genesis = [0; 32];
    OsRng.try_fill_bytes(&mut genesis).unwrap();

    let block_number =
      BlockNumber(NonZero::new(OsRng.try_next_u64().unwrap().saturating_add(1)).unwrap());
    let round_number =
      RoundNumber(NonZero::new(OsRng.try_next_u64().unwrap().saturating_add(1)).unwrap());

    let signature_scheme = TestSignatureScheme::new();
    let signer = signature_scheme.signer(0);

    let mut context = Context::from_waker(Waker::noop());
    let Poll::Ready(first_message) =
      pin!(TestMessage::sign(&signer, &genesis, block_number, round_number, first_data))
        .poll(&mut context)
    else {
      panic!("`TestSignatureScheme::sign` returned `Poll::Pending`")
    };
    let first_signature = first_message.signature;
    let Poll::Ready(second_message) =
      pin!(TestMessage::sign(&signer, &genesis, block_number, round_number, second_data))
        .poll(&mut context)
    else {
      panic!("`TestSignatureScheme::sign` returned `Poll::Pending`")
    };
    let second_signature = second_message.signature;

    let one_weight = NonZero::new(1).unwrap();
    let validator_set = alloc::collections::BTreeMap::from([(0, one_weight), (1, one_weight)]);

    {
      let slash_reason = SlashReason {
        block_number,
        round_number,
        evidence: Evidence::Equivocation {
          data: equivocating_data.clone(),
          first_signature,
          second_signature,
        },
      };

      {
        let from_equivocation = SlashReason::equivocation(first_message, second_message).unwrap();
        assert_eq!(slash_reason, from_equivocation);
        /*
          Explicitly compare each signature within this, in case any equalities are semantic and
          ignore the signatures.
        */
        match (&slash_reason.evidence, &from_equivocation.evidence) {
          (
            Evidence::Equivocation {
              data: EquivocatingData::Prevote { first_block: _, second_block: _ },
              first_signature: sr1,
              second_signature: sr2,
            },
            Evidence::Equivocation {
              data: EquivocatingData::Prevote { first_block: _, second_block: _ },
              first_signature: fe1,
              second_signature: fe2,
            },
          ) => {
            assert_eq!(sr1, fe1);
            assert_eq!(sr2, fe2);
          }
          _ => panic!(),
        }
      }

      // Verify this is recognized as a reason to slash this validator
      let () = slash_reason.verify(&genesis, &validator_set, &signature_scheme, 0).unwrap();

      // Check a different genesis causes this to be rejected as an invalid reason
      let InvalidReason =
        slash_reason.verify(&[], &validator_set, &signature_scheme, 0).unwrap_err();

      // Check a different validator causes this to be rejected as an invalid reason
      let InvalidReason =
        slash_reason.verify(&genesis, &validator_set, &signature_scheme, 1).unwrap_err();
    }

    // Check an incorrect signature causes this to be rejected as an invalid reason
    let InvalidReason = (SlashReason {
      block_number,
      round_number,
      evidence: Evidence::Equivocation {
        data: equivocating_data.clone(),
        first_signature: [0xff; _],
        second_signature,
      },
    })
    .verify(&genesis, &validator_set, &signature_scheme, 0)
    .unwrap_err();
    let InvalidReason = (SlashReason {
      block_number,
      round_number,
      evidence: Evidence::Equivocation {
        data: equivocating_data.clone(),
        first_signature,
        second_signature: [0xff; _],
      },
    })
    .verify(&genesis, &validator_set, &signature_scheme, 0)
    .unwrap_err();

    // Check a non-equivocation is rejected as an invalid reason
    let InvalidReason = (SlashReason {
      block_number,
      round_number,
      evidence: Evidence::Equivocation {
        data: EquivocatingData::Prevote { first_block, second_block: first_block },
        first_signature,
        second_signature: first_signature,
      },
    })
    .verify(&genesis, &validator_set, &signature_scheme, 0)
    .unwrap_err();
  }
}
