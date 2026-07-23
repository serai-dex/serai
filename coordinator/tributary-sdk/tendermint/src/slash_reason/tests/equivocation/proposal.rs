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
fn equivocating_proposal() {
  for _ in 0 .. 128 {
    let first_valid_round = crate::random_valid_round();
    let second_valid_round = loop {
      let candidate = crate::random_valid_round();
      // Ensure this is semantically distinct
      if candidate.as_ref().map(|candidate| candidate.round_number) ==
        first_valid_round.as_ref().map(|first_valid_round| first_valid_round.round_number)
      {
        continue;
      }
      break candidate;
    };

    let mut first_proposal = [0; 32];
    OsRng.try_fill_bytes(&mut first_proposal).unwrap();

    let mut second_proposal = [0; 32];
    OsRng.try_fill_bytes(&mut second_proposal).unwrap();
    assert_ne!(first_proposal, second_proposal);

    let equivocating_data =
      EquivocatingData::<Signature, AggregateSignature, OpaqueBlockHash<'_>>::Proposal {
        first_valid_round: first_valid_round.clone(),
        first_proposal: OpaqueBlockHash(first_proposal.as_slice()),
        second_valid_round: second_valid_round.clone(),
        second_proposal: OpaqueBlockHash(second_proposal.as_slice()),
      };
    let (first_data, second_data) = equivocating_data.split();
    assert!(
      first_data ==
        Data::Proposal {
          valid_round: first_valid_round.clone(),
          proposal: StubBlock(&first_proposal)
        },
      "first `Data` split into was incorrect"
    );
    assert!(
      second_data ==
        Data::Proposal {
          valid_round: second_valid_round.clone(),
          proposal: StubBlock(&second_proposal)
        },
      "second `Data` split into was incorrect"
    );
    assert!(first_data != second_data, "entirely different proposals were considered equal");

    assert!(
      first_data !=
        Data::Proposal {
          valid_round: first_valid_round.clone(),
          proposal: StubBlock(&second_proposal)
        },
      "proposals with different `proposal`s were considered equal"
    );
    assert!(
      first_data !=
        Data::Proposal {
          valid_round: second_valid_round.clone(),
          proposal: StubBlock(&first_proposal)
        },
      "proposals with different `valid_round`s were considered equal"
    );

    if let Some(first_valid_round) = first_valid_round.clone() {
      assert!(
        first_data ==
          Data::Proposal {
            valid_round: Some(ValidRound {
              round_number: first_valid_round.round_number,
              aggregate_signature: {
                let mut aggregate_signature = first_valid_round.aggregate_signature;
                aggregate_signature[0] ^= 1;
                aggregate_signature
              }
            }),
            proposal: StubBlock(&first_proposal)
          },
        "proposals with the same semantics, but distinct signatures, weren't considered equal"
      );
    }

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
              data:
                EquivocatingData::Proposal {
                  first_valid_round: srvr1,
                  first_proposal: _,
                  second_valid_round: srvr2,
                  second_proposal: _,
                },
              first_signature: sr1,
              second_signature: sr2,
            },
            Evidence::Equivocation {
              data:
                EquivocatingData::Proposal {
                  first_valid_round: fevr1,
                  first_proposal: _,
                  second_valid_round: fevr2,
                  second_proposal: _,
                },
              first_signature: fe1,
              second_signature: fe2,
            },
          ) => {
            assert_eq!(
              srvr1
                .as_ref()
                .map(|ValidRound { round_number: _, aggregate_signature }| aggregate_signature),
              fevr1
                .as_ref()
                .map(|ValidRound { round_number: _, aggregate_signature }| aggregate_signature)
            );
            assert_eq!(
              srvr2
                .as_ref()
                .map(|ValidRound { round_number: _, aggregate_signature }| aggregate_signature),
              fevr2
                .as_ref()
                .map(|ValidRound { round_number: _, aggregate_signature }| aggregate_signature)
            );
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
        data: EquivocatingData::Proposal {
          first_valid_round: first_valid_round.clone(),
          first_proposal,
          second_valid_round: first_valid_round.clone(),
          second_proposal: first_proposal,
        },
        first_signature,
        second_signature: first_signature,
      },
    })
    .verify(&genesis, &validator_set, &signature_scheme, 0)
    .unwrap_err();
  }
}
