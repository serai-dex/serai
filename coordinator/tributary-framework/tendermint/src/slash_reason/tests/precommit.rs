use core::num::NonZero;
use core::{
  pin::pin,
  task::{Poll, Waker, Context},
  future::Future as _,
};

use rand_core::{TryRngCore as _, OsRng};

use super::*;

use crate::Commit;

#[cfg(feature = "alloc")]
#[test]
fn precommit() {
  for _ in 0 .. 128 {
    let one_weight = NonZero::new(1).unwrap();
    let validator_set = alloc::collections::BTreeMap::from([(0, one_weight), (1, one_weight)]);
    let signature_scheme = TestSignatureScheme::new();

    let mut genesis = [0; 32];
    OsRng.try_fill_bytes(&mut genesis).unwrap();

    let block_number =
      BlockNumber(NonZero::new(OsRng.try_next_u64().unwrap().saturating_add(1)).unwrap());
    let round_number =
      RoundNumber(NonZero::new(OsRng.try_next_u64().unwrap().saturating_add(1)).unwrap());

    let signer = signature_scheme.signer(0);

    let mut context = Context::from_waker(Waker::noop());

    let mut block = [0; 32];
    OsRng.try_fill_bytes(&mut block).unwrap();
    let block = OpaqueBlockHash(block.as_slice());

    let Poll::Ready(precommit_signature) =
      pin!(Commit::<AggregateSignature>::sign::<TestSignatureScheme>(
        &signer,
        &genesis,
        block_number,
        round_number,
        block.as_ref()
      ))
      .poll(&mut context)
    else {
      panic!("`TestSignatureScheme::sign` returned `Poll::Pending`")
    };

    let mut static_verificiation = |block, precommit_signature| {
      let data =
        Data::Precommit { block_and_precommit_signature: Some((block, precommit_signature)) };

      let Poll::Ready(message) =
        pin!(TestMessage::sign(&signer, &genesis, block_number, round_number, data))
          .poll(&mut context)
      else {
        panic!("`TestSignatureScheme::sign` returned `Poll::Pending`")
      };

      (message.signature, message.static_verificiation(&genesis, &validator_set, &signature_scheme))
    };

    let signature = {
      let (signature, static_verificiation) = static_verificiation(block, precommit_signature);
      static_verificiation.unwrap();
      signature
    };

    {
      let mut precommit_signature = precommit_signature;
      precommit_signature[0] ^= 1;
      let (malleated_precommit_signature_signature, Err(MessageError::Invalid(slash_reason))) =
        static_verificiation(block, precommit_signature)
      else {
        panic!()
      };

      // Verify this is recognized as a reason to slash this validator
      sanity_slash_reason(&genesis, &validator_set, &signature_scheme, 0, &slash_reason);
      let () = (SlashReason {
        block_number,
        round_number,
        evidence: Evidence::InvalidPrecommit {
          block,
          precommit_signature,
          signature: malleated_precommit_signature_signature,
        },
      })
      .verify(&genesis, &validator_set, &signature_scheme, 0)
      .unwrap();

      // Check an incorrect signature causes this to be rejected as an invalid reason
      let InvalidReason = (SlashReason {
        block_number,
        round_number,
        evidence: Evidence::InvalidPrecommit {
          block,
          precommit_signature,
          signature: {
            let mut signature = malleated_precommit_signature_signature;
            signature[0] ^= 1;
            signature
          },
        },
      })
      .verify(&genesis, &validator_set, &signature_scheme, 0)
      .unwrap_err();
    }

    // Check a correct signature is rejected as an invalid reason
    let InvalidReason = (SlashReason {
      block_number,
      round_number,
      evidence: Evidence::InvalidPrecommit { block, precommit_signature, signature },
    })
    .verify(&genesis, &validator_set, &signature_scheme, 0)
    .unwrap_err();
  }
}
