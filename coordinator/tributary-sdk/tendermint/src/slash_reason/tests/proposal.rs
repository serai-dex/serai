use core::num::NonZero;
use core::{
  pin::pin,
  task::{Poll, Waker, Context},
  future::Future as _,
};

use rand_core::{TryRngCore as _, OsRng};

use super::*;

use crate::InvalidAggregateSignature;

#[cfg(feature = "alloc")]
#[test]
fn valid() {
  for _ in 0 .. 128 {
    let one_weight = NonZero::new(1).unwrap();
    let validator_set =
      alloc::collections::BTreeMap::from([(0, NonZero::new(3).unwrap()), (1, one_weight)]);
    let signature_scheme = TestSignatureScheme::new();

    let mut genesis = [0; 32];
    OsRng.try_fill_bytes(&mut genesis).unwrap();

    let block_number =
      BlockNumber(NonZero::new(OsRng.try_next_u64().unwrap().saturating_add(1)).unwrap());
    let round_number = loop {
      let round_number =
        RoundNumber(NonZero::new(OsRng.try_next_u64().unwrap().saturating_add(1)).unwrap());
      if validator_set.proposer(block_number, round_number) != 0 {
        continue;
      }
      break round_number;
    };

    let signer = signature_scheme.signer(0);

    let mut context = Context::from_waker(Waker::noop());

    let mut block = [0; 32];
    OsRng.try_fill_bytes(&mut block).unwrap();
    let block = StubBlock::from(block.as_slice());

    let valid_round = {
      let valid_round_number =
        RoundNumber(NonZero::new(OsRng.try_next_u64().unwrap().saturating_add(1)).unwrap());

      let Poll::Ready(Message { signature: prevote_signature, .. }) = pin!(TestMessage::sign(
        &signer,
        &genesis,
        block_number,
        valid_round_number,
        Data::Prevote { block: Some(block.hash()) }
      ))
      .poll(&mut context) else {
        panic!("`TestSignatureScheme::sign` returned `Poll::Pending`")
      };

      let aggregate_signature = signature_scheme.aggregate(
        TestMessage::signature_message(
          &genesis,
          block_number,
          valid_round_number,
          &Data::Prevote { block: Some(block.hash()) },
        ),
        [(&0, &prevote_signature)],
      );

      Some(ValidRound { round_number: valid_round_number, aggregate_signature })
        .filter(|valid_round| valid_round.round_number < round_number)
    };

    let mut static_verificiation = |valid_round, block| {
      let data = Data::Proposal { valid_round, proposal: block };

      let Poll::Ready(message) =
        pin!(TestMessage::sign(&signer, &genesis, block_number, round_number, data))
          .poll(&mut context)
      else {
        panic!("`TestSignatureScheme::sign` returned `Poll::Pending`")
      };

      (message.signature, message.static_verificiation(&genesis, &validator_set, &signature_scheme))
    };

    let (signature, Ok(())) = static_verificiation(valid_round.clone(), block.clone()) else {
      panic!()
    };

    // Check this is rejected as an invalid reason to slash the validator
    let InvalidReason = (SlashReason {
      block_number,
      round_number,
      evidence: Evidence::InvalidProposal {
        valid_round: valid_round.clone(),
        proposal: block.hash(),
        signature,
      },
    })
    .verify(&genesis, &validator_set, &signature_scheme, 0)
    .unwrap_err();
  }
}

#[cfg(feature = "alloc")]
#[test]
fn not_proposer() {
  for _ in 0 .. 128 {
    let one_weight = NonZero::new(1).unwrap();
    let validator_set =
      alloc::collections::BTreeMap::from([(0, NonZero::new(3).unwrap()), (1, one_weight)]);
    let signature_scheme = TestSignatureScheme::new();

    let mut genesis = [0; 32];
    OsRng.try_fill_bytes(&mut genesis).unwrap();

    let block_number =
      BlockNumber(NonZero::new(OsRng.try_next_u64().unwrap().saturating_add(1)).unwrap());
    let round_number = loop {
      let round_number =
        RoundNumber(NonZero::new(OsRng.try_next_u64().unwrap().saturating_add(1)).unwrap());
      if validator_set.proposer(block_number, round_number) == 0 {
        continue;
      }
      break round_number;
    };

    let signer = signature_scheme.signer(0);

    let mut context = Context::from_waker(Waker::noop());

    let mut block = [0; 32];
    OsRng.try_fill_bytes(&mut block).unwrap();
    let block = StubBlock::from(block.as_slice());

    let valid_round = {
      let valid_round_number =
        RoundNumber(NonZero::new(OsRng.try_next_u64().unwrap().saturating_add(1)).unwrap());

      let Poll::Ready(Message { signature: prevote_signature, .. }) = pin!(TestMessage::sign(
        &signer,
        &genesis,
        block_number,
        valid_round_number,
        Data::Prevote { block: Some(block.hash()) }
      ))
      .poll(&mut context) else {
        panic!("`TestSignatureScheme::sign` returned `Poll::Pending`")
      };

      let aggregate_signature = signature_scheme.aggregate(
        TestMessage::signature_message(
          &genesis,
          block_number,
          valid_round_number,
          &Data::Prevote { block: Some(block.hash()) },
        ),
        [(&0, &prevote_signature)],
      );

      Some(ValidRound { round_number: valid_round_number, aggregate_signature })
        .filter(|valid_round| valid_round.round_number < round_number)
    };

    let mut static_verificiation = |valid_round, block| {
      let data = Data::Proposal { valid_round, proposal: block };

      let Poll::Ready(message) =
        pin!(TestMessage::sign(&signer, &genesis, block_number, round_number, data))
          .poll(&mut context)
      else {
        panic!("`TestSignatureScheme::sign` returned `Poll::Pending`")
      };

      (message.signature, message.static_verificiation(&genesis, &validator_set, &signature_scheme))
    };

    let (signature, Err(MessageError::Invalid(slash_reason))) =
      static_verificiation(valid_round.clone(), block.clone())
    else {
      panic!()
    };

    // Verify this is recognized as a reason to slash this validator
    sanity_slash_reason(&genesis, &validator_set, &signature_scheme, 0, &slash_reason);
    let () = (SlashReason {
      block_number,
      round_number,
      evidence: Evidence::InvalidProposal {
        valid_round: valid_round.clone(),
        proposal: block.hash(),
        signature,
      },
    })
    .verify(&genesis, &validator_set, &signature_scheme, 0)
    .unwrap();

    // Check an incorrect signature causes this to be rejected as an invalid reason
    let InvalidReason = (SlashReason {
      block_number,
      round_number,
      evidence: Evidence::InvalidProposal {
        valid_round: valid_round.clone(),
        proposal: block.hash(),
        signature: {
          let mut signature = signature;
          signature[0] ^= 1;
          signature
        },
      },
    })
    .verify(&genesis, &validator_set, &signature_scheme, 0)
    .unwrap_err();
  }
}

#[cfg(feature = "alloc")]
#[test]
fn invalid_valid_round_number() {
  for _ in 0 .. 128 {
    let one_weight = NonZero::new(1).unwrap();
    let validator_set =
      alloc::collections::BTreeMap::from([(0, NonZero::new(3).unwrap()), (1, one_weight)]);
    let signature_scheme = TestSignatureScheme::new();

    let mut genesis = [0; 32];
    OsRng.try_fill_bytes(&mut genesis).unwrap();

    let block_number =
      BlockNumber(NonZero::new(OsRng.try_next_u64().unwrap().saturating_add(1)).unwrap());
    let round_number = loop {
      let round_number =
        RoundNumber(NonZero::new(OsRng.try_next_u64().unwrap().saturating_add(1)).unwrap());
      if validator_set.proposer(block_number, round_number) != 0 {
        continue;
      }
      break round_number;
    };

    let signer = signature_scheme.signer(0);

    let mut context = Context::from_waker(Waker::noop());

    let mut block = [0; 32];
    OsRng.try_fill_bytes(&mut block).unwrap();
    let block = StubBlock::from(block.as_slice());

    let valid_round = {
      let valid_round_number =
        RoundNumber(NonZero::new(OsRng.try_next_u64().unwrap().saturating_add(1)).unwrap());
      // Ensure this round number is greater than the current round, or at least equal
      let valid_round_number = valid_round_number.max(round_number);

      let Poll::Ready(Message { signature: prevote_signature, .. }) = pin!(TestMessage::sign(
        &signer,
        &genesis,
        block_number,
        valid_round_number,
        Data::Prevote { block: Some(block.hash()) }
      ))
      .poll(&mut context) else {
        panic!("`TestSignatureScheme::sign` returned `Poll::Pending`")
      };

      let aggregate_signature = signature_scheme.aggregate(
        TestMessage::signature_message(
          &genesis,
          block_number,
          valid_round_number,
          &Data::Prevote { block: Some(block.hash()) },
        ),
        [(&0, &prevote_signature)],
      );

      Some(ValidRound { round_number: valid_round_number, aggregate_signature })
    };

    let mut static_verificiation = |valid_round, block| {
      let data = Data::Proposal { valid_round, proposal: block };

      let Poll::Ready(message) =
        pin!(TestMessage::sign(&signer, &genesis, block_number, round_number, data))
          .poll(&mut context)
      else {
        panic!("`TestSignatureScheme::sign` returned `Poll::Pending`")
      };

      (message.signature, message.static_verificiation(&genesis, &validator_set, &signature_scheme))
    };

    let (signature, Err(MessageError::Invalid(slash_reason))) =
      static_verificiation(valid_round.clone(), block.clone())
    else {
      panic!()
    };

    // Verify this is recognized as a reason to slash this validator
    sanity_slash_reason(&genesis, &validator_set, &signature_scheme, 0, &slash_reason);
    let () = (SlashReason {
      block_number,
      round_number,
      evidence: Evidence::InvalidProposal {
        valid_round: valid_round.clone(),
        proposal: block.hash(),
        signature,
      },
    })
    .verify(&genesis, &validator_set, &signature_scheme, 0)
    .unwrap();

    // Check an incorrect signature causes this to be rejected as an invalid reason
    let InvalidReason = (SlashReason {
      block_number,
      round_number,
      evidence: Evidence::InvalidProposal {
        valid_round: valid_round.clone(),
        proposal: block.hash(),
        signature: {
          let mut signature = signature;
          signature[0] ^= 1;
          signature
        },
      },
    })
    .verify(&genesis, &validator_set, &signature_scheme, 0)
    .unwrap_err();
  }
}

#[cfg(feature = "alloc")]
#[test]
fn invalid_valid_round_signature() {
  for _ in 0 .. 128 {
    let one_weight = NonZero::new(1).unwrap();
    let validator_set =
      alloc::collections::BTreeMap::from([(0, NonZero::new(3).unwrap()), (1, one_weight)]);
    let signature_scheme = TestSignatureScheme::new();

    let mut genesis = [0; 32];
    OsRng.try_fill_bytes(&mut genesis).unwrap();

    let block_number =
      BlockNumber(NonZero::new(OsRng.try_next_u64().unwrap().saturating_add(1)).unwrap());
    let round_number = loop {
      let round_number =
        RoundNumber(NonZero::new(OsRng.try_next_u64().unwrap().saturating_add(1)).unwrap());
      if validator_set.proposer(block_number, round_number) != 0 {
        continue;
      }
      break round_number;
    };

    let signer = signature_scheme.signer(0);

    let mut context = Context::from_waker(Waker::noop());

    let mut block = [0; 32];
    OsRng.try_fill_bytes(&mut block).unwrap();
    let block = StubBlock::from(block.as_slice());

    let valid_round = {
      let valid_round_number = loop {
        let candidate =
          RoundNumber(NonZero::new(OsRng.try_next_u64().unwrap().saturating_add(1)).unwrap());
        if candidate < round_number {
          break candidate;
        }
      };

      let Poll::Ready(Message { signature: prevote_signature, .. }) = pin!(TestMessage::sign(
        &signer,
        &genesis,
        block_number,
        valid_round_number,
        Data::Prevote { block: Some(block.hash()) }
      ))
      .poll(&mut context) else {
        panic!("`TestSignatureScheme::sign` returned `Poll::Pending`")
      };

      let mut aggregate_signature = signature_scheme.aggregate(
        TestMessage::signature_message(
          &genesis,
          block_number,
          valid_round_number,
          &Data::Prevote { block: Some(block.hash()) },
        ),
        [(&0, &prevote_signature)],
      );

      // Corrupt this into an invalid signature
      *aggregate_signature.last_mut().unwrap() ^= 1;
      let InvalidAggregateSignature = signature_scheme
        .verify_aggregate(
          TestMessage::signature_message(
            &genesis,
            block_number,
            valid_round_number,
            &Data::Prevote { block: Some(block.hash()) },
          ),
          &aggregate_signature,
        )
        .map(|_iter| ())
        .unwrap_err();

      Some(ValidRound { round_number: valid_round_number, aggregate_signature })
    };

    let mut static_verificiation = |valid_round, block| {
      let data = Data::Proposal { valid_round, proposal: block };

      let Poll::Ready(message) =
        pin!(TestMessage::sign(&signer, &genesis, block_number, round_number, data))
          .poll(&mut context)
      else {
        panic!("`TestSignatureScheme::sign` returned `Poll::Pending`")
      };

      (message.signature, message.static_verificiation(&genesis, &validator_set, &signature_scheme))
    };

    let (signature, Err(MessageError::Invalid(slash_reason))) =
      static_verificiation(valid_round.clone(), block.clone())
    else {
      panic!()
    };

    // Verify this is recognized as a reason to slash this validator
    sanity_slash_reason(&genesis, &validator_set, &signature_scheme, 0, &slash_reason);
    let () = (SlashReason {
      block_number,
      round_number,
      evidence: Evidence::InvalidProposal {
        valid_round: valid_round.clone(),
        proposal: block.hash(),
        signature,
      },
    })
    .verify(&genesis, &validator_set, &signature_scheme, 0)
    .unwrap();

    // Check an incorrect signature causes this to be rejected as an invalid reason
    let InvalidReason = (SlashReason {
      block_number,
      round_number,
      evidence: Evidence::InvalidProposal {
        valid_round: valid_round.clone(),
        proposal: block.hash(),
        signature: {
          let mut signature = signature;
          signature[0] ^= 1;
          signature
        },
      },
    })
    .verify(&genesis, &validator_set, &signature_scheme, 0)
    .unwrap_err();
  }
}

#[cfg(feature = "alloc")]
#[test]
fn invalid_valid_round_weight() {
  for _ in 0 .. 128 {
    let one_weight = NonZero::new(1).unwrap();
    let validator_set =
      alloc::collections::BTreeMap::from([(0, NonZero::new(3).unwrap()), (1, one_weight)]);
    let signature_scheme = TestSignatureScheme::new();

    let mut genesis = [0; 32];
    OsRng.try_fill_bytes(&mut genesis).unwrap();

    let block_number =
      BlockNumber(NonZero::new(OsRng.try_next_u64().unwrap().saturating_add(1)).unwrap());
    let round_number = loop {
      let round_number =
        RoundNumber(NonZero::new(OsRng.try_next_u64().unwrap().saturating_add(1)).unwrap());
      if validator_set.proposer(block_number, round_number) != 0 {
        continue;
      }
      break round_number;
    };

    let signer = signature_scheme.signer(0);

    let mut context = Context::from_waker(Waker::noop());

    let mut block = [0; 32];
    OsRng.try_fill_bytes(&mut block).unwrap();
    let block = StubBlock::from(block.as_slice());

    let valid_round = {
      let valid_round_number = loop {
        let candidate =
          RoundNumber(NonZero::new(OsRng.try_next_u64().unwrap().saturating_add(1)).unwrap());
        if candidate < round_number {
          break candidate;
        }
      };

      let signer = signature_scheme.signer(1);
      let Poll::Ready(Message { signature: prevote_signature, .. }) = pin!(TestMessage::sign(
        &signer,
        &genesis,
        block_number,
        valid_round_number,
        Data::Prevote { block: Some(block.hash()) }
      ))
      .poll(&mut context) else {
        panic!("`TestSignatureScheme::sign` returned `Poll::Pending`")
      };

      let aggregate_signature = signature_scheme.aggregate(
        TestMessage::signature_message(
          &genesis,
          block_number,
          valid_round_number,
          &Data::Prevote { block: Some(block.hash()) },
        ),
        [(&1, &prevote_signature)],
      );

      Some(ValidRound { round_number: valid_round_number, aggregate_signature })
    };

    let mut static_verificiation = |valid_round, block| {
      let data = Data::Proposal { valid_round, proposal: block };

      let Poll::Ready(message) =
        pin!(TestMessage::sign(&signer, &genesis, block_number, round_number, data))
          .poll(&mut context)
      else {
        panic!("`TestSignatureScheme::sign` returned `Poll::Pending`")
      };

      (message.signature, message.static_verificiation(&genesis, &validator_set, &signature_scheme))
    };

    let (signature, Err(MessageError::Invalid(slash_reason))) =
      static_verificiation(valid_round.clone(), block.clone())
    else {
      panic!()
    };

    // Verify this is recognized as a reason to slash this validator
    sanity_slash_reason(&genesis, &validator_set, &signature_scheme, 0, &slash_reason);
    let () = (SlashReason {
      block_number,
      round_number,
      evidence: Evidence::InvalidProposal {
        valid_round: valid_round.clone(),
        proposal: block.hash(),
        signature,
      },
    })
    .verify(&genesis, &validator_set, &signature_scheme, 0)
    .unwrap();

    // Check an incorrect signature causes this to be rejected as an invalid reason
    let InvalidReason = (SlashReason {
      block_number,
      round_number,
      evidence: Evidence::InvalidProposal {
        valid_round: valid_round.clone(),
        proposal: block.hash(),
        signature: {
          let mut signature = signature;
          signature[0] ^= 1;
          signature
        },
      },
    })
    .verify(&genesis, &validator_set, &signature_scheme, 0)
    .unwrap_err();
  }
}
