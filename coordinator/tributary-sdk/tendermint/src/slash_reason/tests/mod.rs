use super::*;
use crate::TestSignatureScheme;

type Validator = u8;
type Signature = <crate::TestSignatureScheme as SignatureScheme>::Signature;
type AggregateSignature = <crate::TestSignatureScheme as SignatureScheme>::AggregateSignature;
type TestMessage<'hash> = Message<Validator, Signature, AggregateSignature, StubBlock<'hash>>;
type TestSlashReason<'hash> = SlashReason<Signature, AggregateSignature, OpaqueBlockHash<'hash>>;

mod equivocation;
mod proposal;
mod precommit;

fn sanity_slash_reason(
  genesis: &[u8],
  validator_set: &(impl ?Sized + ValidatorSet<Validator = Validator>),
  signature_scheme: &TestSignatureScheme,
  validator: Validator,
  slash_reason: &TestSlashReason,
) {
  // Verify this is recognized as a reason to slash this validator
  let () = slash_reason.verify(&genesis, &validator_set, &signature_scheme, validator).unwrap();

  // Check a different genesis causes this to be rejected as an invalid reason
  assert_ne!(genesis, &[]);
  let InvalidReason =
    slash_reason.verify(&[], &validator_set, &signature_scheme, validator).unwrap_err();

  // Check a different validator causes this to be rejected as an invalid reason
  let InvalidReason = slash_reason
    .verify(&genesis, &validator_set, &signature_scheme, validator.wrapping_add(1))
    .unwrap_err();
}
