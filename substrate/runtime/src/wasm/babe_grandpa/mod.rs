use super::*;

mod babe;
pub(super) use babe::{BABE_GENESIS_EPOCH_CONFIG, submit_equivocation as submit_babe_equivocation};
mod grandpa;
#[rustfmt::skip]
pub(super) use grandpa::{GrandpaEquivocationProof, submit_equivocation as submit_grandpa_equivocation};

type MaxAuthorities =
  ConstU32<{ serai_abi::primitives::validator_sets::KeyShares::MAX_PER_SET_U32 }>;

const BABE_EQUIVOCATION: u8 = 0;
const GRANDPA_EQUIVOCATION: u8 = 1;

fn submit_babe_grandpa_equivocation(
  session: Session,
  validator: SeraiAddress,
  reason: sp_core::bounded::BoundedVec<u8, ConstU32<{ u16::MAX as u32 }>>,
) -> Option<()> {
  let slashes = serai_abi::validator_sets::Slashes::Serai { session, validator, reason };
  let transaction: <Block as sp_runtime::traits::Block>::Extrinsic =
    serai_abi::Transaction::Unsigned {
      call: serai_abi::UnsignedCall::try_from(serai_abi::Call::from(
        serai_abi::validator_sets::Call::report_slashes(slashes),
      ))
      .expect("`serai_abi::validator_sets::Call::report_slashes` wasn't unsigned?"),
    };
  sp_io::offchain::submit_transaction(sp_core::Encode::encode(&transaction)).ok()
}

#[must_use]
pub(super) fn verify_serai_slash_reason(
  session: Session,
  validator: SeraiAddress,
  reason: &[u8],
) -> bool {
  let Some(kind) = reason.first() else { return false };
  let reason = &reason[1 ..];
  let (key_type, expected_authority_id) = match *kind {
    kind if kind == BABE_EQUIVOCATION => {
      let Some(authority_id) = babe::check_equivocation_proof(reason) else { return false };
      (sp_core::crypto::key_types::BABE, authority_id.into_inner())
    }
    kind if kind == GRANDPA_EQUIVOCATION => {
      let Some(authority_id) = grandpa::check_equivocation_proof(reason) else {
        return false;
      };
      (sp_core::crypto::key_types::GRANDPA, authority_id.into_inner())
    }
    _ => return false,
  };

  let Some(aux_key) = ValidatorSets::selected_validators_with_serai_auxiliary_keys(ValidatorSet {
    network: NetworkId::Serai,
    session,
  })
  .find_map(|(this_validator, aux_key)| (validator == this_validator).then_some(aux_key)) else {
    return false;
  };
  serai_validator_sets_pallet::subkey(&aux_key, key_type) == expected_authority_id
}
