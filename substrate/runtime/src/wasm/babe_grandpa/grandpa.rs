use scale::{Encode as _, DecodeAll as _};
use sp_core::{ConstU32, ConstU64, crypto::key_types};
use sp_runtime::traits::Header as HeaderTrait;

use sp_consensus_grandpa::{AuthorityId, EquivocationProof};

use serai_abi::{
  primitives::{
    network_id::NetworkId,
    validator_sets::{Session, ValidatorSet},
  },
  SubstrateHeader,
};

use super::{GRANDPA_EQUIVOCATION, MaxAuthorities, ValidatorSets, RuntimeEvent, Runtime};

impl pallet_grandpa::Config for Runtime {
  type RuntimeEvent = RuntimeEvent;

  type WeightInfo = ();
  type MaxAuthorities = MaxAuthorities;
  type MaxNominators = ConstU32<1>;

  // These are stubbed as while we do handle equivocations, they are not routed through here.
  type KeyOwnerProof = sp_core::Void;
  /*
    `MaxSetIdSessionEntries` is documented as allowed to be `0` if `pallet-grandpa` is not used to
    handle equivocations. It is not inherently an invalid parameter.
  */
  type MaxSetIdSessionEntries = ConstU64<0>;
  type EquivocationReportSystem = ();
}

pub(crate) type GrandpaEquivocationProof = EquivocationProof<
  <SubstrateHeader as HeaderTrait>::Hash,
  <SubstrateHeader as HeaderTrait>::Number,
>;

pub(crate) fn submit_equivocation(equivocation_proof: GrandpaEquivocationProof) -> Option<()> {
  let subkey = equivocation_proof.offender().clone().into_inner();
  // Find the most recent (non-historical) session we can associate this with
  let mut outer_session = ValidatorSets::current_session(NetworkId::Serai);
  let mut completed_iters = 0;
  while let Some(inner_session) = outer_session {
    let Some(validator) =
      ValidatorSets::selected_validators_with_serai_auxiliary_keys(ValidatorSet {
        network: NetworkId::Serai,
        session: inner_session,
      })
      .find_map(|(validator, aux_key)| {
        (serai_validator_sets_pallet::subkey(&aux_key, key_types::GRANDPA) == subkey)
          .then_some(validator)
      })
    else {
      completed_iters += 1;
      outer_session = inner_session.0.checked_sub(1).map(Session).filter(|_| completed_iters < 3);
      continue;
    };

    return super::submit_babe_grandpa_equivocation(
      validator,
      (GRANDPA_EQUIVOCATION, inner_session, equivocation_proof)
        .encode()
        .try_into()
        .expect("`GrandpaEquivocationProof` is of constant size less than the bound for a reason"),
    );
  }
  None
}

/// Check the (encoded) equivocation proof.
///
/// This expects the encoding to be delimited and will consider the proof invalid if any bytes are
/// present after.
///
/// This will return `None` if the proof was invalid or otherwise `Some(authority_id)` where
/// `authority_id` is the ID of the offending authority.
#[must_use]
pub(super) fn check_equivocation_proof(mut equivocation_proof: &[u8]) -> Option<AuthorityId> {
  let Ok(equivocation_proof) = GrandpaEquivocationProof::decode_all(&mut equivocation_proof) else {
    None?
  };
  let offender = equivocation_proof.offender().clone();
  if !sp_consensus_grandpa::check_equivocation_proof(equivocation_proof) {
    None?;
  }
  Some(offender)
}
