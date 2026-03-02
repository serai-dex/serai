use alloc::vec;

use scale::{Encode, Decode, DecodeAll as _, DecodeWithMemTracking, MaxEncodedLen};
use sp_core::{
  serde::{Serialize, Deserialize},
  crypto::{Wraps, key_types},
};
use sp_runtime::{
  generic::{DigestItem, Digest},
  traits::Header as HeaderTrait,
};
use sp_consensus_babe::{
  AuthorityId, AuthoritySignature,
  digests::{CompatibleDigestItem, PreDigest},
  EquivocationProof,
};

use serai_abi::{primitives::network_id::NetworkId, SubstrateHeader as Header};

use super::*;

/*
  `pallet-babe` requires `pallet-session` for `GetCurrentSessionForSubstrate` (from its
  configuration) but not it itself.

  To ensure `pallet_session::Pallet` truly isn't required, our fork of `polkadot-sdk` (as derived
  in the `patch-polkadot-sdk` repository) has been patched to _solely_ be this one `trait`. This
  means if `pallet-babe` ever updated to require something else from `pallet-session`, we'd observe
  the compilation error.
*/
#[doc(hidden)]
pub struct GetCurrentSessionForSubstrate;
impl pallet_session::GetCurrentSessionForSubstrate for GetCurrentSessionForSubstrate {
  fn get() -> u32 {
    serai_validator_sets_pallet::Pallet::<Runtime>::current_session(NetworkId::Serai)
      .map(|session| session.0)
      .unwrap_or(0)
  }
}
impl pallet_session::Config for Runtime {
  type Session = GetCurrentSessionForSubstrate;
}

/// The epoch configuration for BABE.
pub(crate) const BABE_GENESIS_EPOCH_CONFIG: sp_consensus_babe::BabeEpochConfiguration =
  sp_consensus_babe::BabeEpochConfiguration {
    /*
      This value is used within the Polkadot ecosystem, the citation being:
      https://research.web3.foundation/Polkadot/protocols/block-production/Babe#6-practical-results

      The research itself is disorganized, but the resulting comment is for $\delta = 1$ (where
      $\delta$ corresponds to allowed clock drift in _slots_), `c = 0.22` is resistant to clock
      drift corresponding to one slot to achieve probabilistic consensus over a span of years.
      `(1, 4)` serves as the approximation of that.

      Perfect optimality would suggest we should run their linked Python script, extensively
      discuss the parameters, and return an output ourselves. In reality, we defer entirely to
      Polkadot/Parity/the Web3 Foundation as this is fundamentally defining a bound for
      probabilistic consensus in a synchronous environment and Serai intends to reject all notions
      that the world is synchronous. Any efforts of our own to derive an optimal, secure answer
      would solely yield the obvious answer: Do not use BABE.

      As we are incapable of finding parameters for BABE we would be happy with, we defer to the
      parameters its creators are happy with, while planning its replacement:
      https://github.com/serai-dex/serai/issues/333
    */
    c: (1, 4),
    allowed_slots: sp_consensus_babe::AllowedSlots::PrimaryAndSecondaryPlainSlots,
  };

impl pallet_babe::Config for Runtime {
  type EpochDuration = ConstU64<{ SESSION_LENGTH_IN_SLOTS }>;

  #[expect(clippy::as_conversions, clippy::cast_possible_truncation)]
  type ExpectedBlockTime = ConstU64<{ TARGET_BLOCK_TIME.as_millis() as u64 }>;
  type EpochChangeTrigger = pallet_babe::ExternalTrigger;

  type WeightInfo = ();
  type MaxAuthorities = MaxAuthorities;
  type MaxNominators = ConstU32<1>;

  type DisabledValidators = ValidatorSets;

  // These are stubbed as while we do handle equivocations, they are not routed through here.
  type KeyOwnerProof = sp_core::Void;
  type EquivocationReportSystem = ();
}

/// A header as used within a BABE equivocation proof.
///
/// BABE equivocation proofs specify a pair of headers, each of unbounded length due to
/// Substrate's policy of including an unbounded list (the digest) within a header. As we wish
/// to bound the size of an equivocation proof, this is unacceptable to use.
///
/// The following shims a header to only as relevant for a BABE equivocation proof, enabling a
/// constant bound on the size of an equivocation proof.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(crate = "sp_core::serde")]
struct BabeHeader {
  hash: <Header as HeaderTrait>::Hash,
  /*
    Our `struct`, while achieving a constant size (or at least a constant bound on its size), still
    contains the unbounded `Digest` field due to an API limitation. Specifically, we HAVE to return
    `&Digest` later, so we MUST own a `Digest`.

    We use this very carefully to achieve all our desired properties accordingly.
  */
  digest: Digest,
}

impl BabeHeader {
  /// Construct a new `BabeHeader`.
  ///
  /// This will ensure the contained `Digest` has the desired layout as will have its structure
  /// assumed later.
  fn new(
    hash: <Header as HeaderTrait>::Hash,
    pre_digest: PreDigest,
    seal: AuthoritySignature,
  ) -> Self {
    Self {
      hash,
      digest: Digest {
        logs: vec![DigestItem::babe_pre_digest(pre_digest), DigestItem::babe_seal(seal)],
      },
    }
  }
}

// Truncate a full header into a fixed-size header for an `EquivocationProof`.
impl TryFrom<Header> for BabeHeader {
  type Error = ();
  fn try_from(header: Header) -> Result<BabeHeader, ()> {
    let pre_digest =
      header.digest().logs().iter().find_map(CompatibleDigestItem::as_babe_pre_digest).ok_or(())?;
    let seal = header.digest().logs().last().ok_or(())?.as_babe_seal().ok_or(())?;
    Ok(Self::new(header.hash(), pre_digest, seal))
  }
}

impl Encode for BabeHeader {
  fn size_hint(&self) -> usize {
    // This should be of effectively constant length
    Self::max_encoded_len()
  }

  fn encode_to<T: ?Sized + scale::Output>(&self, dest: &mut T) {
    /*
      This produces an encoding equivalent to `(Hash, PreDigest, AuthoritySignature)` on the
      assumption `logs = vec![pre_digest, seal]`, as the case with the `BabeHeader::new` (the sole
      function which directly constructs a `BabeHeader` with `struct`-initialization syntax).

      If `logs` has a different value, this would produce an undefined encoding.
    */
    self.hash.encode_to(dest);
    for digest in &self.digest.logs {
      if let Some(pre_digest) = digest.as_babe_pre_digest() {
        pre_digest.encode_to(dest);
      } else if let Some(seal) = digest.as_babe_seal() {
        seal.encode_to(dest);
      } else {
        unreachable!("`BabeHeader` had non-BABE `DigestItem`")
      }
    }
  }
}
impl MaxEncodedLen for BabeHeader {
  fn max_encoded_len() -> usize {
    <Header as HeaderTrait>::Hash::max_encoded_len() +
      PreDigest::max_encoded_len() +
      <AuthoritySignature as Wraps>::Inner::max_encoded_len()
  }
}

impl Decode for BabeHeader {
  fn decode<I: scale::Input>(input: &mut I) -> Result<Self, scale::Error> {
    let (hash, pre_digest, seal) =
      <(<Header as HeaderTrait>::Hash, PreDigest, AuthoritySignature)>::decode(input)?;

    // Each `DigestItem` contains a heap-allocated encoding of its corresponding item
    input.on_before_alloc_mem(PreDigest::max_encoded_len())?;
    input.on_before_alloc_mem(<AuthoritySignature as Wraps>::Inner::max_encoded_len())?;
    // The allocation for the `Digest` `Vec` containing the `DigestItem`s
    input.on_before_alloc_mem(2 * core::mem::size_of::<DigestItem>())?;

    Ok(BabeHeader::new(hash, pre_digest, seal))
  }
}
impl DecodeWithMemTracking for BabeHeader {}

/*
  We now have to implement a variety of methods within `trait`s for `BabeHeader``, many of which
  are `unimplemented!()`, effecting a runtime panic if ever tried to be called. Ideally, we could
  use of one two tricks to prove these would never be called.

  ---

  We could apply the methodology presented in https://jack.wrenn.fyi/blog/undroppable, defining a
  function which would fail to compile if ever called and attempted to be compiled (due to
  containing a `const { panic!() }` expression), proving it is never called and the function is
  optimized out entirely.

  The exact reference for such `const` blocks can be seen with
  https://doc.rust-lang.org/1.93.1/reference/expressions/block-expr.html#const-blocks, the relevant
  quotes being:
    > If the const block expression is executed at runtime, then the constant is guaranteed to be
      evaluated, even if its return value is ignored
    > If the const block expression is not executed at runtime, it may or may not be evaluated

  Those bounds would ensure the expressions aren't "executed" (reachable) at runtime, though
  whether or not it'd compile _because_ they aren't reachable would be undefined and up to the
  compiler's whims.

  Unfortunately, the compiler's whims do not favor us here and such a solution was not demonstrated
  to work. This is potentially due to `sp_runtime::traits::Header` being `dyn`-compatible...

  Note the above quotes are taken directly from the Rust reference and the Rust reference is
  published with MIT and Apache 2.0 licenses. The MIT license is fulfilled here with the following
  satisfaction of its terms, as applied to the quotes and only to the quotes, not any of the code
  or other associated documentation present in this file.

  """
  Copyright (c) 2010 The Rust Project Developers

  Permission is hereby granted, free of charge, to any
  person obtaining a copy of this software and associated
  documentation files (the "Software"), to deal in the
  Software without restriction, including without
  limitation the rights to use, copy, modify, merge,
  publish, distribute, sublicense, and/or sell copies of
  the Software, and to permit persons to whom the Software
  is furnished to do so, subject to the following
  conditions:

  The above copyright notice and this permission notice
  shall be included in all copies or substantial portions
  of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
  ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
  TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
  PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
  SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
  CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
  IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
  DEALINGS IN THE SOFTWARE.
  """

  ---

  The other trick would be one seen within https://github.com/Kixunil/dont_panic. In general, one
  can call an external function which does not exist and is never linked, causing the linker to
  error _unless_ the calling function is itself optimized out as dead code.

  Unfortunately for us, Rust's links for WASM targets with `--allow-undefined`:
  https://github.com/rust-lang/rust/blob/80381278a08582356c13b0f52af92d27c567c230
    /compiler/rustc_target/src/spec/base/wasm.rs#L40

  So such a solution will not produce an error at compile-time but rather Rust will simply produce
  an invalid (unusable?) WASM blob.

  ---

  With both of those tricks inapplicable, and lacking a third potential trick, we do use runtime
  panics here and are left to extremely carefully monitor the exact usage of `BabeHeader`. To that
  end, it is not marked `pub(_)` and is solely used within this file.
*/

impl HeaderTrait for BabeHeader {
  type Number = <Header as HeaderTrait>::Number;
  type Hash = <Header as HeaderTrait>::Hash;
  type Hashing = <Header as HeaderTrait>::Hashing;

  fn new(
    _number: Self::Number,
    _extrinsics_root: Self::Hash,
    _state_root: Self::Hash,
    _parent_hash: Self::Hash,
    _digest: Digest,
  ) -> Self {
    unimplemented!()
  }

  fn number(&self) -> &Self::Number {
    unimplemented!()
  }
  fn set_number(&mut self, _number: Self::Number) {
    unimplemented!()
  }

  fn extrinsics_root(&self) -> &Self::Hash {
    unimplemented!()
  }
  fn set_extrinsics_root(&mut self, _extrinsics_root: Self::Hash) {
    unimplemented!()
  }

  fn state_root(&self) -> &Self::Hash {
    unimplemented!()
  }
  fn set_state_root(&mut self, _state_root: Self::Hash) {
    unimplemented!()
  }

  fn parent_hash(&self) -> &Self::Hash {
    unimplemented!()
  }

  fn set_parent_hash(&mut self, _parent_hash: Self::Hash) {
    unimplemented!()
  }

  fn digest(&self) -> &Digest {
    &self.digest
  }
  /*
    This function has the ability to disrupt our assumed, and so far enforced, structure for our
    `digest` field. Unfortunately, it is needed by `sp_consensus_babe::check_equivocation_proof`.
  */
  fn digest_mut(&mut self) -> &mut Digest {
    &mut self.digest
  }

  fn hash(&self) -> Self::Hash {
    self.hash
  }
}

pub(crate) fn submit_equivocation(equivocation_proof: EquivocationProof<Header>) -> Option<()> {
  // Repack into an `EquivocationProof<BabeHeader>`
  let equivocation_proof = {
    let EquivocationProof { offender, slot, first_header, second_header } = equivocation_proof;
    let first_header = BabeHeader::try_from(first_header).ok()?;
    let second_header = BabeHeader::try_from(second_header).ok()?;
    EquivocationProof { offender, slot, first_header, second_header }
  };
  let subkey = equivocation_proof.offender.clone().into_inner();

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
        (serai_validator_sets_pallet::subkey(&aux_key, key_types::BABE) == subkey)
          .then_some(validator)
      })
    else {
      completed_iters += 1;
      outer_session = inner_session.0.checked_sub(1).map(Session).filter(|_| completed_iters < 3);
      continue;
    };

    return super::submit_babe_grandpa_equivocation(
      inner_session,
      validator,
      (BABE_EQUIVOCATION, equivocation_proof).encode().try_into().expect(
        "`EquivocationProof<BabeHeader>` is of constant size less than the bound for a reason",
      ),
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
  let Ok(equivocation_proof) = EquivocationProof::<BabeHeader>::decode_all(&mut equivocation_proof)
  else {
    None?
  };

  /*
    This is the one and only consumer of `BabeHeader as sp_runtime::traits::Header` within the
    entire project. This can be easily confirmed as `BabeHeader` is not exported/used beyond this
    file. While the function called here is opqaue, it MUST NOT call any functions which
    `BabeHeader` does not actually implement. A cursory review of `sp-consensus-babe`'s
    implementation does confirm the soundness of this.

    TODO: Patch `sp-consensus-babe` to not accept `H: Header` but `H: PartialHeader` where
    `impl<H: Header> PartialHeader for H`. This would be backwards compatible but ensure the unused
    API functions are in fact unused. This would also allow removing the stubs which panic above
    and the _extensive_ associated commentary.
  */
  let offender = equivocation_proof.offender.clone();
  if !sp_consensus_babe::check_equivocation_proof(equivocation_proof) {
    None?;
  }

  Some(offender)
}
