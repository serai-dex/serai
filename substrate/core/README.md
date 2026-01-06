# Serai Core Pallet

This pallet serves a similar role as
[`frame-system`](https://docs.rs/frame-system) does within the Substrate
ecosystem. Specifically, `serai-core-pallet` manages the most basic of account
state (nonces), events, the limits on a block's size, and the transaction/block
execution flow.

This pallet still relies on `frame-system` in some regards, notably outsourcing
the actual storage of events and the handling of the
[`Digest`](
  https://docs.rs/sp-runtime/45.0.0/sp_runtime/generic/struct.Digest.html
). This is considered an implementation detail and is intended to be abstracted
over via usage of `serai-core-pallet`.

Additionally, `serai-core-pallet` does not implement
[`ExecuteBlock`](
  https://docs.rs/frame-support/45.0.0/frame_support/traits/trait.ExecuteBlock.html
) and is still intended to be used with
[`frame-executive`](https://docs.rs/frame-executive). `frame-executive` ensures
the
[`SingleBlockMigrations`](
  https://docs.rs/frame-system/45.0.0/frame_system/pallet/trait.Config.html#associatedtype.SingleBlockMigrations
),
[`MultiBlockMigrator`](
  https://docs.rs/frame-system/45.0.0/frame_system/pallet/trait.Config.html#associatedtype.MultiBlockMigrator
),
[`PreInherents`](
  https://docs.rs/frame-system/45.0.0/frame_system/pallet/trait.Config.html#associatedtype.PreInherents
),
[`PostInherents`](
  https://docs.rs/frame-system/45.0.0/frame_system/pallet/trait.Config.html#associatedtype.PostInherents
), and
[`PostTransactions`](
  https://docs.rs/frame-system/45.0.0/frame_system/pallet/trait.Config.html#associatedtype.PostTransactions
) hooks are run as expected. Additionally, `frame-executive` makes use of the
[`ValidateUnsigned`](
  https://docs.rs/sp-runtime/45.0.0/sp_runtime/traits/trait.ValidateUnsigned.html
) trait, passing it as necessary to the also-used
[`Applyable`](
  https://docs.rs/sp-runtime/45.0.0/sp_runtime/traits/trait.Applyable.html
) trait (which Serai's transactions implement and engage with).

Notably, Serai transactions do _NOT_ use the transaction extension framework
nor _any_ of the transaction extensions provided in `frame-system`. While
Serai offers equivalent functionality to
[`CheckGenesis`](
  https://docs.rs/frame-system/45.0.0/frame_system/struct.CheckGenesis.html
) and
[`CheckSpecVersion`](
  https://docs.rs/frame-system/45.0.0/frame_system/struct.CheckSpecVersion.html
) via [`serai_abi::ImplicitContext`], and
[`CheckNonce`](
  https://docs.rs/frame-system/45.0.0/frame_system/struct.CheckNonce.html
) and
[`CheckEra`](
  https://docs.rs/frame-system/45.0.0/frame_system/struct.CheckEra.html
) via [`serai_abi::ExplicitContext`] (which also covers
[`ChargeTransactionPayment`](
  https://docs.rs/pallet-transaction-payment/45.0.0/pallet_transaction_payment/struct.ChargeTransactionPayment.html
)),
[`CheckWeight`](
  https://docs.rs/frame-system/45.0.0/frame_system/struct.CheckWeight.html
) is trickier to discuss. It's configured directly as part of
[`frame_system::pallet::Config`](
  https://docs.rs/frame-system/45.0.0/frame_system/pallet/trait.Config.html
) and is effectively assumed to be part of a Substrate runtime. Serai
_requires_
[`frame_system::pallet::Config::BlockWeights`](
  https://docs.rs/frame-system/45.0.0/frame_system/pallet/trait.Config.html#associatedtype.BlockLength
) and
[`frame_system::pallet::Config::BlockLength`](
  https://docs.rs/frame-system/45.0.0/frame_system/pallet/trait.Config.html#associatedtype.BlockLength
) be set to Serai's core pallet's [`Limits`], ensuring distinct weights (which
would have no actual effect) aren't attempted to be used.

### Events

Events are stored within `frame-system` once being wrapped by [`Event`]. Two
variants are defined:

- [`Event::Transaction`]: Delineates how a transaction's execution has begun,
  allowing determining which transactions produced which events.
- [`Event::Event`]: Wraps a [`serai_abi::Event`].

This defers to `frame-system` while achieving the additional functionality of
considering events as localized to a transaction.

This is an implementation detail, as prior stated. For how these are exposed,
please refer to [`serai-abi`] (specifically,
[`serai_abi::HeaderV1::events_commitment`]) or Serai's RPC.

### Operations During a Block

At the start of each block, a transaction will be executed with a 'hash' of
`u256::from(block.number()).to_be_bytes()`. This wraps the
[`PreInherents`](
  https://docs.rs/frame-support/45.0.0/frame_support/traits/trait.PreInherents.html
) hooks as required since events _MUST_ be emitted within the context of a
transaction (and a `PreInherents` hook may perform an action which emits an
event). While these hashes are not the output of a cryptographic hash
algorithm, to find a collision would require colliding with the extensive
amount of leading zeroes, accordingly still requiring greater than 128 bits of
work (assuming the block number is less than 128 bits) to find a collision with
the output from a secure cryptographic hash algorithm.

To ensure that all `PreInherents` hooks are executed within these wrappers,
`serai-core-pallet` requires `frame-system` be configured to have its
[`PreInherents`](
  https://docs.rs/frame-system/45.0.0/frame_system/pallet/trait.Config.html#associatedtype.PreInherents
) configured to [`()`], instead offering [`Config::PreInherents`] to define
hooks with. Please note this slightly changes the timeline for `PreInherents`
as Serai will execute them from within an
[`on_initialize`](
  https://docs.rs/frame-support/45.0.0/frame_support/traits/trait.Hooks.html#method.on_initialize
) hook. This causes effects such as
[`pallet-babe`](https://docs.rs/pallet-babe) having to be ordered before
`serai-core-pallet`.

[`PostInherents`](
  https://docs.rs/frame-support/45.0.0/frame_support/traits/trait.PostInherents.html
) is not supported and Serai requires `frrame-system` has [its](
  https://docs.rs/frame-system/45.0.0/frame_system/pallet/trait.Config.html#associatedtype.PostInherents
) configured to [`()`].

Similarly,
[`PostTransactions`](
  https://docs.rs/frame-support/45.0.0/frame_support/traits/trait.PostTransactions.html
) is not supported and Serai requires
[`frame-system`'s](
  https://docs.rs/frame-system/45.0.0/frame_system/pallet/trait.Config.html#associatedtype.PostTransactions
) be configured to [`()`]. Pallets generally _SHOULD_ use `PreInherents`
instead (in order to ensure the weight doesn't exceed the block's limit).

There is also the
[`Hooks`](
  https://docs.rs/frame-support/45.0.0/frame_support/traits/trait.Hooks.html
) trait which every pallet implements
([`frame-support`](https://docs.rs/frame-support) providing the default
implementation if hooks aren't explicitly defined), which `frame-executive`
will invoke. Hooks _MUST NOT_ emit a Serai event and _SHOULD NOT_ be used. They
are supported however, primarily as constraining them is infeasible without
replacing `frame-executive`. This is unfortunate as the `Hooks` trait
guarantees execution, not allowing the runtime to forget to specify their
execution, and allows declaring the
[`Weight`](
  https://docs.rs/frame-support/45.0.0/frame_support/weights/struct.Weight.html
) consumed during execution. `PreInherents` does not allow declaring the
`Weight` consumed, effecting a `Weight` of zero, regardless of the amount of
work performed. While Serai's [`Limits`] are extensively documented, this
should be improved in the future as part of
[the discussion on dynamic scaling](
  https://github.com/serai-dex/serai/issues/715
). Until then, a workaround is defining a
[`Hooks::on_initialize`](
  https://docs.rs/frame-support/45.0.0/frame_support/traits/trait.Hooks.html#method.on_initialize
) which solely returns the weight the `PreInherents` hook will incur (ensuring
the weight is considered but delaying execution until wrapped within the
context of the block's transaction).

The following POSIX shell script is suggested to detect inadvertent usage of
the `pallet::hooks` attribute:

```sh
find ./substrate -iname "*.rs" | while read -r file; do
  hooks=$(grep -F "pallet::hooks" "$file" | grep -v -F "serai-core-pallet: allow" | wc -l)
  if [ $hooks -ne 0 ]; then
    echo "\`pallet::hooks\` (without \`serai-core-pallet: allow\`) found in $file"
  fi
done
```

It will search for any instance not annotated with `serai-core-pallet: allow`
(presumably `#[pallet::hooks] // serai-core-pallet: allow`), effecting a poor
man's linter. This is [present in Serai's CI](/.github/workflows/lint.yml).

### `Digest` and `pallet-timestamp`

`serai-core-pallet` expects [`serai_abi::SeraiPreExecutionDigest`] be provided,
and that it's provided as a
[`DigestItem::PreRuntime`](
  https://docs.rs/sp-runtime/45.0.0/sp_runtime/generic/enum.DigestItem.html#variant.PreRuntime
) by the time its [`StartOfBlock`] (a `PreInherents` implementer) is called.
Serai does this to avoid a transaction to set the timestamp, when the timestamp
is defined as a mandatory part of the header.

The timestamp is then set within
[`pallet-timestamp`](https://docs.rs/pallet-timestamp), which defines a hook to
ensure it was set within each block (automatically invoked via
`frame-executive` regardless of configuration, if `pallet-timestamp` is
included in the runtime definition used with `frame-executive`). This ensures
congruence with the Substrate ecosystem and allows the checks defined within
`pallet-timestamp` to be enforced. Note the _user_ is responsible for creating,
and validating, the timestamp within the header. The
[`check_inherent`](
  https://docs.rs/pallet-timestamp/44.0.0/pallet_timestamp/pallet/struct.Pallet.html#method.check_inherent
) function is _NOT_ invoked by `serai-core-pallet`.

`serai-core-pallet` will additionally provide a
[`serai_abi::SeraiExecutionDigest`] at the end of the block, as intended to
populate a header.

### `TransactionContext`

`serai-core-pallet` implements [`serai_abi::TransactionContext`], as necessary
to enable the verification and execution of [`serai_abi::Transaction`], but
also defining the primary interface for `serai-core-pallet`. This is part of
the abstraction over the underlying methodology (such as `pallet-timestamp`).
In order to be able to implement `TransactionContext`,
[`frame_system::pallet::Config::Hash`](
  https://docs.rs/frame-system/latest/frame_system/pallet/trait.Config.html#associatedtype.Hash
) is constrained to
[`H256`](https://docs.rs/sp-core/39.0.0/sp_core/struct.H256.html),
[`frame_system::pallet::Config::Nonce`](
  https://docs.rs/frame-system/latest/frame_system/pallet/trait.Config.html#associatedtype.Nonce
) is constrained to [`u32`],
[`frame_system::pallet::Config::AccountId`](
  https://docs.rs/frame-system/latest/frame_system/pallet/trait.Config.html#associatedtype.AccountId
) is constrained to [`SeraiAddress`], and
[`frame_system::pallet::Config::RuntimeCall`](
  https://docs.rs/frame-system/latest/frame_system/pallet/trait.Config.html#associatedtype.RuntimeCall
) is constrained to be interoperable with [`serai_abi::Call`].

The first two are quite generic, although the choice of [`u32`] is limiting in
that it could, technically feasibly, be reached. Given how unlikely it is to be
reached, and to avoid doubling the size of the encoding of the nonce (without
defining/adopting a variable-length encoding scheme), this is accepted.

The latter two are specific to Serai, but this pallet doesn't have to be
universal/widely usable. This pallet would be acceptable even if completely
tightly-bound to the types present in `serai-abi`. Here, tight-binding is done
as needed and fair for a functional system, without reservation.
