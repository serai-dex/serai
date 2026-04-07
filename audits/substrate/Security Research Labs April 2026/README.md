# Security Research Labs `substrate` Audit, April 2026

### Scope

This audit was over most of the [`substrate`](/substrate) folder, as
represents the Serai protocol's blockchain node. Various parts were audited at
various times, as they independently became ready for review. To mirror the
manifest from the report, with the list sorted alphabetically, and with the Git
references extended from seven characters to their full length,

| Component                     | Commit                                                                                                                                                     |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `substrate/abi`               | [`786ba87125ca9205e02bf74f29c49d0e28040a08`](https://github.com/serai-dex/serai/tree/786ba87125ca9205e02bf74f29c49d0e28040a08/substrate/abi)               |
| `substrate/coins`             | [`24eefa8bc50a6d17c23a6930bcf34aab1b6163d3`](https://github.com/serai-dex/serai/tree/24eefa8bc50a6d17c23a6930bcf34aab1b6163d3/substrate/coins)             |
| `substrate/core`              | [`786ba87125ca9205e02bf74f29c49d0e28040a08`](https://github.com/serai-dex/serai/tree/786ba87125ca9205e02bf74f29c49d0e28040a08/substrate/core)              |
| `substrate/dex`               | [`30e61adb9b5318cdd2b2cf9c3f8ce6c9afef1cb0`](https://github.com/serai-dex/serai/tree/30e61adb9b5318cdd2b2cf9c3f8ce6c9afef1cb0/substrate/dex)               |
| `substrate/economic-security` | [`391f1f050290ae90e31e90a3a524832cfaddaf94`](https://github.com/serai-dex/serai/tree/391f1f050290ae90e31e90a3a524832cfaddaf94/substrate/economic-security) |
| `substrate/emissions`         | [`85b9d79641d603cb9a94eac8fd667ca26513a59b`](https://github.com/serai-dex/serai/tree/85b9d79641d603cb9a94eac8fd667ca26513a59b/substrate/emissions)         |
| `substrate/genesis-liquidity` | [`391f1f050290ae90e31e90a3a524832cfaddaf94`](https://github.com/serai-dex/serai/tree/391f1f050290ae90e31e90a3a524832cfaddaf94/substrate/genesis-liquidity) |
| `substrate/in-instructions`   | [`e962cf49c8bb61f5779f10ad342cd075457bfd1b`](https://github.com/serai-dex/serai/tree/e962cf49c8bb61f5779f10ad342cd075457bfd1b/substrate/in-instructions)   |
| `substrate/median`            | [`786ba87125ca9205e02bf74f29c49d0e28040a08`](https://github.com/serai-dex/serai/tree/786ba87125ca9205e02bf74f29c49d0e28040a08/substrate/median)            |
| `substrate/node`              | [`cf4276f8219cdde057c31434766c56446a7853e6`](https://github.com/serai-dex/serai/tree/cf4276f8219cdde057c31434766c56446a7853e6/substrate/node)              |
| `substrate/primitives`        | [`786ba87125ca9205e02bf74f29c49d0e28040a08`](https://github.com/serai-dex/serai/tree/786ba87125ca9205e02bf74f29c49d0e28040a08/substrate/primitives)        |
| `substrate/runtime`           | [`e962cf49c8bb61f5779f10ad342cd075457bfd1b`](https://github.com/serai-dex/serai/tree/e962cf49c8bb61f5779f10ad342cd075457bfd1b/substrate/runtime)           |
| `substrate/runtime/build.rs`  | [`3f5d73492f604e4d68b9919c8e4c84f54ffccb9e`](https://github.com/serai-dex/serai/tree/3f5d73492f604e4d68b9919c8e4c84f54ffccb9e/substrate/runtime/build.rs)  |
| `substrate/signals`           | [`24eefa8bc50a6d17c23a6930bcf34aab1b6163d3`](https://github.com/serai-dex/serai/tree/24eefa8bc50a6d17c23a6930bcf34aab1b6163d3/substrate/signals)           |
| `substrate/validator-sets`    | [`c079232cc40db53154e41b70c825295ac11afd4d`](https://github.com/serai-dex/serai/tree/c079232cc40db53154e41b70c825295ac11afd4d/substrate/validator-sets)    |
| `patch-polkadot-sdk`          | [`202d1717d69251b704ce97d177e890ba2b95f6d5`](https://github.com/serai-dex/patch-polkadot-sdk/tree/202d1717d69251b704ce97d177e890ba2b95f6d5)                |

`patch-polkadot-sdk` refers to Serai's
[`patch-polkadot-sdk`](https://github.com/serai-dex/patch-polkadot-sdk)
repository which provides the methodology to derive a fork of the
[`polkadot-sdk`](https://github.com/paritytech/polkadot-sdk) (including
patches, automated tooling, and a script) along with the resulting artifact.
Security Research Labs' engagement regarded the derivations applied, not the
resulting artifact as a whole.

[`substrate/client`](/substrate/client) was NOT in-scope for this engagement,
the sole part of `substrate` (as it existed at the time) to be so excluded.

`substrate/runtime/build.rs` has since been refactored from a single,
monolithic file into what's now the
[`substrate/runtime/build`](/substrate/runtime/build) folder.

No audited scopes were frozen during/after the audit. Changes made to these
scopes, after the cited commits, were not included under any scope or
engagement unless otherwise stated.

The cited commits were part of a branch labeled `next-polkadot-sdk`. That
branch has since been merged and itself removed, so the cited commits may no
longer directly appear in any active branch's history.

### Other Documentation

As stated in the report (section 4.5), findings were published in real time
to [Serai's GitHub issues](https://github.com/serai-dex/serai/issues). All
issues opened by the Security Research Labs team members are as follows:

- https://github.com/serai-dex/serai/issues/727
- https://github.com/serai-dex/serai/issues/729
- https://github.com/serai-dex/serai/issues/731
- https://github.com/serai-dex/serai/issues/733
- https://github.com/serai-dex/serai/issues/734
- https://github.com/serai-dex/serai/issues/741
- https://github.com/serai-dex/serai/issues/742
- https://github.com/serai-dex/serai/issues/744
- https://github.com/serai-dex/serai/issues/745
- https://github.com/serai-dex/serai/issues/746
- https://github.com/serai-dex/serai/issues/747
- https://github.com/serai-dex/serai/issues/753
- https://github.com/serai-dex/serai/issues/757
- https://github.com/serai-dex/serai/issues/758
- https://github.com/serai-dex/serai/issues/759
- https://github.com/serai-dex/serai/issues/760
- https://github.com/serai-dex/serai/issues/761
- https://github.com/serai-dex/serai/issues/763
- https://github.com/serai-dex/serai/issues/771
- https://github.com/serai-dex/serai/issues/772
- https://github.com/serai-dex/serai/issues/773
- https://github.com/serai-dex/serai/issues/774
- https://github.com/serai-dex/serai/issues/775
- https://github.com/serai-dex/serai/issues/776

Additionally, the following relevant issues were opened by kayabaNerve during
the audit and may provide additional context:

- https://github.com/serai-dex/serai/issues/728
- https://github.com/serai-dex/serai/issues/735
- https://github.com/serai-dex/serai/issues/751
- https://github.com/serai-dex/serai/issues/752
- https://github.com/serai-dex/serai/issues/754
- https://github.com/serai-dex/serai/issues/755
- https://github.com/serai-dex/serai/issues/756
- https://github.com/serai-dex/serai/issues/764
