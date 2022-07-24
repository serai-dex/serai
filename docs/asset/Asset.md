# Asset

Serai Assets are wrapped tokens representing assets held in the decentralized
custody of Serai's multisigs. They're implemented as ink! contracts following
the
[PSP-22 token standard](https://github.com/w3f/PSPs/blob/master/PSPs/psp-22.md),
with added functions for minting and transferring to addresses native to the
asset in question.

All native transfer functions error if told to transfer 0.

### `mint(account: AcccountId, amount: u64, instruction: Vec<u8>)`

`mint` can only be called from inside an inherent transaction. Accordingly,
they can only be created by block producers and are validated under consensus,
as detailed in [Consensus](../protocol/Consensus.md#consensus).

The arguments are expanded from an
[In Instruction](../integrations/Instructions.md#in-instruction), with `amount`
being the amount received. For coins with more than 8 decimals, any parts
exceeding 8 decimals is dropped as part of normalization.

The new tokens will be transferred to `account` which is then called with
`instruction`.

### `complete_native_transfer(to: Vec<u8>, data: Option<Vec<u8>>)`

`complete_native_transfer` transfers tokens held by the contract itself out of
Serai to `to`, with the `data` specified (if specified, and if it isn't ignored
by the network underlying the asset in question). It's the most minimal form of
a native transfer, intended for transfer and call flows.

### `native_transfer(to: Vec<u8>, amount: u64, data: Option<Vec<u8>>)`

`native_transfer` transfers tokens held by the caller out of Serai to `to`, with
the `data` specified (if...).

### `native_transfer(from: AccountId, to: Vec<u8>, amount: u64,
data: Option<Vec<u8>>)`

`native_transfer` transfers tokens held by `from`, spending the caller's
allowance, out of Serai to `to`, with the `data` specified (if...).
