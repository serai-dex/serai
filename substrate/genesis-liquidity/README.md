# Serai Genesis Liquidity Pallet

This pallet corresponds to the
["Genesis" section of the Economics specification](/spec/Economics.md#genesis).

### Integration Details

This will call the `set_allocation_per_key_share` method provided by
[`serai-validator-sets-pallet`] when values are oraclized during Serai's
genesis. It will verify the message against a public key the result of
performing MuSig aggregation against the Serai validator set's auxiliary keys
for the Serai network. It assumes the current Serai validator set _is_ the
genesis validators to fulfill the expectation the genesis validators are the
ones who oraclize the values, an invariant immediate to hold _if_ no one else
sets the allocation per key shares (enabling selecting non-genesis validators
who allocated stake as validators) first.

In order to ensure no allocation per key share is insane, a minimum of 0.01% of
the amount distributed to the pools is set. This may cause even a single
validator who allocates for a single key share to meet the requirement for the
network to be considered economically secure.
