# Serai Genesis Liquidity Pallet

This pallet corresponds to the
["Genesis" section of the Economics specification](/spec/Economics.md#genesis).
It also implements the conditions on removing liquidity added during genesis.

### Implementation Details

As liquidity tokens represent a share of the value within a liquidity pool,
genesis liquidity tokens are minted and represent a share of the liquidity
tokens moderated by the genesis liquidity module. These genesis liquidity
tokens may be transferred, allowing participants to update their keys as they
see fit.

The removal logic is non-trivial and potentially even more math than the
entirety of the liquidity pools themselves. It does introspect the relation of
liquidity tokens to coins within a liquidity pool, and assumes a quote as the
ratio between coins within a pool, making it tightly bound to the symmetric
liquidity design of Serai's DEX implementation.

### Integration Details

This will call the `set_allocation_per_key_share` method provided by
[`serai-validator-sets-pallet`] when values are oraclized during Serai's
genesis. It will verify the message against a public key the result of
performing a MuSig aggregation for a sufficient threshold of the genesis
validators' auxiliary keys for the Serai network. Each genesis validator will
be considered to have a single key share.

In order to ensure no allocation per key share is insane, a minimum of 0.01% of
the amount distributed to the pools is set. This may cause even a single
validator who allocates for a single key share to meet the requirement for the
network to be considered economically secure.

### Audit Status

This was
[audited by Security Research Labs](/audits/substrate/Security%20Research%20Labs%20April%202026)
as of commit `391f1f050290ae90e31e90a3a524832cfaddaf94`. Any following changes
were not audited unless otherwise stated. Please read the linked report for
more information.
