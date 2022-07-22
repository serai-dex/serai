# Scenarios

### Pong

Pong has Serai receive funds, just to return them. It's a demonstration of the
in/out flow.

```
Shorthand::Raw(
  In Instruction {
    target: Incoming Asset Contract,
    data:   native_transfer(Incoming Asset Sender)
  }
)
```

### Wrap

Wrap wraps an asset from a connected chain into a Serai Asset, making it usable
with applications on Serai, such as Serai DEX.

```
Shorthand::Raw(
  In Instruction {
    target: Serai Address
  }
)
```

### Swap SRI to Bitcoin

For a SRI to Bitcoin swap, a SRI holder would perform an
[Application Call](../Serai.md#application-calls) to Serai DEX, purchasing
seraiBTC. Once they have seraiBTC, they are able to call `native_transfer`,
transferring the BTC underlying the seraiBTC to a specified Bitcoin address.

### Swap Bitcoin to Monero

For a Bitcoin to Monero swap, the following Shorthand would be used.

```
Shorthand::Swap {
  coin:    Monero,
  minimum: Minimum Monero from Swap,
  out:     Monero Address
}
```

 This Shorthand is expected to generally take:

  - 1 byte to identify as Swap.
  - 1 byte to not override `origin`.
  - 1 byte for `coin`.
  - 4 bytes for `minimum`.
  - 1 byte for `out`'s `destination`'s ordinal byte.
  - 65 bytes for `out`'s `destination`'s address.
  - 1 byte to not include `data` in `out`.

Or 74 bytes.

### Add Liquidity (Fresh)

For a user who has never used Serai before, they have three requirements to add
liquidity:

  - Minting the Serai asset they wish to add liquidity for
  - Acquiring Serai, as liquidity is symmetric
  - Acquiring Serai for gas fees

The Add Liquidity Shorthand enables all three of these actions, and actually
adding the liquidity, in just one transaction from a connected network.

```
Shorthand::AddLiquidity {
  minimum: Minimum SRI from Swap,
  gas:     Amount of SRI to keep for gas
  address: Serai address for the liquidity tokens and gas
}
```

For adding liquidity from Bitcoin, this Shorthand is expected to generally take:

  - 1 byte to identify as Add Liquidity.
  - 1 byte to not override `origin`.
  - 5 bytes for `minimum`.
  - 4 bytes for `gas`.
  - 32 bytes for `address`.

Or 43 bytes.

### Add Liquidity (SRI Holder)

For a user who already has SRI, they solely need to have the asset they wish to
add liquidity for via their SRI. They can either purchase it from Serai DEX, or
wrap it as detailed above.

Once they have both their SRI and the asset they wish to provide liquidity for,
they would use a Serai transaction to call the DEX, adding the liquidity.
