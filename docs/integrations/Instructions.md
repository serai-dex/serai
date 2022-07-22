# Instructions

Instructions are used to communicate with networks connected to Serai, and they
come in two forms:

  - In Instructions are [Application Calls](../Serai.md#application-call),
paired with incoming funds. Encoded in transactions on connected networks,
Serai will parse out instructions when it receives funds, executing the included
calls.

  - Out Instructions detail how to transfer assets, either to a Serai address or
an address native to the asset in question.

A transaction containing an In Instruction and an Out Instruction (to a native
address) will receive funds to Serai and send funds from Serai, without
requiring directly performing any transactions on Serai itself.

All instructions are encoded under [Shorthand](#shorthand). Shorthand provides
frequent use cases to create minimal data representations on connected networks.

Instructions are interpreted according to their non-Serai network. Addresses
have no validation performed, beyond being a valid enum entry (when applicable)
of the correct length, unless otherwise noted. If the processor is instructed to
act on invalid data, or send to itself, it will drop the entire instruction.

### Serialization

  - Numbers are exclusively unsigned and encoded as compact integers under
SCALE. If omitted, `0`.
  - Enums are prefixed by an ordinal byte of their type, followed by their
actual values.
  - Vectors are prefixed by their length. If omitted, `vec![]`.
  - Instruction fields are numbered and sequentially encoded, each prefixed by
an ordinal byte. All other fields are sequentially encoded with no markers.

Certain fields may be omitted depending on the network in question.

### In Instructions

  - `origin` (Address):  Address from the network of origin which sent funds in.
  - `target` (Address):  The ink! contract to transfer the incoming funds to.
  - `data`   (Vec\<u8>): The data to call `target` with.

Networks may automatically provide `origin`. If they do, the instruction may
still provide `origin`, overriding the automatically provided value. If no
`origin` is provided, the instruction is dropped.

Upon receiving funds, the respective Serai Asset contract is called, minting the
appropriate amount of coins, and transferring them to `target`, calling it with
the attached data.

If the transaction fails, funds are scheduled to be returned to `origin`.

### Out Instructions

  - `destination` (Enum { Native(Address), Serai(Address) }): Address to receive
funds to.
  - `data`        (Vec<u8>):                                  The data to call
the target with.

Transfer the funds included with this instruction to the specified address with
the specified data. Asset contracts perform no validation on native
addresses/data.

### Shorthand

Shorthand is an enum which expands to an In Instruction.

##### Raw

Raw Shorthand encodes a raw In Instruction with no further processing. This is
a verbose fallback option for infrequent use cases not covered by Shorthand.

##### Swap

  - `origin`  (Option\<Address>): In Instruction's `origin`.
  - `coin`    (Coin):             Coin to swap funds for.
  - `minimum` (Amount):           Minimum amount of `coin` to receive.
  - `out`     (Out Instruction):  Final destination for funds.

which expands to:

```
In Instruction {
  origin,
  target: Router,
  data:   swap(Incoming Asset, out, minimum)
}
```

where `swap` is a function which:

  1) Swaps the incoming funds for SRI.
  2) Swaps the SRI for `coin`.
  3) Checks the amount of `coin` received is greater than `minimum`.
  4) Executes `out` with the amount of `coin` received.

##### Add Liquidity

  - `origin`  (Option\<Address>): In Instruction's `origin`.
  - `minimum` (Amount):           Minimum amount of SRI to receive.
  - `gas`     (Amount):           Amount of SRI to send to `address` to cover
gas in the future.
  - `address` (Address):          Account to send the created liquidity tokens.

which expands to:

```
In Instruction {
  origin,
  target: Router,
  data:   swap_and_add_liquidity(Incoming Asset, address, minimum, gas)
}
```

where `swap_and_add_liquidity` is a function which:

  1) Swaps half of the incoming funds for SRI.
  2) Checks the amount of SRI received is greater than `minimum`.
  3) Calls `swap_and_add_liquidity` with the amount of SRI received - `gas`, and
a matching amount of the incoming asset.
  4) Transfers any leftover funds to `address`.
