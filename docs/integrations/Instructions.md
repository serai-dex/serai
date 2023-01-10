# Instructions

Instructions are used to communicate with networks connected to Serai, and they
come in two forms:

  - In Instructions are programmable specifications paired with incoming coins,
encoded into transactions on connected networks. Serai will parse included
instructions when it receives coins, executing the included specs.

  - Out Instructions detail how to transfer coins, either to a Serai address or
an address native to the coin in question.

A transaction containing an In Instruction and an Out Instruction (to a native
address) will receive coins to Serai and send coins from Serai, without
requiring directly performing any transactions on Serai itself.

All instructions are encoded under [Shorthand](#shorthand). Shorthand provides
frequent use cases to create minimal data representations on connected networks.

Instructions are interpreted according to their non-Serai network. Addresses
have no validation performed, beyond being a valid enum entry (when applicable)
of the correct length, unless otherwise noted. If the processor is instructed to
act on invalid data, it will drop the entire instruction.

### Serialization

Instructions are SCALE encoded.

### Application Call

  - `application` (u16): The application of Serai to call. Currently, only 0,
Serai DEX is valid.
  - `data`        (Vec\<u8>): The data to call the application with.

### Target

Target is an enum of Application Call and Address.

### In Instructions (Native)

  - `target` (Target):  The target to transfer the incoming coins to. If an
Application Call, the encoded call will be executed.
  - `origin` (Address): Address from the network of origin which sent
coins in.

Upon receiving coins, the respective Serai token has the appropriate amount
minted. If `target` is an Address, it'll be transferred the tokens.

### In Instructions (External)

  - `target` (Target):           The target to transfer the incoming coins to.
If an application call, the encoded call will be executed.
  - `origin` (Option\<Address>): Address from the network of origin which sent
coins in.

Networks may automatically provide `origin`. If they do, the instruction may
still provide `origin`, overriding the automatically provided value. If no
`origin` is provided, the instruction is dropped.

If the instruction fails, coins are scheduled to be returned to `origin`.

### Out Instructions

  - `destination` (Enum { External(Address), Native(Address) }): Address to
receive coins to.
  - `data`        (Option\<Vec\<u8>>):                           The data to
call the target with.

Transfer the coins included with this instruction to the specified address with
the specified data. No validation of external addresses/data is performed
on-chain.

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
  target: ApplicationCall {
    application: DEX,
    data:        swap(Incoming Asset, coin, out, minimum)
  }
}
```

where `swap` is a function which:

  1) Swaps the incoming funds for SRI.
  2) Swaps the SRI for `coin`.
  3) Checks the amount of `coin` received is greater than `minimum`.
  4) Executes `out` with the amount of `coin` received.

##### Add Liquidity

  - `origin`  (Option\<Address>): In Instruction's `origin`.
  - `minimum` (Amount):           Minimum amount of SRI tokens to swap half for.
  - `gas`     (Amount):           Amount of SRI to send to `address` to cover
gas in the future.
  - `address` (Address):          Account to send the created liquidity tokens.

which expands to:

```
In Instruction {
  origin,
  target: ApplicationCall {
    application: DEX,
    data:        swap_and_add_liquidity(Incoming Asset, address, minimum, gas)
  }
}
```

where `swap_and_add_liquidity` is a function which:

  1) Swaps half of the incoming funds for SRI.
  2) Checks the amount of SRI received is greater than `minimum`.
  3) Calls `swap_and_add_liquidity` with the amount of SRI received - `gas`, and
a matching amount of the incoming coin.
  4) Transfers any leftover funds to `address`.
