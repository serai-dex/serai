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
have no validation performed unless otherwise noted. If the processor is
instructed to act on invalid data, it will drop the entire instruction.

### Serialization

Instructions are SCALE encoded.

### Application Call

  - `application` (u16):  The application of Serai to call. Currently, only 0,
Serai DEX is valid.
  - `data`        (Data): The data to call the application with.

### In Instruction

InInstruction is an enum of SeraiAddress and ApplicationCall.

The specified target will be minted an appropriate amount of the respective
Serai token. If an Application Call, the encoded call will be executed.

### Refundable In Instruction

  - `origin` (Option\<ExternalAddress>): Address, from the network of origin,
which sent coins in.
  - `instruction` (InInstruction):       The action to perform with the incoming
coins.

Networks may automatically provide `origin`. If they do, the instruction may
still provide `origin`, overriding the automatically provided value.

If the instruction fails, coins are scheduled to be returned to `origin`,
if provided.

### Destination

Destination is an enum of SeraiAddress and ExternalAddress.

### Out Instruction

  - `destination` (Destination):   Address to receive coins to.
  - `data`        (Option\<Data>): The data to call the destination with.

Transfer the coins included with this instruction to the specified address with
the specified data. No validation of external addresses/data is performed
on-chain. If data is specified for a chain not supporting data, it is silently
dropped.

### Shorthand

Shorthand is an enum which expands to an Refundable In Instruction.

##### Raw

Raw Shorthand encodes a raw Refundable In Instruction in a Data, with no further
processing. This is a verbose fallback option for infrequent use cases not
covered by Shorthand.

##### Swap

  - `origin`  (Option\<ExternalAddress>): Refundable In Instruction's `origin`.
  - `coin`    (Coin):                     Coin to swap funds for.
  - `minimum` (Amount):                   Minimum amount of `coin` to receive.
  - `out`     (Out Instruction):          Final destination for funds.

which expands to:

```
RefundableInInstruction {
  origin,
  instruction: ApplicationCall {
    application: DEX,
    data:        swap(Incoming Asset, coin, minimum, out)
  }
}
```

where `swap` is a function which:

  1) Swaps the incoming funds for SRI.
  2) Swaps the SRI for `coin`.
  3) Checks the amount of `coin` received is greater than `minimum`.
  4) Executes `out` with the amount of `coin` received.

##### Add Liquidity

  - `origin`  (Option\<ExternalAddress>): Refundable In Instruction's `origin`.
  - `minimum` (Amount):                   Minimum amount of SRI tokens to swap
half for.
  - `gas`     (Amount):                   Amount of SRI to send to `address` to
cover gas in the future.
  - `address` (Address):                  Account to send the created liquidity
tokens.

which expands to:

```
RefundableInInstruction {
  origin,
  instruction: ApplicationCall {
    application: DEX,
    data:        swap_and_add_liquidity(Incoming Asset, minimum, gas, address)
  }
}
```

where `swap_and_add_liquidity` is a function which:

  1) Swaps half of the incoming funds for SRI.
  2) Checks the amount of SRI received is greater than `minimum`.
  3) Calls `swap_and_add_liquidity` with the amount of SRI received - `gas`, and
a matching amount of the incoming coin.
  4) Transfers any leftover funds to `address`.
