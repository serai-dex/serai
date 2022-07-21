# Instructions

Instructions have two forms, In and Out. For a transaction originating on a
connected network, an In Instruction must be provided, which may embed an Out
Instruction. For a transaction originating on Serai, only an Out Instruction is
allowed. Additionally, short hand forms are provided to minimize representations
on connected networks.

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

  - `origin` (Address): Address from the network of origin which sent funds in.
  - `target` (Address): The ink! contract to transfer the incoming funds to.
  - `data`   (Vec<u8>): The data to call the target with.

Networks may automatically provide `origin`. If they do, the instruction may
still provide `origin`, overriding the automatically provided value. If no
`origin` is provided, the instruction is dropped.

Upon receiving funds, the respective Serai Asset contract is called, minting the
appropriate amount of coins, and transferring them to the specified target with
the attached data.

If the transaction fails, funds are scheduled to be returned to `origin`.

### Out Instructions

  - `destination` (Enum { Native(Address), Serai(Address) }): Address to receive
funds to.
  - `data`        (Vec<u8>):                                  The data to call
the target with.

If the network is Serai, this is a transfer. Else, it's a withdrawal to the
specified address with the specified data. Asset contracts perform no validation
on these fields.

### Shorthand

All In Instructions are encoded as Shorthand. Shorthand is an enum which expands
to an In Instruction.

##### Raw

Raw Shorthand encodes a raw In Instruction with no further processing.

##### Swap

  - `origin`  (Option<Address>): In Instruction's `origin`.
  - `coin`    (Coin):            Coin to swap funds for.
  - `minimum` (Amount):          Minimum amount of `coin` to receive.
  - `out`     (Out Instruction): Final destination for funds.

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

For a Bitcoin to Monero swap, Swap Shorthand is expected to generally take:

  - 1 byte to identify as Swap.
  - 1 byte to not override `origin`.
  - 1 byte for `coin`.
  - 4 bytes for `minimum`.
  - 1 byte for `out`'s `destination` field label.
  - 1 byte for `out`'s `destination`'s ordinal byte.
  - 65 bytes for `out`'s `destination`'s address.

Or 74 bytes.

##### Add Liquidity

  - `origin`  (Option<Address>): In Instruction's `origin`.
  - `minimum` (Amount):  Minimum amount of SRI to receive.
  - `gas`     (Amount):  Amount of SRI to send to `address` to cover gas in the
future.
  - `address` (Address): Account to give the created liquidity tokens.

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

For adding liquidity from Bitcoin, Add Liquidity Shorthand is expected to
generally take:

  - 1 byte to identify as Add Liquidity.
  - 1 byte to not override `origin`.
  - 5 bytes for `minimum`.
  - 1/4 bytes for `gas`.
  - 32 bytes for `address`.

Or 40/43 bytes, depending on whether or not the Serai address already has gas.

### Examples

All examples are assumed to be from Bitcoin.

##### Pong Example

```
In Instruction {
  target: Bitcoin Asset Contract,
  data:   Withdraw(Out Instruction { destination: Native(Bitcoin Sender) })
}
```

would cause the created seraiBTC to be transferred to the Bitcoin Asset Contract
and withdrawn to the Bitcoin Sender.

##### Wrap Example

```
In Instruction {
  target: Serai Address
}
```

would cause the created seraiBTC to be transferred to the specified Serai
address for usage on Serai.
