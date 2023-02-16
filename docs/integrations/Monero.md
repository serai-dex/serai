# Monero

### Addresses

Monero addresses are structs, defined as follows:

  - `kind`:  Enum {
               Standard,
               Integrated { payment_id: [u8; 8] },
               Subaddress,
               Featured { flags: u8, payment_id: Option<[u8; 8]> }
             }
  - `spend`: [u8; 32]
  - `view`:  [u8; 32]

This definition of Featured Addresses is non-standard given the flags are
intended to be a VarInt, yet as of now, only half of the bits are used, with no
further planned features. Accordingly, it should be fine to fix its length,
which makes it comply with expectations present here. If needed, another enum
entry for a 2-byte flags Featured Address could be added.

### In Instructions

Monero In Instructions are present via `tx.extra`, specifically via inclusion
in a `TX_EXTRA_NONCE` tag, and accordingly limited to 255 bytes.

### Out Instructions

Out Instructions ignore `data`.
