# Monero

### Addresses

Monero addresses are structs, defined as follows:

  - `kind`:  Enum {
               Standard,
               Subaddress,
               Featured { flags: u8 }
             }
  - `spend`: [u8; 32]
  - `view`:  [u8; 32]

Integrated addresses are not supported due to only being able to send to one
per Monero transaction. Supporting them would add a level of complexity
to Serai which isn't worth it.

This definition of Featured Addresses is non-standard since the flags are
represented by a u8, not a VarInt. Currently, only half of the bits are used,
with no further planned features. Accordingly, it should be fine to fix its
size. If needed, another enum entry for a 2-byte flags Featured Address could be
added.

This definition is also non-standard by not having a Payment ID field. This is
per not supporting integrated addresses.

### In Instructions

Monero In Instructions are present via `tx.extra`, specifically via inclusion
in a `TX_EXTRA_NONCE` tag. The tag is followed by the VarInt length of its
contents, and then additionally marked by a byte `127`. The following data is
limited to 254 bytes.

### Out Instructions

Out Instructions ignore `data`.
