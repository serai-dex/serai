# Monero

### Addresses

Monero addresses are an enum, defined as follows:

  - `standard`:   32-byte key, 32-byte key.
  - `subaddress`: 32-byte key, 32-byte key.
  - `featured`:   1-byte flags, 32-byte key, 32-byte key.

This definition of Featured Addresses is non-standard given the flags are
intended to be a VarInt, yet as of now, only half of the bits are used, with no
further planned features. Accordingly, it should be fine to fix its length,
which makes it comply with expectations present here. If needed, another enum
entry for a 2-byte flags Featured Address could be added.

### In Instructions

Monero In Instructions are present via `tx.extra`, specifically via inclusion
in a `TX_EXTRA_TAG_PADDING` tag, and accordingly limited to 255 bytes.

### Out Instructions

Out Instructions ignore `data`.
