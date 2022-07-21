# Bitcoin

### Addresses

Bitcoin addresses are an enum, defined as follows:

  - `p2pkh`:  20-byte hash.
  - `p2sh`:   20-byte hash.
  - `p2wpkh`: 20-byte hash.
  - `p2wsh`:  32-byte hash.
  - `p2tr`:   32-byte key.

### In Instructions

Bitcoin In Instructions are present via the transaction's last output in the
form of `OP_RETURN`, and accordingly limited to 80 bytes. `origin` is
automatically set to the transaction's first input's address, if recognized.
If it's not recognized, an address of the multisig's current Bitcoin address is
used, causing any failure to become a donation.

### Out Instructions

Out Instructions ignore `data`.
