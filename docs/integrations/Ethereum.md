# Ethereum

### Addresses

Ethereum addresses are 20-byte hashes.

### In Instructions

Ethereum In Instructions are present via being appended to the calldata
transferring funds to Serai. `origin` is automatically set to the party from
which funds are being transferred. For an ERC20, this is `from`. For ETH, this
is the caller. `data` is limited to 255 bytes.

### Out Instructions

`data` is limited to 255 bytes.
