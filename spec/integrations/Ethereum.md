# Ethereum

### Addresses

Ethereum addresses are 20-byte hashes.

### In Instructions

Ethereum In Instructions are present via being appended to the calldata
transferring funds to Serai. `origin` is automatically set to the party from
which funds are being transferred. For an ERC20, this is `from`. For ETH, this
is the caller.

### Out Instructions

`data` is limited to 512 bytes.

If `data` isn't provided or is malformed, ETH transfers will execute with 5,000
gas and token transfers with 100,000 gas.

If `data` is provided and well-formed, `destination` is ignored and the Ethereum
Router will construct and call a new contract to proxy the contained calls. The
transfer executes to the constructed contract as above, before the constructed
contract is called with the calls inside `data`. The sandboxed execution has a
gas limit of 350,000.
