# Ethereum

### Addresses

Ethereum addresses are 20-byte hashes, identical to Ethereum proper.

### In Instructions

In Instructions may be created in one of two ways.

1) Have an EOA call `transfer` or `transferFrom` on an ERC20, appending the
   encoded InInstruction directly after the calldata. `origin` defaults to the
   party transferred from.
2) Call `inInstruction` on the Router. `origin` defaults to `msg.sender`.

### Out Instructions

`data` is limited to 512 bytes.

If `data` isn't provided or is malformed, ETH transfers will execute with 5,000
gas and token transfers with 100,000 gas.

If `data` is provided and well-formed, `destination` is ignored and the Ethereum
Router will construct and call a new contract to proxy the contained calls. The
transfer executes to the constructed contract as above, before the constructed
contract is called with the calls inside `data`. The sandboxed execution has a
gas limit of 350,000.
