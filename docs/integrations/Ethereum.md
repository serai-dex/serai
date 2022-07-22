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

If `data` is provided, the Ethereum Router will call a contract-calling child
contract in order to sandbox it. The first byte of `data` designates which child
child contract to call. After this byte is read, `data` is solely considered as
`data`, post its first byte. The child contract is sent the funds before this
call is performed.

##### Child Contract 0

This contract is intended to enable connecting with other protocols, and should
be used to convert withdrawn assets to other assets on Ethereum.

  1) Transfers the asset to `destination`.
  2) Calls `destination` with `data`.

##### Child Contract 1

This contract is intended to enable authenticated calls from Serai.

  1) Transfers the asset to `destination`.
  2) Calls `destination` with `data[.. 4], serai_address, data[4 ..]`, where
`serai_address` is the address which triggered this Out Instruction.
