// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.26;

import "./IERC20.sol";

import "Schnorr.sol";

// _ is used as a prefix for internal functions and smart-contract-scoped variables
contract Router {
  // Nonce is incremented for each command executed, preventing replays
  uint256 private _nonce;

  // The nonce which will be used for the smart contracts we deploy, enabling
  // predicting their addresses
  uint256 private _smartContractNonce;

  // The current public key, defined as per the Schnorr library
  bytes32 private _seraiKey;

  enum DestinationType {
    Address,
    Code
  }

  struct OutInstruction {
    DestinationType destinationType;
    bytes destination;
    address coin;
    uint256 value;
  }

  struct Signature {
    bytes32 c;
    bytes32 s;
  }

  event SeraiKeyUpdated(uint256 indexed nonce, bytes32 indexed key);
  event InInstruction(
    address indexed from, address indexed coin, uint256 amount, bytes instruction
  );
  event Executed(uint256 indexed nonce, bytes32 indexed batch);

  error InvalidSignature();
  error InvalidAmount();
  error FailedTransfer();

  // Update the Serai key at the end of the current function.
  modifier _updateSeraiKeyAtEndOfFn(uint256 nonceUpdatedWith, bytes32 newSeraiKey) {
    // Run the function itself.
    _;

    // Update the key.
    _seraiKey = newSeraiKey;
    emit SeraiKeyUpdated(nonceUpdatedWith, newSeraiKey);
  }

  constructor(bytes32 initialSeraiKey) _updateSeraiKeyAtEndOfFn(0, initialSeraiKey) {
    // We consumed nonce 0 when setting the initial Serai key
    _nonce = 1;
    // Nonces are incremented by 1 upon account creation, prior to any code execution, per EIP-161
    // This is incompatible with any networks which don't have their nonces start at 0
    _smartContractNonce = 1;
  }

  // updateSeraiKey validates the given Schnorr signature against the current public key, and if
  // successful, updates the contract's public key to the one specified.
  function updateSeraiKey(bytes32 newSeraiKey, Signature calldata signature)
    external
    _updateSeraiKeyAtEndOfFn(_nonce, newSeraiKey)
  {
    bytes memory message = abi.encodePacked("updateSeraiKey", block.chainid, _nonce, newSeraiKey);
    _nonce++;

    if (!Schnorr.verify(_seraiKey, message, signature.c, signature.s)) {
      revert InvalidSignature();
    }
  }

  function inInstruction(address coin, uint256 amount, bytes memory instruction) external payable {
    if (coin == address(0)) {
      if (amount != msg.value) {
        revert InvalidAmount();
      }
    } else {
      (bool success, bytes memory res) = address(coin).call(
        abi.encodeWithSelector(IERC20.transferFrom.selector, msg.sender, address(this), amount)
      );

      // Require there was nothing returned, which is done by some non-standard tokens, or that the
      // ERC20 contract did in fact return true
      bool nonStandardResOrTrue = (res.length == 0) || abi.decode(res, (bool));
      if (!(success && nonStandardResOrTrue)) {
        revert FailedTransfer();
      }
    }

    /*
      Due to fee-on-transfer tokens, emitting the amount directly is frowned upon. The amount
      instructed to be transferred may not actually be the amount transferred.

      If we add nonReentrant to every single function which can effect the balance, we can check the
      amount exactly matches. This prevents transfers of less value than expected occurring, at
      least, not without an additional transfer to top up the difference (which isn't routed through
      this contract and accordingly isn't trying to artificially create events from this contract).

      If we don't add nonReentrant, a transfer can be started, and then a new transfer for the
      difference can follow it up (again and again until a rounding error is reached). This contract
      would believe all transfers were done in full, despite each only being done in part (except
      for the last one).

      Given fee-on-transfer tokens aren't intended to be supported, the only token actively planned
      to be supported is Dai and it doesn't have any fee-on-transfer logic, and how fee-on-transfer
      tokens aren't even able to be supported at this time by the larger Serai network, we simply
      classify this entire class of tokens as non-standard implementations which induce undefined
      behavior.

      It is the Serai network's role not to add support for any non-standard implementations.
    */
    emit InInstruction(msg.sender, coin, amount, instruction);
  }

  // Perform a transfer out
  function _transferOut(address to, address coin, uint256 value) private {
    /*
      We on purposely do not check if these calls succeed. A call either succeeded, and there's no
      problem, or the call failed due to:
        A) An insolvency
        B) A malicious receiver
        C) A non-standard token
      A is an invariant, B should be dropped, C is something out of the control of this contract.
      It is again the Serai's network role to not add support for any non-standard tokens,
    */
    if (coin == address(0)) {
      // Enough gas to service the transfer and a minimal amount of logic
      to.call{ value: value, gas: 5_000 }("");
    } else {
      coin.call{ gas: 100_000 }(abi.encodeWithSelector(IERC20.transfer.selector, msg.sender, value));
    }
  }

  /*
    Serai supports arbitrary calls out via deploying smart contracts (with user-specified code),
    letting them execute whatever calls they're coded for. Since we can't meter CREATE, we call
    CREATE from this function which we call not internally, but with CALL (which we can meter).
  */
  function arbitaryCallOut(bytes memory code) external {
    // Because we're creating a contract, increment our nonce
    _smartContractNonce += 1;

    address contractAddress;
    assembly {
      contractAddress := create(0, add(code, 0x20), mload(code))
    }
  }

  // Execute a list of transactions if they were signed by the current key with the current nonce
  function execute(OutInstruction[] calldata transactions, Signature calldata signature) external {
    // Verify the signature
    bytes memory message = abi.encode("execute", block.chainid, _nonce, transactions);
    if (!Schnorr.verify(_seraiKey, message, signature.c, signature.s)) {
      revert InvalidSignature();
    }

    // Since the signature was verified, perform execution
    emit Executed(_nonce, keccak256(message));
    // While this is sufficient to prevent replays, it's still technically possible for instructions
    // from later batches to be executed before these instructions upon re-entrancy
    _nonce++;

    for (uint256 i = 0; i < transactions.length; i++) {
      // If the destination is an address, we perform a direct transfer
      if (transactions[i].destinationType == DestinationType.Address) {
        // This may cause a panic and the contract to become stuck if the destination isn't actually
        // 20 bytes. Serai is trusted to not pass a malformed destination
        (address destination) = abi.decode(transactions[i].destination, (address));
        _transferOut(destination, transactions[i].coin, transactions[i].value);
      } else {
        // The destination is a piece of initcode. We calculate the hash of the will-be contract,
        // transfer to it, and then run the initcode
        address nextAddress =
          address(uint160(uint256(keccak256(abi.encode(address(this), _smartContractNonce)))));

        // Perform the transfer
        _transferOut(nextAddress, transactions[i].coin, transactions[i].value);

        // Perform the calls with a set gas budget
        (uint32 gas, bytes memory code) = abi.decode(transactions[i].destination, (uint32, bytes));
        address(this).call{ gas: gas }(
          abi.encodeWithSelector(Router.arbitaryCallOut.selector, code)
        );
      }
    }
  }

  function nonce() external view returns (uint256) {
    return _nonce;
  }

  function smartContractNonce() external view returns (uint256) {
    return _smartContractNonce;
  }

  function seraiKey() external view returns (bytes32) {
    return _seraiKey;
  }
}
