// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity =0.8.34;

import "IERC20.sol";

import "Schnorr.sol";

import "IRouter.sol";

/*
  The Router directly performs low-level calls in order to have direct control over gas. Since this
  contract is meant to relay an entire batch of outs in a single transaction, the ability to exactly
  meter individual outs is critical.

  We don't check the return values as we don't care if the calls succeeded. We solely care we made
  them. If someone configures an external contract in a way which borks, we explicitly define that
  as their fault and out-of-scope to this contract.

  If an actual invariant within Serai exists, an escape hatch exists to move to a new contract. Any
  improperly handled actions can be re-signed and re-executed at that point in time.

  Historically, the call-stack-depth limit would've made this design untenable. Due to EIP-150, even
  with 1 billion gas transactions, the call-stack-depth limit remains unreachable.

  The `execute` function pays a relayer, as expected for use in the account-abstraction model. Other
  functions also expect relayers, yet do not explicitly pay fees. Those calls are expected to be
  justified via the backpressure of transactions with fees.
*/
// slither-disable-start low-level-calls,unchecked-lowlevel

/// @title Serai Router
/// @author Luke Parker <lukeparker@serai.exchange>
/// @notice Intakes coins for the Serai network and handles relaying batches of transfers out
contract Router is IRouterWithoutCollisions {
  /// @dev The code hash for a non-empty account without code
  bytes32 constant ACCOUNT_WITHOUT_CODE_CODEHASH = keccak256("");

  /// @dev The address in transient storage used for the reentrancy guard
  bytes32 constant REENTRANCY_GUARD_SLOT =
    bytes32(uint256(keccak256("ReentrancyGuard Router")) - 1);

  /**
   * @dev The amount of gas to use when interacting with ERC20s
   *
   *  The ERC20s integrated are presumed to have a constant gas cost, meaning this fixed gas cost
   *  can only be insufficient if:
   *
   *    A) An integrated ERC20 uses more gas than this limit (presumed not to be the case)
   *    B) An integrated ERC20 is upgraded (integrated ERC20s are presumed to not be upgradeable)
   *    C) The ERC20 call has a variable gas cost and the user set a hook on receive which caused
   *       this (in which case, we accept such interactions failing)
   *    D) The user was blacklisted and any transfers to them cause out of gas errors (in which
   *       case, we again accept dropping this)
   *    E) Other extreme edge cases, for which such tokens are assumed to not be integrated
   *    F) Ethereum opcodes are repriced in a sufficiently breaking fashion
   *
   *  This should be in such excess of the gas requirements of integrated tokens we'll survive
   *  repricing, so long as the repricing doesn't revolutionize EVM gas costs as we know it. In such
   *  a case, Serai would have to migrate to a new smart contract using `escapeHatch`. That also
   *  covers all other potential exceptional cases.
   */
  uint256 constant ERC20_GAS = 100_000;

  /**
   * @dev The next nonce used to determine the address of contracts deployed with CREATE. This is
   *  used to predict the addresses of deployed contracts ahead of time.
   */
  /*
    We don't expose a getter for this as it shouldn't be expected to have any specific value at a
    given moment in time. If someone wants to know the address of their deployed contract, they can
    have it emit an event and verify the emitting contract is the expected one.
  */
  uint256 private _smartContractNonce;

  /**
   * @dev The nonce to verify the next signature with, incremented upon an action to prevent
   *  replays/out-of-order execution
   */
  uint256 private _nextNonce;

  /**
   * @dev The next public key for Serai's Ethereum validator set, in the form the Schnorr library
   *  expects
   */
  bytes32 private _nextSeraiKey;

  /**
   * @dev The current public key for Serai's Ethereum validator set, in the form the Schnorr library
   *  expects
   */
  bytes32 private _seraiKey;

  /// @dev The address escaped to
  address private _escapedTo;

  /// @dev Acquire the re-entrancy lock for the lifetime of this transaction
  modifier nonReentrant() {
    bytes32 reentrancyGuardSlot = REENTRANCY_GUARD_SLOT;
    bytes32 priorEntered;
    // slither-disable-next-line assembly
    assembly {
      priorEntered := tload(reentrancyGuardSlot)
      tstore(reentrancyGuardSlot, 1)
    }
    if (priorEntered != bytes32(0)) {
      revert Reentered();
    }

    _;

    // Clear the re-entrancy guard to allow multiple transactions to non-re-entrant functions within
    // a transaction
    // slither-disable-next-line assembly
    assembly {
      tstore(reentrancyGuardSlot, 0)
    }
  }

  /// @dev Set the next Serai key. This does not read from/write to `_nextNonce`
  /// @param nonceUpdatedWith The nonce used to set the next key
  /// @param nextSeraiKeyVar The key to set as next
  function _setNextSeraiKey(uint256 nonceUpdatedWith, bytes32 nextSeraiKeyVar) private {
    // Explicitly disallow 0 so we can always consider 0 as None and non-zero as Some
    if (nextSeraiKeyVar == bytes32(0)) {
      revert InvalidSeraiKey();
    }
    _nextSeraiKey = nextSeraiKeyVar;
    emit NextSeraiKeySet(nonceUpdatedWith, nextSeraiKeyVar);
  }

  /// @notice The constructor for the relayer
  /// @param initialSeraiKey The initial key for Serai's Ethereum validators
  constructor(bytes32 initialSeraiKey) {
    // Nonces are incremented by 1 upon account creation, prior to any code execution, per EIP-161
    // This is incompatible with any networks which don't have their nonces start at 0
    _smartContractNonce = 1;

    // Set the next Serai key
    _setNextSeraiKey(0, initialSeraiKey);
    // Set the current Serai key to None
    _seraiKey = bytes32(0);

    // We just consumed nonce 0 when setting the initial Serai key
    _nextNonce = 1;

    // We haven't escaped to any address yet
    _escapedTo = address(0);
  }

  /**
   * @dev Verify a signature of the calldata, placed immediately after the function selector. The
   *  calldata should be signed with the chain ID taking the place of the signature's challenge, and
   *  the signature's response replaced by the contract's address shifted into the high bits with
   *  the contract's nonce as the low bits.
   */
  /// @param key The key to verify the signature with
  function verifySignature(bytes32 key)
    private
    returns (uint256 nonceUsed, bytes memory message, bytes32 messageHash)
  {
    // If the escape hatch was triggered, reject further signatures
    if (_escapedTo != address(0)) {
      revert EscapeHatchInvoked();
    }

    /*
      If this key isn't set, reject it.

      The Schnorr contract should already reject this public key yet it's best to be explicit.
    */
    if (key == bytes32(0)) {
      revert SeraiKeyWasNone();
    }

    message = msg.data;
    uint256 messageLen = message.length;
    /*
      function selector, signature

      This check means we don't read memory, and as we attempt to clear portions, write past it
      (triggering undefined behavior).
    */
    if (messageLen < 68) {
      revert InvalidSignature();
    }

    // Read _nextNonce into memory as the nonce we'll use
    nonceUsed = _nextNonce;

    // We overwrite the signature response with the Router contract's address concatenated with the
    // nonce. This is safe until the nonce exceeds 2**96, which is infeasible to do on-chain
    uint256 signatureResponseOverwrite = (uint256(uint160(address(this))) << 96) | nonceUsed;

    // Declare memory to copy the signature out to
    bytes32 signatureC;
    bytes32 signatureS;

    uint256 chainID = block.chainid;
    // slither-disable-next-line assembly
    assembly {
      // Read the signature (placed after the function signature)
      signatureC := mload(add(message, 36))
      signatureS := mload(add(message, 68))

      // Overwrite the signature challenge with the chain ID
      mstore(add(message, 36), chainID)
      // Overwrite the signature response with the contract's address, nonce
      mstore(add(message, 68), signatureResponseOverwrite)

      // Calculate the message hash
      messageHash := keccak256(add(message, 32), messageLen)
    }

    // Verify the signature
    if (!Schnorr.verify(key, messageHash, signatureC, signatureS)) {
      revert InvalidSignature();
    }

    // Set the next nonce
    unchecked {
      _nextNonce = nonceUsed + 1;
    }

    /*
      Advance the message past the function selector, enabling decoding the arguments. Ideally, we'd
      also advance past the signature (to simplify decoding arguments and save some memory). This
      would transform message from:

        message (pointer)
               v
               ------------------------------------------------------------
               | 32-byte length | 4-byte selector | Signature | Arguments |
               ------------------------------------------------------------

      to:

                 message (pointer)
                        v
        ----------------------------------------------
        | Junk 68 bytes | 32-byte length | Arguments |
        ----------------------------------------------

      Unfortunately, doing so corrupts the offsets defined within the ABI itself. We settle for a
      transform to:

                message (pointer)
                       v
        ---------------------------------------------------------
        | Junk 4 bytes | 32-byte length | Signature | Arguments |
        ---------------------------------------------------------
    */
    // slither-disable-next-line assembly
    assembly {
      message := add(message, 4)
      mstore(message, sub(messageLen, 4))
    }
  }

  /// @notice Start updating the key representing Serai's Ethereum validators
  /**
   * @dev This does not validate the passed-in key as much as possible. This is accepted as the key
   *  won't actually be rotated to until it provides a signature confirming the update however
   *  (proving signatures can be made by the key in question and verified via our Schnorr
   *  contract).
   *
   *  The hex bytes are to cause a collision with `IRouter.updateSeraiKey`.
   */
  // @param signature The signature by the current key authorizing this update
  // @param nextSeraiKey The key to update to
  function updateSeraiKey5A8542A2() external {
    (uint256 nonceUsed, bytes memory args,) = verifySignature(_seraiKey);
    /*
      We could replace this with a length check (if we don't simply assume the calldata is valid as
      it was properly signed) + mload to save 24 gas but it's not worth the complexity.
    */
    (,, bytes32 nextSeraiKeyVar) = abi.decode(args, (bytes32, bytes32, bytes32));
    _setNextSeraiKey(nonceUsed, nextSeraiKeyVar);
  }

  /// @notice Confirm the next key representing Serai's Ethereum validators, updating to it
  /// @dev The hex bytes are to cause a collision with `IRouter.confirmSeraiKey`.
  // @param signature The signature by the next key confirming its validity
  function confirmNextSeraiKey34AC53AC() external {
    // Checks
    bytes32 nextSeraiKeyVar = _nextSeraiKey;
    (uint256 nonceUsed,,) = verifySignature(nextSeraiKeyVar);
    // Effects
    _nextSeraiKey = bytes32(0);
    _seraiKey = nextSeraiKeyVar;
    emit SeraiKeyUpdated(nonceUsed, nextSeraiKeyVar);
  }

  /// @notice Transfer coins into Serai with an instruction
  /// @param coin The coin to transfer in (address(0) if Ether)
  /// @param amount The amount to transfer in (msg.value if Ether)
  /**
   * @param instruction The encoded `RefundableInInstruction` for Serai to associate with this
   *  transfer in
   */
  // This function doesn't require nonReentrant as re-entrancy isn't an issue with this function
  // slither-disable-next-line reentrancy-events
  function inInstruction(address coin, uint256 amount, bytes memory instruction) external payable {
    // Check there is an active key
    if (_seraiKey == bytes32(0)) {
      revert SeraiKeyWasNone();
    }

    // Don't allow further InInstructions once the escape hatch has been invoked
    if (_escapedTo != address(0)) {
      revert EscapeHatchInvoked();
    }

    // Check the transfer
    if (coin == address(0)) {
      if (amount != msg.value) revert AmountMismatchesMsgValue();
    } else {
      (bool success, bytes memory res) = address(coin)
        .call(
          abi.encodeWithSelector(IERC20.transferFrom.selector, msg.sender, address(this), amount)
        );

      /*
        Require there was nothing returned, which is done by some non-standard tokens, or that the
        ERC20 contract did in fact return true
      */
      bool nonStandardResOrTrue =
        (res.length == 0) || ((res.length == 32) && abi.decode(res, (bool)));
      if (!(success && nonStandardResOrTrue)) revert TransferFromFailed();
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

  /// @dev Perform an Ether/ERC20 transfer out
  /// @param to The address to transfer the coins to
  /// @param coin The coin to transfer (address(0) if Ether)
  /// @param amount The amount of the coin to transfer
  /// @param contractDestination If we're transferring to a contract we just deployed
  /**
   * @return success If the coins were successfully transferred out. For Ethereum, this is if the
   *  call succeeded. For the ERC20, it's if the call succeeded and returned true or nothing.
   */
  // execute has this annotation yet this still flags (even when it doesn't have its own loop)
  // slither-disable-next-line calls-loop
  function transferOut(address to, address coin, uint256 amount, bool contractDestination)
    private
    returns (bool success)
  {
    if (coin == address(0)) {
      // This uses assembly to prevent return bombs
      // slither-disable-next-line assembly
      assembly {
        success := call(
          // explicit gas
          0,
          to,
          amount,
          // calldata
          0,
          0,
          // return data
          0,
          0
        )
      }
    } else {
      bytes4 selector;
      if (contractDestination) {
        /*
          If this is an out of `DestinationType::Contract`, we only grant an approval, we don't
          perform a transfer. This allows the contract, or our expectation of the contract as far as
          our obligation to it, to be borked and for Serai to potentially adjust accordingly.

          Unfortunately, this isn't a feasible flow for Ether unless we set Ether approvals within
          our contract (for entities to collect later) which is of sufficient complexity to not be
          worth the effort. We also don't have the `CREATE` complexity when transferring Ether to
          contracts we deploy.
        */
        selector = IERC20.approve.selector;
      } else {
        /*
          For non-contracts, we don't place the burden of the transferFrom flow and directly
          transfer.
        */
        selector = IERC20.transfer.selector;
      }

      /*
        `coin` is either signed (from `execute`) or called from `escape` (which can safely be
        arbitrarily called). We accordingly don't need to be worried about return bombs here.
      */
      // slither-disable-next-line return-bomb
      (bool erc20Success, bytes memory res) =
        address(coin).call{ gas: ERC20_GAS }(abi.encodeWithSelector(selector, to, amount));

      /*
        Require there was nothing returned, which is done by some non-standard tokens, or that the
        ERC20 contract did in fact return true.
      */
      // slither-disable-next-line incorrect-equality
      bool nonStandardResOrTrue =
        (res.length == 0) || ((res.length == 32) && abi.decode(res, (bool)));
      success = erc20Success && nonStandardResOrTrue;
    }
  }

  /// @notice The header for an address, when encoded with RLP for the purposes of CREATE
  /// @dev 0x80 + 20, shifted left 30 bytes
  uint256 constant ADDRESS_HEADER = (0x80 + 20) << (30 * 8);

  /// @notice Calculate the next address which will be deployed to by CREATE
  /**
   * @dev While CREATE2 is preferable inside smart contracts, CREATE2 is fundamentally vulnerable to
   *  collisions. Our usage of CREATE forces an incremental nonce infeasible to brute force. While
   *  addresses are still variable to the Router address, the Router address itself is the product
   *  of an incremental nonce (the Deployer's). The Deployer's address is constant (generated via
   *  NUMS methods), finally ensuring the security of this.
   *
   *  This is written to be constant-gas, allowing state-independent gas prediction.
   *
   *  This has undefined behavior when `nonce` is zero (EIP-161 makes this irrelevant).
   */
  /// @param nonce The nonce to use for CREATE
  function createAddress(uint256 nonce) internal view returns (address) {
    unchecked {
      // The amount of bytes needed to represent the nonce
      uint256 bitsNeeded = 0;
      // This only iterates up to 64-bits as this will never exceed 2**64 as a matter of
      // practicality
      for (uint256 bits = 0; bits <= 64; bits += 8) {
        bool valueFits = nonce < (uint256(1) << bits);
        bool notPriorSet = bitsNeeded == 0;
        // If the value fits, and the bits weren't prior set, we should set the bits now
        uint256 shouldSet;
        // slither-disable-next-line assembly
        assembly {
          shouldSet := and(valueFits, notPriorSet)
        }
        // Carry the existing bitsNeeded value, set bits if should set
        bitsNeeded += (shouldSet * bits);
      }
      uint256 bytesNeeded = bitsNeeded / 8;

      // if the nonce is an RLP string or not
      bool nonceIsNotStringBool = nonce <= 0x7f;
      uint256 nonceIsNotString;
      // slither-disable-next-line assembly
      assembly {
        nonceIsNotString := nonceIsNotStringBool
      }
      // slither-disable-next-line incorrect-exp This is meant to be a xor
      uint256 nonceIsString = nonceIsNotString ^ 1;

      // Define the RLP length
      // slither-disable-next-line divide-before-multiply
      uint256 rlpEncodingLen = 23 + (nonceIsString * bytesNeeded);

      // forgefmt: disable-start
      uint256 rlpEncoding =
        // The header, which does not include itself in its length, shifted into the first byte
        ((0xc0 + (rlpEncodingLen - 1)) << 248)
        // The address header, which is constant
        | ADDRESS_HEADER
        // Shift the address from bytes 12 .. 32 to 2 .. 22
        | (uint256(uint160(address(this))) << 80)
        // Shift the nonce (one byte) or the nonce's header from byte 31 to byte 22
        | (((nonceIsNotString * nonce) + (nonceIsString * (0x80 + bytesNeeded))) << 72)
        // Shift past the unnecessary bytes
        | (nonce * nonceIsString) << (72 - bitsNeeded);
      // forgefmt: disable-end

      // Store this to the scratch space
      bytes memory rlp;
      // slither-disable-next-line assembly
      assembly {
        mstore(0, rlpEncodingLen)
        mstore(32, rlpEncoding)
        rlp := 0
      }

      return address(uint160(uint256(keccak256(rlp))));
    }
  }

  /// @notice Execute some arbitrary code within a secure sandbox
  /**
   * @dev This performs sandboxing by deploying this code with `CREATE`. This is an external
   *  function as we can't meter `CREATE`/internal functions. We work around this by calling this
   *  function with `CALL` (which we can meter). This does forward `msg.value` to the newly
   *  deployed contract.
   */
  /// @param code The code to execute
  function executeArbitraryCode(bytes memory code) external payable {
    /*
      execute assumes that from the time it reads `_smartContractNonce` until the time it calls this
      function, no mutations to it will occur. If any mutations could occur, it'd lead to a fault
      where tokens could be sniped by:

      1) An out occurring, transferring tokens to an about-to-be-deployed smart contract
      2) The token contract re-entering the Router to deploy a new smart contract which claims the
         tokens
      3) The Router then deploying the intended smart contract (ignoring whatever result it may
         have)

      This does assume a malicious token, or a token with callbacks which can be set by a malicious
      adversary, yet the way to ensure it's a non-issue is to not allow other entities to mutate
      `_smartContractNonce`.
    */
    if (msg.sender != address(this)) {
      revert CodeNotBySelf();
    }

    // Because we're creating a contract, increment our nonce
    _smartContractNonce += 1;

    uint256 msgValue = msg.value;
    address contractAddress;
    // We need to use assembly here because Solidity doesn't expose CREATE
    // slither-disable-next-line assembly
    assembly {
      contractAddress := create(msgValue, add(code, 0x20), mload(code))
    }
  }

  /// @notice Execute a batch of `OutInstruction`s
  /**
   * @dev All `OutInstruction`s in a batch are only for a single coin to simplify handling of the
   *  fee.
   *
   *  The hex bytes are to cause a function selector collision with `IRouter.execute`.
   *
   *  Re-entrancy is prevented because we emit a bitmask of which `OutInstruction`s succeeded. Doing
   *  that requires executing the `OutInstruction`s, which may re-enter here. While our application
   *  of CEI with `verifySignature` prevents replays, re-entrancy would allow out-of-order
   *  completion for the execution of batches (despite their in-order start of execution) which
   *  isn't a headache worth dealing with.
   *
   * Re-entrancy is also explicitly required due to how `_smartContractNonce` is handled.
   */
  // @param signature The signature by the current key for Serai's Ethereum validators
  // @param coin The coin all of these `OutInstruction`s are for
  // @param fee The fee to pay (in coin) to the caller for their relaying of this batch
  // @param outs The `OutInstruction`s to act on
  // Each individual call is explicitly metered to ensure there isn't a DoS here
  // slither-disable-next-line calls-loop,reentrancy-events
  function execute4DE42904() external nonReentrant {
    (uint256 nonceUsed, bytes memory args, bytes32 message) = verifySignature(_seraiKey);
    (,, address coin, uint256 fee, IRouter.OutInstruction[] memory outs) =
      abi.decode(args, (bytes32, bytes32, address, uint256, IRouter.OutInstruction[]));

    // Define a bitmask to store the results of all following `OutInstruction`s
    bytes memory results = new bytes((outs.length + 7) / 8);

    // slither-disable-next-line reentrancy-events
    for (uint256 i = 0; i < outs.length; i++) {
      bool success = true;

      // If the destination is an address, we perform a direct transfer
      if (outs[i].destinationType == IRouter.DestinationType.Address) {
        /*
          This may cause a revert if the destination isn't actually a valid address. Serai is
          trusted to not pass a malformed destination, yet if it ever did, it could simply re-sign a
          corrected batch using this nonce.
        */
        address destination = abi.decode(outs[i].destination, (address));
        success = transferOut(destination, coin, outs[i].amount, false);
      } else {
        // Prepare the transfer
        uint256 ethValue = 0;
        if (coin == address(0)) {
          // If it's Ether, we transfer the amount with the call
          ethValue = outs[i].amount;
        } else {
          /*
            If it's an ERC20, we calculate the address of the will-be contract and transfer to it
            before deployment. This avoids needing to deploy the contract, then call transfer, then
            call the contract again.

            We use CREATE, not CREATE2, despite the difficulty in calculating the address
            in-contract, for reasons explained within `createAddress`'s documentation.

            If this is ever borked, the fact we only set an approval allows recovery.
          */
          address nextAddress = createAddress(_smartContractNonce);
          success = transferOut(nextAddress, coin, outs[i].amount, true);
        }

        /*
          If success is false, we presume it a fault with an ERC20, not with us, and move on. If we
          reverted here, we'd halt the execution of every single batch (now and future). By simply
          moving on, we may have reached some invariant with this specific ERC20, yet the project
          entire isn't put into a halted state.

          Since the recipient is a fresh account, this presumably isn't the recipient being
          blacklisted (the most likely invariant upon the integration of a popular,
          otherwise-standard ERC20). That means there likely is some invariant with this integration
          to be resolved later. Given our ability to sign new batches with the necessary
          corrections, this is accepted.
        */
        if (success) {
          (IRouter.CodeDestination memory destination) =
            abi.decode(outs[i].destination, (IRouter.CodeDestination));

          /*
            Perform the deployment with the defined gas budget.

            We don't care if the following call fails as we don't want to block/retry if it does.
            Failures are considered the recipient's fault. We explicitly do not want the surface
            area/inefficiency of caching these for later attempted retires.

            We don't have to worry about a return bomb here as this is our own function which
            doesn't return any data.
          */
          (success,) = address(this).call{ gas: destination.gasLimit, value: ethValue }(
            abi.encodeWithSelector(Router.executeArbitraryCode.selector, destination.code)
          );
        }
      }

      if (success) {
        results[i / 8] |= bytes1(uint8(1 << (i % 8)));
      }
    }

    /*
      Emit batch execution with the status of all included events.

      This is an effect after interactions yet we have a reentrancy guard making this safe.
    */
    emit Batch(nonceUsed, message, outs.length, results);

    // Transfer the fee to the relayer
    transferOut(msg.sender, coin, fee, false);
  }

  /// @notice Escapes to a new smart contract
  /**
   * @dev This should be used upon an invariant being reached or new functionality being needed.
   *
   * The hex bytes are to cause a collision with `IRouter.escapeHatch`.
   */
  // @param signature The signature by the current key for Serai's Ethereum validators
  // @param escapeTo The address to escape to
  function escapeHatchDCDD91CC() external {
    // Verify the signature
    (uint256 nonceUsed, bytes memory args,) = verifySignature(_seraiKey);

    (,, address escapeTo) = abi.decode(args, (bytes32, bytes32, address));

    if (escapeTo == address(0)) {
      revert InvalidEscapeAddress();
    }

    /*
      We could define the escape hatch as having its own confirmation flow, as new keys do, but new
      contracts don't face all of the cryptographic concerns faced by new keys. New contracts also
      would presumably be moved to after strict review, making the chance of specifying the wrong
      contract incredibly unlikely.

      The only check performed accordingly (with no confirmation flow) is that the new contract is
      in fact a contract. This is done to confirm the contract was successfully deployed on this
      blockchain.

      This check is also comprehensive to the zero-address case, but this function doesn't have to
      be perfectly optimized and it's better to explicitly handle that due to it being its own
      invariant.
    */
    {
      bytes32 codehash = escapeTo.codehash;
      if ((codehash == bytes32(0)) || (codehash == ACCOUNT_WITHOUT_CODE_CODEHASH)) {
        revert EscapeAddressWasNotAContract();
      }
    }

    /*
      We want to define the escape hatch so coins here now, and latently received, can be forwarded.
      If the last Serai key set could update the escape hatch, they could siphon off latently
      received coins without penalty (if they update the escape hatch after unstaking).
    */
    if (_escapedTo != address(0)) {
      revert EscapeHatchInvoked();
    }

    _escapedTo = escapeTo;
    emit EscapeHatch(nonceUsed, escapeTo);
  }

  /// @notice Escape coins after the escape hatch has been invoked
  /// @param coin The coin to escape
  // slither-disable-next-line reentrancy-events Out-of-order events aren't an issue here
  function escape(address coin) external {
    if (_escapedTo == address(0)) {
      revert EscapeHatchNotInvoked();
    }

    // Fetch the amount to escape
    uint256 amount = address(this).balance;
    if (coin != address(0)) {
      amount = IERC20(coin).balanceOf(address(this));
    }

    // Perform the transfer
    // While this can be re-entered to try escaping our balance twice, the outer call will fail
    /*
      We don't flag the escape hatch as a contract destination, despite being a contract, as the
      escape hatch's invocation is permanent. If the coins do not go through the escape hatch, they
      will never go anywhere (ignoring any unspent approvals voided by this action).
    */
    if (!transferOut(_escapedTo, coin, amount, false)) {
      revert EscapeFailed();
    }

    // Since we successfully escaped this amount, emit the event for it
    emit Escaped(coin, amount);
  }

  /// @notice Fetch the next nonce to use by an action published to this contract
  /// return The next nonce to use by an action published to this contract
  function nextNonce() external view returns (uint256) {
    return _nextNonce;
  }

  /// @notice Fetch the next key for Serai's Ethereum validator set
  /// @return The next key for Serai's Ethereum validator set or bytes32(0) if none is currently set
  function nextSeraiKey() external view returns (bytes32) {
    return _nextSeraiKey;
  }

  /// @notice Fetch the current key for Serai's Ethereum validator set
  /**
   * @return The current key for Serai's Ethereum validator set or bytes32(0) if none is currently
   * set
   */
  function seraiKey() external view returns (bytes32) {
    return _seraiKey;
  }

  /// @notice Fetch the address escaped to
  /// @return The address which was escaped to (address(0) if the escape hatch hasn't been invoked)
  function escapedTo() external view returns (address) {
    return _escapedTo;
  }
}

// slither-disable-end low-level-calls,unchecked-lowlevel
