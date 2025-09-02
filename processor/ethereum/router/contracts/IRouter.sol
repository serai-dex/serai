// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title Serai Router (without functions overriden by selector collisions)
/// @author Luke Parker <lukeparker@serai.exchange>
/// @notice Intakes coins for the Serai network and handles relaying batches of transfers out
interface IRouterWithoutCollisions {
  /// @notice Emitted when the next key for Serai's Ethereum validators is set
  /// @param nonce The nonce consumed to update this key
  /// @param key The key updated to
  event NextSeraiKeySet(uint256 indexed nonce, bytes32 indexed key);

  /// @notice Emitted when the key for Serai's Ethereum validators is updated
  /// @param nonce The nonce consumed to update this key
  /// @param key The key updated to
  event SeraiKeyUpdated(uint256 indexed nonce, bytes32 indexed key);

  /// @notice Emitted when an InInstruction occurs
  /// @param from The address which called `inInstruction` and caused this event to be emitted
  /// @param coin The coin transferred in
  /// @param amount The amount of the coin transferred in
  /// @param instruction The encoded `RefundableInInstruction` for Serai to decode and handle
  event InInstruction(
    address indexed from, address indexed coin, uint256 amount, bytes instruction
  );

  /// @notice Emitted when a batch of `OutInstruction`s occurs
  /// @param nonce The nonce consumed to execute this batch of transactions
  /// @param messageHash The hash of the message signed for the executed batch
  /// @param resultsLength The length of the results bitvec (represented as bytes)
  /**
   * @param results The result of each `OutInstruction` executed. This is a bitvec with true
   *   representing success and false representing failure. The low bit in the first byte is used
   *   for the first `OutInstruction`, before the next bit, and so on, before the next byte. An
   *   `OutInstruction` is considered as having succeeded if the call transferring ETH doesn't fail,
   *   the ERC20 transfer doesn't fail, and any executed code doesn't revert.
   */
  event Batch(
    uint256 indexed nonce, bytes32 indexed messageHash, uint256 resultsLength, bytes results
  );

  /// @notice Emitted when `escapeHatch` is invoked
  /// @param escapeTo The address to escape to
  event EscapeHatch(uint256 indexed nonce, address indexed escapeTo);

  /// @notice Emitted when coins escape through the escape hatch
  /// @param coin The coin which escaped
  /// @param amount The amount which escaped
  event Escaped(address indexed coin, uint256 amount);

  /// @notice The Serai key verifying the signature wasn't set
  error SeraiKeyWasNone();
  /// @notice The key for Serai was invalid
  /// @dev This is incomplete and not always guaranteed to be thrown upon an invalid key
  error InvalidSeraiKey();
  /// @notice The contract has had its escape hatch invoked and won't accept further actions
  error EscapeHatchInvoked();
  /// @notice The signature was invalid
  error InvalidSignature();

  /// @notice The amount specified didn't match `msg.value`
  error AmountMismatchesMsgValue();
  /// @notice The call to an ERC20's `transferFrom` failed
  error TransferFromFailed();

  /// @notice The code wasn't to-be-executed by self
  error CodeNotBySelf();
  /// @notice A non-reentrant function was re-entered
  error Reentered();

  /// @notice An invalid address to escape to was specified.
  error InvalidEscapeAddress();
  /// @notice The escape address wasn't a contract.
  error EscapeAddressWasNotAContract();
  /// @notice Escaping when escape hatch wasn't invoked.
  error EscapeHatchNotInvoked();
  /// @notice Escaping failed to transfer out.
  error EscapeFailed();

  /// @notice Transfer coins into Serai with an instruction
  /// @param coin The coin to transfer in (address(0) if Ether)
  /// @param amount The amount to transfer in (msg.value if Ether)
  /**
   * @param instruction The encoded `RefundableInInstruction` for Serai to associate with this
   *  transfer in
   */
  // Re-entrancy doesn't bork this function
  // slither-disable-next-line reentrancy-events
  function inInstruction(address coin, uint256 amount, bytes memory instruction) external payable;

  /// @notice Execute some arbitrary code within a secure sandbox
  /**
   * @dev This performs sandboxing by deploying this code with `CREATE`. This is an external
   *   function as we can't meter `CREATE`/internal functions. We work around this by calling this
   *   function with `CALL` (which we can meter). This does forward `msg.value` to the newly
   *  deployed contract.
   */
  /// @param code The code to execute
  function executeArbitraryCode(bytes memory code) external payable;

  /// @notice Escape coins after the escape hatch has been invoked
  /// @param coin The coin to escape
  function escape(address coin) external;

  /// @notice Fetch the next nonce to use by an action published to this contract
  /// return The next nonce to use by an action published to this contract
  function nextNonce() external view returns (uint256);

  /// @notice Fetch the next key for Serai's Ethereum validator set
  /// @return The next key for Serai's Ethereum validator set or bytes32(0) if none is currently set
  function nextSeraiKey() external view returns (bytes32);

  /// @notice Fetch the current key for Serai's Ethereum validator set
  /**
   * @return The current key for Serai's Ethereum validator set or bytes32(0) if none is currently
   * set
   */
  function seraiKey() external view returns (bytes32);

  /// @notice Fetch the address escaped to
  /// @return The address which was escaped to (address(0) if the escape hatch hasn't been invoked)
  function escapedTo() external view returns (address);
}

/// @title Serai Router
/// @author Luke Parker <lukeparker@serai.exchange>
/// @notice Intakes coins for the Serai network and handles relaying batches of transfers out
interface IRouter is IRouterWithoutCollisions {
  /// @title A signature
  /// @dev Thin wrapper around `c, s` to simplify the API
  struct Signature {
    bytes32 c;
    bytes32 s;
  }

  /// @title The type of destination
  /**
   * @dev A destination is either an ABI-encoded address or an ABI-encoded `CodeDestination`
   *   containing code to deploy (invoking its constructor).
   */
  enum DestinationType {
    Address,
    Code
  }

  /// @title A code destination
  /**
   * @dev If transferring an ERC20 to this destination, it will be transferred to the address the
   *   code will be deployed to. If transferring ETH, it will be transferred with the deployment of
   *   the code. `code` is deployed with CREATE (calling its constructor). The entire deployment
   *   (and associated sandboxing) must consume less than `gasLimit` units of gas or it will revert.
   */
  struct CodeDestination {
    uint32 gasLimit;
    bytes code;
  }

  /// @title An instruction to transfer coins out
  /// @dev Specifies a destination and amount but not the coin as that's assumed to be contextual
  struct OutInstruction {
    DestinationType destinationType;
    bytes destination;
    uint256 amount;
  }

  /// @notice Update the key representing Serai's Ethereum validators
  /**
   * @dev This does not validate the passed-in key as much as possible. This is accepted as the key
   *   won't actually be rotated to until it provides a signature confirming the update however
   *   (proving signatures can be made by the key in question and verified via our Schnorr
   *   contract).
   */
  // @param signature The signature by the current key authorizing this update
  /// @param signature The signature by the current key authorizing this update
  /// @param nextSeraiKeyVar The key to update to, once it confirms the update
  function updateSeraiKey(Signature calldata signature, bytes32 nextSeraiKeyVar) external;

  /// @notice Confirm the next key representing Serai's Ethereum validators, updating to it
  /// @param signature The signature by the next key confirming its validity
  function confirmNextSeraiKey(Signature calldata signature) external;

  /// @notice Execute a batch of `OutInstruction`s
  /**
   * @dev All `OutInstruction`s in a batch are only for a single coin to simplify handling of the
   *   fee
   */
  /// @param signature The signature by the current key for Serai's Ethereum validators
  /// @param coin The coin all of these `OutInstruction`s are for
  /// @param fee The fee to pay (in coin) to the caller for their relaying of this batch
  /// @param outs The `OutInstruction`s to act on
  function execute(
    Signature calldata signature,
    address coin,
    uint256 fee,
    OutInstruction[] calldata outs
  ) external;

  /// @notice Escapes to a new smart contract
  /// @dev This should be used upon an invariant being reached or new functionality being needed
  /// @param signature The signature by the current key for Serai's Ethereum validators
  /// @param escapeTo The address to escape to
  function escapeHatch(Signature calldata signature, address escapeTo) external;
}
