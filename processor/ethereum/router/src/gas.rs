use k256::{Scalar, ProjectivePoint};

use alloy_core::primitives::{Address, U160, U256};
use alloy_sol_types::SolCall;

use revm::{
  primitives::*,
  interpreter::{gas::*, opcode::InstructionTables, *},
  db::{emptydb::EmptyDB, in_memory_db::InMemoryDB},
  Handler, Context, EvmBuilder, Evm,
};

use ethereum_schnorr::{PublicKey, Signature};

use crate::*;

// The chain ID used for gas estimation
const CHAIN_ID: U256 = U256::from_be_slice(&[1]);

/// The object used for estimating gas.
///
/// Due to `execute` heavily branching, we locally simulate calls with revm.
pub(crate) type GasEstimator = Evm<'static, (), InMemoryDB>;

impl Router {
  const SMART_CONTRACT_NONCE_STORAGE_SLOT: U256 = U256::from_be_slice(&[0]);
  const NONCE_STORAGE_SLOT: U256 = U256::from_be_slice(&[1]);
  const SERAI_KEY_STORAGE_SLOT: U256 = U256::from_be_slice(&[3]);

  // Gas allocated for ERC20 calls
  #[cfg(test)]
  pub(crate) const GAS_FOR_ERC20_CALL: u64 = 100_000;

  /*
    The gas limits to use for non-Execute transactions.

    These don't branch on the success path, allowing constants to be used out-right. These
    constants target the Cancun network upgrade and are validated by the tests.

    While whoever publishes these transactions may be able to query a gas estimate, it may not be
    reasonable to. If the signing context is a distributed group, as Serai frequently employs, a
    non-deterministic gas (such as estimates from the local nodes) would require a consensus
    protocol to determine  which to use.

    These gas limits may break if/when gas opcodes undergo repricing. In that case, this library is
    expected to be modified with these made parameters. The caller would then be expected to pass
    the correct set of prices for the network they're operating on.
  */
  /// The gas used by `confirmSeraiKey`.
  pub const CONFIRM_NEXT_SERAI_KEY_GAS: u64 = 57_736;
  /// The gas used by `updateSeraiKey`.
  pub const UPDATE_SERAI_KEY_GAS: u64 = 60_045;
  /// The gas used by `escapeHatch`.
  pub const ESCAPE_HATCH_GAS: u64 = 61_094;

  /// The key to use when performing gas estimations.
  ///
  /// There has to be a key to verify the signatures of the messages signed.
  fn gas_estimation_key() -> (Scalar, PublicKey) {
    (Scalar::ONE, PublicKey::new(ProjectivePoint::GENERATOR).unwrap())
  }

  pub(crate) fn gas_estimator(&self, erc20: Option<Address>) -> GasEstimator {
    // The DB to use
    let db = {
      const BYTECODE: &[u8] = {
        const BYTECODE_HEX: &[u8] = include_bytes!(concat!(
          env!("OUT_DIR"),
          "/serai-processor-ethereum-router/Router.bin-runtime"
        ));
        const BYTECODE: [u8; BYTECODE_HEX.len() / 2] =
          match hex::const_decode_to_array::<{ BYTECODE_HEX.len() / 2 }>(BYTECODE_HEX) {
            Ok(bytecode) => bytecode,
            Err(_) => panic!("Router.bin-runtime did not contain valid hex"),
          };
        &BYTECODE
      };
      let bytecode = Bytecode::new_legacy(Bytes::from_static(BYTECODE));

      let mut db = InMemoryDB::new(EmptyDB::new());
      // Insert the Router into the state
      db.insert_account_info(
        self.address,
        AccountInfo {
          balance: U256::from(0),
          // Per EIP-161
          nonce: 1,
          code_hash: bytecode.hash_slow(),
          code: Some(bytecode),
        },
      );

      // Insert the value for _smartContractNonce set in the constructor
      // All operations w.r.t. execute in constant-time, making the actual value irrelevant
      db.insert_account_storage(
        self.address,
        Self::SMART_CONTRACT_NONCE_STORAGE_SLOT,
        U256::from(1),
      )
      .unwrap();

      // Insert a non-zero nonce, as the zero nonce will update to the initial key and never be
      // used for any gas estimations of `execute`, the only function estimated
      db.insert_account_storage(self.address, Self::NONCE_STORAGE_SLOT, U256::from(1)).unwrap();

      // Insert the public key to verify with
      db.insert_account_storage(
        self.address,
        Self::SERAI_KEY_STORAGE_SLOT,
        U256::from_be_bytes(Self::gas_estimation_key().1.eth_repr()),
      )
      .unwrap();

      db
    };

    // Create a custom handler so we can assume every CALL is the worst-case
    let handler = {
      let mut instructions = InstructionTables::<'_, _>::new_plain::<CancunSpec>();
      instructions.update_boxed(revm::interpreter::opcode::CALL, {
        move |call_op, interpreter, host: &mut Context<_, _>| {
          let (address_called, value, return_addr, return_len) = {
            let stack = &mut interpreter.stack;

            let address = stack.peek(1).unwrap();
            let value = stack.peek(2).unwrap();
            let return_addr = stack.peek(5).unwrap();
            let return_len = stack.peek(6).unwrap();

            (
              address,
              value,
              usize::try_from(return_addr).unwrap(),
              usize::try_from(return_len).unwrap(),
            )
          };
          let address_called =
            Address::from(U160::from_be_slice(&address_called.to_be_bytes::<32>()[12 ..]));

          // Have the original call op incur its costs as programmed
          call_op(interpreter, host);

          /*
            Unfortunately, the call opcode executed only sets itself up, it doesn't handle the
            entire inner call for us. We manually do so here by shimming the intended result. The
            other option, on this path chosen, would be to shim the call-frame execution ourselves
            and only then manipulate the result.

            Ideally, we wouldn't override CALL, yet STOP/RETURN (the tail of the CALL) to avoid all
            of this. Those overrides weren't being successfully hit in initial experiments, and
            while this solution does appear overly complicated, it's sufficiently tested to justify
            itself.

            revm does cost the entire gas limit during the call setup. After the call completes,
            it refunds whatever was unused. Since we manually complete the call here ourselves,
            but don't implement that refund logic as we want the worst-case scenario, we do
            successfully implement complete costing of the gas limit.
          */

          // Perform the call value transfer, which also marks the recipient as warm
          assert!(host
            .evm
            .inner
            .journaled_state
            .transfer(
              &interpreter.contract.target_address,
              &address_called,
              value,
              &mut host.evm.inner.db
            )
            .unwrap()
            .is_none());

          // Clear the call-to-be
          debug_assert!(matches!(interpreter.next_action, InterpreterAction::Call { .. }));
          interpreter.next_action = InterpreterAction::None;
          interpreter.instruction_result = InstructionResult::Continue;

          // Clear the existing return data
          interpreter.return_data_buffer.clear();

          /*
            If calling an ERC20, trigger the return data's worst-case by returning `true`
            (as expected by compliant ERC20s). Else return none, as we expect none or won't bother
            copying/decoding the return data.

            This doesn't affect calls to ecrecover as those use STATICCALL and this overrides CALL
            alone.
          */
          if Some(address_called) == erc20 {
            interpreter.return_data_buffer = true.abi_encode().into();
          }
          // Also copy the return data into memory
          let return_len = return_len.min(interpreter.return_data_buffer.len());
          let needed_memory_size = return_addr + return_len;
          if interpreter.shared_memory.len() < needed_memory_size {
            assert!(interpreter.resize_memory(needed_memory_size));
          }
          interpreter
            .shared_memory
            .slice_mut(return_addr, return_len)
            .copy_from_slice(&interpreter.return_data_buffer[.. return_len]);

          // Finally, push the result of the call onto the stack
          interpreter.stack.push(U256::from(1)).unwrap();
        }
      });
      let mut handler = Handler::mainnet::<CancunSpec>();
      handler.set_instruction_table(instructions);

      handler
    };

    EvmBuilder::default()
      .with_db(db)
      .with_handler(handler)
      .modify_cfg_env(|cfg| {
        cfg.chain_id = CHAIN_ID.try_into().unwrap();
      })
      .modify_tx_env(|tx| {
        tx.gas_limit = u64::MAX;
        tx.transact_to = self.address.into();
      })
      .build()
  }

  /// The worst-case gas cost for a legacy transaction which executes this batch.
  ///
  /// This assumes the fee will be non-zero.
  pub fn execute_gas(&self, coin: Coin, fee_per_gas: U256, outs: &OutInstructions) -> u64 {
    // Unfortunately, we can't cache this in self, despite the following code being written such
    // that a common EVM instance could be used, as revm's types aren't Send/Sync and we expect the
    // Router to be send/sync
    let mut gas_estimator = self.gas_estimator(match coin {
      Coin::Ether => None,
      Coin::Erc20(erc20) => Some(erc20),
    });

    let fee = match coin {
      Coin::Ether => {
        // Use a fee of 1 so the fee payment is recognized as positive-value
        let fee = U256::from(1);

        // Set a balance of the amount sent out to ensure we don't error on that premise
        {
          let db = gas_estimator.db_mut();
          let account = db.load_account(self.address).unwrap();
          account.info.balance = fee + outs.0.iter().map(|out| out.amount).sum::<U256>();
        }

        fee
      }
      Coin::Erc20(_) => U256::from(0),
    };

    // Sign a dummy signature
    let (private_key, public_key) = Self::gas_estimation_key();
    let c = Signature::challenge(
      // Use a nonce of 1
      ProjectivePoint::GENERATOR,
      &public_key,
      &Self::execute_message(CHAIN_ID, 1, coin, fee, outs.clone()),
    );
    let s = Scalar::ONE + (c * private_key);
    let sig = Signature::new(c, s).unwrap();

    // Write the current transaction
    /*
      revm has poor documentation on if the EVM instance can be dirtied, which would be the concern
      if we shared a mutable reference to a singular instance across invocations, but our
      consistent use of nonce #1 shows storage read/writes aren't being persisted. They're solely
      returned upon execution in a `state` field we ignore.
    */
    {
      let tx = gas_estimator.tx_mut();
      tx.caller = Address::from({
        /*
          We assume the transaction sender is not the destination of any `OutInstruction`, making
          all transfers to destinations cold. A malicious adversary could create an
          `OutInstruction` whose destination is the caller stubbed here, however, to make us
          under-estimate.

          We prevent this by defining the caller as the hash of the `OutInstruction`s, forcing a
          hash collision to cause an `OutInstruction` destination to be warm when it wasn't warmed
          by either being the Router, being the ERC20, or by being the destination of a distinct
          `OutInstruction`. All of those cases will affect the gas used in reality accordingly.
        */
        let hash = ethereum_primitives::keccak256(outs.0.abi_encode());
        <[u8; 20]>::try_from(&hash[12 ..]).unwrap()
      });
      tx.data = abi::executeCall::new((
        abi::Signature::from(&sig),
        Address::from(coin),
        fee,
        outs.0.clone(),
      ))
      .abi_encode()
      .into();
    }

    // Execute the transaction
    let mut gas = match gas_estimator.transact().unwrap().result {
      ExecutionResult::Success { gas_used, gas_refunded, .. } => {
        assert_eq!(gas_refunded, 0);
        gas_used
      }
      res => panic!("estimated execute transaction failed: {res:?}"),
    };

    // The transaction uses gas based on the amount of non-zero bytes in the calldata, which is
    // variable to the fee, which is variable to the gad used. This iterates until parity
    let initial_gas = |fee, sig| {
      let gas = calculate_initial_tx_gas(
        SpecId::CANCUN,
        &abi::executeCall::new((sig, Address::from(coin), fee, outs.0.clone())).abi_encode(),
        false,
        &[],
        0,
      );
      assert_eq!(gas.floor_gas, 0);
      gas.initial_gas
    };
    let mut current_initial_gas = initial_gas(fee, abi::Signature::from(&sig));
    loop {
      let fee = fee_per_gas * U256::from(gas);
      let new_initial_gas =
        initial_gas(fee, abi::Signature { c: [0xff; 32].into(), s: [0xff; 32].into() });
      if current_initial_gas >= new_initial_gas {
        return gas;
      }

      gas += new_initial_gas - current_initial_gas;
      current_initial_gas = new_initial_gas;
    }
  }

  /// The estimated fee for this `OutInstruction`.
  ///
  /// This does not model the quadratic costs incurred when in a batch, nor other misc costs such
  /// as the potential to cause one less zero byte in the fee's encoding. This is intended to
  /// produce a per-`OutInstruction` fee to deduct from each `OutInstruction`, before all
  /// `OutInstruction`s incur an amortized fee of what remains for the batch itself.
  pub fn execute_out_instruction_gas_estimate(
    &mut self,
    coin: Coin,
    instruction: abi::OutInstruction,
  ) -> u64 {
    #[allow(clippy::map_entry)] // clippy doesn't realize the multiple mutable borrows
    if !self.empty_execute_gas.contains_key(&coin) {
      // This can't be de-duplicated across ERC20s due to the zero bytes in the address
      let gas = self.execute_gas(coin, U256::from(0), &OutInstructions(vec![]));
      self.empty_execute_gas.insert(coin, gas);
    }

    let gas = self.execute_gas(coin, U256::from(0), &OutInstructions(vec![instruction]));
    gas - self.empty_execute_gas[&coin]
  }
}
