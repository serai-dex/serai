use core::convert::Infallible;

use k256::{Scalar, ProjectivePoint};

use alloy_core::primitives::{Address, U256, Bytes};
use alloy_sol_types::SolCall as _;

use revm::{
  primitives::hardfork::SpecId,
  bytecode::Bytecode,
  state::AccountInfo,
  database::{empty_db::EmptyDB, in_memory_db::InMemoryDB},
  interpreter::{
    gas::calculate_initial_tx_gas,
    interpreter_action::{CallInputs, CallOutcome},
    interpreter::EthInterpreter,
    Interpreter,
  },
  handler::{
    instructions::EthInstructions, PrecompileProvider, EthPrecompiles, EthFrame, MainnetHandler,
  },
  context::{
    result::{EVMError, InvalidTransaction, ExecutionResult},
    context::Context,
    evm::Evm,
    *,
  },
  inspector::{Inspector, InspectorHandler as _},
};

use ethereum_schnorr::{PublicKey, Signature};

use crate::*;

// The specification this uses
const SPEC_ID: SpecId = SpecId::CANCUN;

// The chain ID used for gas estimation
const CHAIN_ID: U256 = U256::from_be_slice(&[1]);

type RevmContext = Context<BlockEnv, TxEnv, CfgEnv, InMemoryDB, Journal<InMemoryDB>, ()>;

fn precompiles() -> EthPrecompiles {
  let mut precompiles = EthPrecompiles::default();
  PrecompileProvider::<RevmContext>::set_spec(&mut precompiles, SPEC_ID);
  precompiles
}

/*
  Instead of attempting to solve the halting problem, we assume all CALLs take the worst-case
  amount of gas (as we do have bounds on the gas they're allowed to take). This assumption is
  implemented via an revm Inspector.

  The Inspector is allowed to override the CALL directly. We don't do this due to the amount of
  side effects a CALL has. Instead, we override the result.

  In the case the ERC20 is called, we additionally have it return `true` (as expected for compliant
  ERC20s, and as will trigger the worst-case gas consumption by the Router itself). This is done by
  hooking `call_end`.
*/
pub(crate) struct WorstCaseCallInspector {
  erc20: Option<Address>,
  call_depth: usize,
  unused_gas: u64,
  override_immediate_call_return_value: bool,
}
impl Inspector<RevmContext> for WorstCaseCallInspector {
  fn call(&mut self, _context: &mut RevmContext, _inputs: &mut CallInputs) -> Option<CallOutcome> {
    self.call_depth += 1;
    // Don't override the CALL immediately for prior described reasons
    None
  }

  fn call_end(
    &mut self,
    _context: &mut RevmContext,
    inputs: &CallInputs,
    outcome: &mut CallOutcome,
  ) {
    self.call_depth -= 1;

    /*
      Mark the amount of gas left unused, for us to later assume will be used in practice.

      This only runs if the call-depth is 1 (so only the Router-made calls have their gas so
      tracked), and if it's not to a precompile. This latter condition isn't solely because we can
      perfectly model precompiles (which wouldn't be worth the complexity) yet because the Router
      does call precompiles (ecrecover) and accordingly has to model the gas of that correctly.
    */
    if (self.call_depth == 1) && (!precompiles().contains(&inputs.target_address)) {
      let unused_gas = inputs.gas_limit - outcome.result.gas.spent();
      self.unused_gas += unused_gas;

      // Now that the CALL is over, flag we should normalize the values on the stack
      self.override_immediate_call_return_value = true;
    }

    // If ERC20, provide the expected ERC20 return data
    if Some(inputs.target_address) == self.erc20 {
      outcome.result.output = true.abi_encode().into();
    }
  }

  fn step(&mut self, interpreter: &mut Interpreter, _context: &mut RevmContext) {
    if self.override_immediate_call_return_value {
      // We fix this result to having succeeded, which triggers the most-expensive pathing within
      // the Router contract itself (some paths return early if a CALL fails)
      let return_value = interpreter.stack.pop().unwrap();
      assert!((return_value == U256::ZERO) || (return_value == U256::ONE));
      assert!(
        interpreter.stack.push(U256::ONE),
        "stack capacity couldn't fit item after popping an item"
      );
      self.override_immediate_call_return_value = false;
    }
  }
}

/// The object used for estimating gas.
///
/// Due to `execute` heavily branching, we locally simulate calls with revm.
pub(crate) type GasEstimator = Evm<
  RevmContext,
  WorstCaseCallInspector,
  EthInstructions<EthInterpreter, RevmContext>,
  EthPrecompiles,
  EthFrame,
>;

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
  pub const CONFIRM_NEXT_SERAI_KEY_GAS: u64 = 57_753;
  /// The gas used by `updateSeraiKey`.
  pub const UPDATE_SERAI_KEY_GAS: u64 = 60_062;
  /// The gas used by `escapeHatch`.
  pub const ESCAPE_HATCH_GAS: u64 = 61_111;

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

    Evm::new_with_inspector(
      RevmContext::new(db, SPEC_ID)
        .modify_cfg_chained(|cfg| {
          cfg.chain_id = CHAIN_ID.try_into().unwrap();
        })
        .modify_tx_chained(|tx: &mut TxEnv| {
          tx.gas_limit = u64::MAX;
          tx.kind = self.address.into();
        }),
      WorstCaseCallInspector {
        erc20,
        call_depth: 0,
        unused_gas: 0,
        override_immediate_call_return_value: false,
      },
      EthInstructions::default(),
      precompiles(),
    )
  }

  /// The worst-case gas cost for a legacy transaction which executes this batch.
  pub fn execute_gas_and_fee(
    &self,
    coin: Coin,
    fee_per_gas: U256,
    outs: &OutInstructions,
  ) -> (u64, U256) {
    // Unfortunately, we can't cache this in self, despite the following code being written such
    // that a common EVM instance could be used, as revm's types aren't Send/Sync and we expect the
    // Router to be send/sync
    let mut gas_estimator = self.gas_estimator(match coin {
      Coin::Ether => None,
      Coin::Erc20(erc20) => Some(erc20),
    });

    let shimmed_fee = match coin {
      Coin::Ether => {
        // Use a fee of 1 so the fee payment is recognized as positive-value, if the fee is
        // non-zero
        let fee = if fee_per_gas == U256::ZERO { U256::ZERO } else { U256::ONE };

        // Set a balance of the amount sent out to ensure we don't error on that premise
        gas_estimator.ctx.modify_db(|db| {
          let account = db.load_account(self.address).unwrap();
          account.info.balance = fee + outs.0.iter().map(|out| out.amount).sum::<U256>();
        });

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
      &Self::execute_message(CHAIN_ID, self.address, 1, coin, shimmed_fee, outs.clone()),
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
    gas_estimator.ctx.modify_tx(|tx| {
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
        shimmed_fee,
        outs.0.clone(),
      ))
      .abi_encode()
      .into();
    });

    // Execute the transaction
    let mut gas =
      match MainnetHandler::<_, EVMError<Infallible, InvalidTransaction>, EthFrame<_>>::default()
        .inspect_run(&mut gas_estimator)
        .unwrap()
      {
        ExecutionResult::Success { gas_used, gas_refunded, .. } => {
          assert_eq!(gas_refunded, 0);
          gas_used
        }
        res @ (ExecutionResult::Revert { .. } | ExecutionResult::Halt { .. }) => {
          panic!("estimated execute transaction failed: {res:?}")
        }
      };
    gas += gas_estimator.into_inspector().unused_gas;

    /*
      The transaction pays an initial gas fee which is dependent on the length of the calldata and
      the amount of non-zero bytes in the calldata. This is variable to the fee, which was prior
      shimmed to be `1`.

      Here, we calculate the actual fee, and update the initial gas fee accordingly. We then update
      the fee again, until the initial gas fee stops increasing.
    */
    let initial_gas = |fee, sig| {
      let gas = calculate_initial_tx_gas(
        SPEC_ID,
        &abi::executeCall::new((sig, Address::from(coin), fee, outs.0.clone())).abi_encode(),
        false,
        0,
        0,
        0,
      );
      assert_eq!(gas.floor_gas, 0);
      gas.initial_gas
    };
    let mut current_initial_gas = initial_gas(shimmed_fee, abi::Signature::from(&sig));
    // Remove the current initial gas from the transaction's gas
    gas -= current_initial_gas;
    loop {
      // Calculate the would-be fee
      let fee = fee_per_gas * U256::from(gas + current_initial_gas);
      // Calculate the would-be gas for this fee
      let new_initial_gas =
        initial_gas(fee, abi::Signature { c: [0xff; 32].into(), s: [0xff; 32].into() });
      // If the values are equal, or if it went down, return
      /*
        The gas will decrease if the new fee has more zero bytes in its encoding. Further
        iterations are unhelpful as they'll simply loop infinitely for some inputs. Accordingly, we
        return the current fee (which is for a very slightly higher gas rate) with the decreased
        gas to ensure this algorithm terminates.
      */
      if current_initial_gas >= new_initial_gas {
        return (gas + new_initial_gas, fee);
      }
      // Update what the current initial gas is
      current_initial_gas = new_initial_gas;
    }
  }

  /// The estimated gas for this `OutInstruction`.
  ///
  /// This does not model the quadratic costs incurred when in a batch, nor other misc costs such
  /// as the potential to cause one less zero byte in the fee's encoding. This is intended to
  /// produce a per-`OutInstruction` value which can be ratioed against others to decide the fee to
  /// deduct from each `OutInstruction`, before all `OutInstruction`s incur an amortized fee of
  /// what remains for the batch itself.
  pub fn execute_out_instruction_gas_estimate(
    &mut self,
    coin: Coin,
    instruction: abi::OutInstruction,
  ) -> u64 {
    if !self.empty_execute_gas.contains_key(&coin) {
      // This can't be de-duplicated across ERC20s due to the zero bytes in the address
      let (gas, _fee) = self.execute_gas_and_fee(coin, U256::from(0), &OutInstructions(vec![]));
      self.empty_execute_gas.insert(coin, gas);
    }

    let (gas, _fee) =
      self.execute_gas_and_fee(coin, U256::from(0), &OutInstructions(vec![instruction]));
    gas - self.empty_execute_gas[&coin]
  }
}
