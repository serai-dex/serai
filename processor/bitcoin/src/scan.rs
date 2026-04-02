use std::{sync::LazyLock, collections::HashMap};

use ciphersuite::*;
use ciphersuite_kp256::Secp256k1;

use bitcoin_serai::{
  bitcoin::{
    blockdata::opcodes,
    script::{Instruction, ScriptBuf},
    Transaction,
  },
  wallet::Scanner,
};

use serai_client_bitcoin::Address;

use serai_db::Get;
use primitives::OutputType;

use crate::hash_bytes;

// TODO: Bitcoin HD derivation, instead of these bespoke labels?
pub(crate) static OFFSETS: LazyLock<HashMap<OutputType, <Secp256k1 as WrappedGroup>::F>> =
  LazyLock::new(|| {
    HashMap::from([
      (OutputType::External, <Secp256k1 as WrappedGroup>::F::ZERO),
      (OutputType::Branch, Secp256k1::hash_to_F(b"branch")),
      (OutputType::Change, Secp256k1::hash_to_F(b"change")),
      (OutputType::Forwarded, Secp256k1::hash_to_F(b"forward")),
    ])
  });

pub(crate) fn scanner(key: <Secp256k1 as WrappedGroup>::G) -> Scanner {
  let mut scanner = Scanner::new(key).unwrap();
  for offset in OFFSETS.values() {
    let () = scanner.register_offset(*offset).unwrap();
  }
  scanner
}

pub(crate) fn presumed_origin(getter: &impl Get, tx: &Transaction) -> Option<Address> {
  for input in &tx.input {
    let txid = hash_bytes(input.previous_output.txid.to_raw_hash());
    let vout = input.previous_output.vout;
    if let Some(address) =
      Address::new(crate::txindex::script_pubkey_for_on_chain_output(getter, txid, vout))
    {
      return Some(address);
    }
  }
  None?
}

// Checks if this script matches SHA256 PUSH MSG_HASH OP_EQUALVERIFY ..
fn matches_segwit_data(script: &ScriptBuf) -> Option<bool> {
  let mut ins = script.instructions();

  // first item should be SHA256 code
  if ins.next()?.ok()?.opcode()? != opcodes::all::OP_SHA256 {
    return Some(false);
  }

  // next should be a data push
  ins.next()?.ok()?.push_bytes()?;

  // next should be a equality check
  if ins.next()?.ok()?.opcode()? != opcodes::all::OP_EQUALVERIFY {
    return Some(false);
  }

  Some(true)
}

// Extract the data for Serai from a transaction
pub(crate) fn extract_serai_data(tx: &Transaction) -> Vec<u8> {
  // Check for an OP_RETURN output
  let mut data = (|| {
    for output in &tx.output {
      if output.script_pubkey.is_op_return() {
        match output.script_pubkey.instructions_minimal().last() {
          Some(Ok(Instruction::PushBytes(data))) => return Some(data.as_bytes().to_vec()),
          _ => continue,
        }
      }
    }
    None
  })();

  // Check the inputs
  if data.is_none() {
    for input in &tx.input {
      let witness = input.witness.to_vec();
      // The witness has to have at least 2 items, msg and the redeem script
      if witness.len() >= 2 {
        let redeem_script = ScriptBuf::from_bytes(witness.last().unwrap().clone());
        if matches_segwit_data(&redeem_script) == Some(true) {
          data = Some(witness[witness.len() - 2].clone()); // len() - 1 is the redeem_script
          break;
        }
      }
    }
  }

  data.unwrap_or(vec![])
}
