use std::{sync::LazyLock, collections::HashMap};

use ciphersuite::{Ciphersuite, Secp256k1};

use bitcoin_serai::{
  bitcoin::{
    blockdata::opcodes,
    script::{Instruction, ScriptBuf},
    Transaction,
  },
  wallet::Scanner,
};

use serai_client::networks::bitcoin::Address;

use primitives::OutputType;

const KEY_DST: &[u8] = b"Serai Bitcoin Processor Key Offset";
static BRANCH_BASE_OFFSET: LazyLock<<Secp256k1 as Ciphersuite>::F> =
  LazyLock::new(|| Secp256k1::hash_to_F(KEY_DST, b"branch"));
static CHANGE_BASE_OFFSET: LazyLock<<Secp256k1 as Ciphersuite>::F> =
  LazyLock::new(|| Secp256k1::hash_to_F(KEY_DST, b"change"));
static FORWARD_BASE_OFFSET: LazyLock<<Secp256k1 as Ciphersuite>::F> =
  LazyLock::new(|| Secp256k1::hash_to_F(KEY_DST, b"forward"));

// Unfortunately, we have per-key offsets as it's the root key plus the base offset may not be
// even. While we could tweak the key until all derivations are even, that'd require significantly
// more tweaking. This algorithmic complexity is preferred.
pub(crate) fn offsets_for_key(
  key: <Secp256k1 as Ciphersuite>::G,
) -> HashMap<OutputType, <Secp256k1 as Ciphersuite>::F> {
  let mut offsets = HashMap::from([(OutputType::External, <Secp256k1 as Ciphersuite>::F::ZERO)]);

  // We create an actual Bitcoin scanner as upon adding an offset, it yields the tweaked offset
  // actually used
  let mut scanner = Scanner::new(key).unwrap();
  let mut register = |kind, offset| {
    let tweaked_offset = scanner.register_offset(offset).expect("offset collision");
    offsets.insert(kind, tweaked_offset);
  };

  register(OutputType::Branch, *BRANCH_BASE_OFFSET);
  register(OutputType::Change, *CHANGE_BASE_OFFSET);
  register(OutputType::Forwarded, *FORWARD_BASE_OFFSET);

  offsets
}

pub(crate) fn scanner(key: <Secp256k1 as Ciphersuite>::G) -> Scanner {
  let mut scanner = Scanner::new(key).unwrap();
  for (_, offset) in offsets_for_key(key) {
    let tweaked_offset = scanner.register_offset(offset).unwrap();
    assert_eq!(tweaked_offset, offset);
  }
  scanner
}

pub(crate) fn presumed_origin(tx: &Transaction) -> Option<Address> {
  todo!("TODO")

  /*
  let spent_output = {
    let input = &tx.input[0];
    let mut spent_tx = input.previous_output.txid.as_raw_hash().to_byte_array();
    spent_tx.reverse();
    let mut tx;
    while {
      tx = self.rpc.get_transaction(&spent_tx).await;
      tx.is_err()
    } {
      log::error!("couldn't get transaction from bitcoin node: {tx:?}");
      sleep(Duration::from_secs(5)).await;
    }
    tx.unwrap().output.swap_remove(usize::try_from(input.previous_output.vout).unwrap())
  };
  Address::new(spent_output.script_pubkey)
  */
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
