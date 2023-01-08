use std::{collections::HashMap};
use bitcoin::{Txid, util::schnorr, schnorr::TapTweak, util::taproot, util::psbt, util::sighash::SchnorrSighashType};
use bitcoin_hashes::hex::FromHex;
use secp256k1::{XOnlyPublicKey, Message};
use bitcoin_hashes::{sha256, Hash, hex::ToHex};
use frost::{
  algorithm::Schnorr,
  curve::{Secp256k1,Ciphersuite},
  tests::{algorithm_machines, key_gen, sign},
  ThresholdKeys,
  sign::{AlgorithmMachine},
  
};
use sha2::{Digest, Sha256};
use rand_core::{OsRng, RngCore};
use crate::crypto::{BitcoinHram, make_even};
use k256::{elliptic_curve::sec1::ToEncodedPoint,Scalar};

pub fn sign_psbt_schnorr(
  secret_key: &secp256k1::SecretKey,
  pubkey: XOnlyPublicKey,
  leaf_hash: Option<taproot::TapLeafHash>,
  psbt_input: &mut psbt::Input,
  hash: taproot::TapSighashHash,
  hash_ty: SchnorrSighashType,
  secp: &secp256k1::Secp256k1<secp256k1::All>,
) {
  let keypair = secp256k1::KeyPair::from_seckey_slice(secp, secret_key.as_ref()).unwrap();
  let keypair = match leaf_hash {
      None => keypair
          .tap_tweak(secp, psbt_input.tap_merkle_root)
          .to_inner(),
      Some(_) => keypair, // no tweak for script spend
  };

  let msg = &Message::from_slice(&hash.into_inner()[..]).unwrap();
  let sig = secp.sign_schnorr(msg, &keypair);
  secp.verify_schnorr(&sig, msg, &XOnlyPublicKey::from_keypair(&keypair).0)
      .expect("invalid or corrupted schnorr signature");

  let final_signature = schnorr::SchnorrSig { sig, hash_ty };

  if let Some(lh) = leaf_hash {
      psbt_input
          .tap_script_sigs
          .insert((pubkey, lh), final_signature);
  } else {
      psbt_input.tap_key_sig = Some(final_signature);
  }
}

#[derive(Clone, Debug)]
pub struct SpendableOutput {
  pub txid: Txid,//[u8;32],
  pub vout: u32,
  pub amount:u64,
}

impl SpendableOutput {
  pub fn deserialize<R: std::io::Read>(r: &mut R) -> std::io::Result<SpendableOutput> {
    let mut txid_buff = [0; 32];
    r.read(&mut txid_buff)?;
    txid_buff.reverse();
    let tx_obj = Txid::from_hex(hex::encode(&txid_buff).as_str()).unwrap();
    let mut vout_buff = [0; 4];
    r.read(&mut vout_buff)?;
    let vout = u32::from_le_bytes(vout_buff);
    let mut amount_buff = [0; 8];
    r.read(&mut amount_buff)?;
    let amount = u64::from_le_bytes(amount_buff);
    Ok(SpendableOutput { txid: tx_obj, vout: vout, amount: amount })
  }
  
  pub fn serialize(&self) -> Vec<u8> {
    let mut res = self.txid.to_vec();
    res.extend(self.vout.to_le_bytes().to_vec());
    res.extend(self.amount.to_le_bytes().to_vec());
    res
  }
}