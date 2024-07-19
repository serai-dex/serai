use curve25519_dalek::{
  edwards::{CompressedEdwardsY, EdwardsPoint},
  scalar::Scalar,
};

use serde_json::Value;

use crate::{
  ringct::RctPrunable,
  transaction::{NotPruned, Transaction, Timelock, Input},
};

const TRANSACTIONS: &str = include_str!("./vectors/transactions.json");
const CLSAG_TX: &str = include_str!("./vectors/clsag_tx.json");
const RING_DATA: &str = include_str!("./vectors/ring_data.json");

#[derive(serde::Deserialize)]
struct Vector {
  id: String,
  hex: String,
  signature_hash: String,
  tx: Value,
}

fn tx_vectors() -> Vec<Vector> {
  serde_json::from_str(TRANSACTIONS).unwrap()
}

fn point(hex: &Value) -> EdwardsPoint {
  CompressedEdwardsY(hex::decode(hex.as_str().unwrap()).unwrap().try_into().unwrap())
    .decompress()
    .unwrap()
}

fn scalar(hex: &Value) -> Scalar {
  Scalar::from_canonical_bytes(hex::decode(hex.as_str().unwrap()).unwrap().try_into().unwrap())
    .unwrap()
}

fn point_vector(val: &Value) -> Vec<EdwardsPoint> {
  let mut v = vec![];
  for hex in val.as_array().unwrap() {
    v.push(point(hex));
  }
  v
}

fn scalar_vector(val: &Value) -> Vec<Scalar> {
  let mut v = vec![];
  for hex in val.as_array().unwrap() {
    v.push(scalar(hex));
  }
  v
}

#[test]
fn parse() {
  for v in tx_vectors() {
    let tx =
      Transaction::<NotPruned>::read(&mut hex::decode(v.hex.clone()).unwrap().as_slice()).unwrap();

    // check version
    assert_eq!(tx.version(), v.tx["version"]);

    // check unlock time
    match tx.prefix().additional_timelock {
      Timelock::None => assert_eq!(0, v.tx["unlock_time"]),
      Timelock::Block(h) => assert_eq!(h, v.tx["unlock_time"]),
      Timelock::Time(t) => assert_eq!(t, v.tx["unlock_time"]),
    }

    // check inputs
    let inputs = v.tx["vin"].as_array().unwrap();
    assert_eq!(tx.prefix().inputs.len(), inputs.len());
    for (i, input) in tx.prefix().inputs.iter().enumerate() {
      match input {
        Input::Gen(h) => assert_eq!(*h, inputs[i]["gen"]["height"]),
        Input::ToKey { amount, key_offsets, key_image } => {
          let key = &inputs[i]["key"];
          assert_eq!(amount.unwrap_or(0), key["amount"]);
          assert_eq!(*key_image, point(&key["k_image"]));
          assert_eq!(key_offsets, key["key_offsets"].as_array().unwrap());
        }
      }
    }

    // check outputs
    let outputs = v.tx["vout"].as_array().unwrap();
    assert_eq!(tx.prefix().outputs.len(), outputs.len());
    for (i, output) in tx.prefix().outputs.iter().enumerate() {
      assert_eq!(output.amount.unwrap_or(0), outputs[i]["amount"]);
      if output.view_tag.is_some() {
        assert_eq!(output.key, point(&outputs[i]["target"]["tagged_key"]["key"]).compress());
        let view_tag =
          hex::decode(outputs[i]["target"]["tagged_key"]["view_tag"].as_str().unwrap()).unwrap();
        assert_eq!(view_tag.len(), 1);
        assert_eq!(output.view_tag.unwrap(), view_tag[0]);
      } else {
        assert_eq!(output.key, point(&outputs[i]["target"]["key"]).compress());
      }
    }

    // check extra
    assert_eq!(tx.prefix().extra, v.tx["extra"].as_array().unwrap().as_slice());

    match &tx {
      Transaction::V1 { signatures, .. } => {
        // check signatures for v1 txs
        let sigs_array = v.tx["signatures"].as_array().unwrap();
        for (i, sig) in signatures.iter().enumerate() {
          let tx_sig = hex::decode(sigs_array[i].as_str().unwrap()).unwrap();
          for (i, sig) in sig.sigs.iter().enumerate() {
            let start = i * 64;
            let c: [u8; 32] = tx_sig[start .. (start + 32)].try_into().unwrap();
            let s: [u8; 32] = tx_sig[(start + 32) .. (start + 64)].try_into().unwrap();
            assert_eq!(sig.c, Scalar::from_canonical_bytes(c).unwrap());
            assert_eq!(sig.s, Scalar::from_canonical_bytes(s).unwrap());
          }
        }
      }
      Transaction::V2 { proofs: None, .. } => assert_eq!(v.tx["rct_signatures"]["type"], 0),
      Transaction::V2 { proofs: Some(proofs), .. } => {
        // check rct signatures
        let rct = &v.tx["rct_signatures"];
        assert_eq!(u8::from(proofs.rct_type()), rct["type"]);

        assert_eq!(proofs.base.fee, rct["txnFee"]);
        assert_eq!(proofs.base.commitments, point_vector(&rct["outPk"]));
        let ecdh_info = rct["ecdhInfo"].as_array().unwrap();
        assert_eq!(proofs.base.encrypted_amounts.len(), ecdh_info.len());
        for (i, ecdh) in proofs.base.encrypted_amounts.iter().enumerate() {
          let mut buf = vec![];
          ecdh.write(&mut buf).unwrap();
          assert_eq!(buf, hex::decode(ecdh_info[i]["amount"].as_str().unwrap()).unwrap());
        }

        // check ringct prunable
        match &proofs.prunable {
          RctPrunable::Clsag { bulletproof: _, clsags, pseudo_outs } => {
            // check bulletproofs
            /* TODO
            for (i, bp) in bulletproofs.iter().enumerate() {
              match bp {
                Bulletproof::Original(o) => {
                  let bps = v.tx["rctsig_prunable"]["bp"].as_array().unwrap();
                  assert_eq!(bulletproofs.len(), bps.len());
                  assert_eq!(o.A, point(&bps[i]["A"]));
                  assert_eq!(o.S, point(&bps[i]["S"]));
                  assert_eq!(o.T1, point(&bps[i]["T1"]));
                  assert_eq!(o.T2, point(&bps[i]["T2"]));
                  assert_eq!(o.taux, scalar(&bps[i]["taux"]));
                  assert_eq!(o.mu, scalar(&bps[i]["mu"]));
                  assert_eq!(o.L, point_vector(&bps[i]["L"]));
                  assert_eq!(o.R, point_vector(&bps[i]["R"]));
                  assert_eq!(o.a, scalar(&bps[i]["a"]));
                  assert_eq!(o.b, scalar(&bps[i]["b"]));
                  assert_eq!(o.t, scalar(&bps[i]["t"]));
                }
                Bulletproof::Plus(p) => {
                  let bps = v.tx["rctsig_prunable"]["bpp"].as_array().unwrap();
                  assert_eq!(bulletproofs.len(), bps.len());
                  assert_eq!(p.A, point(&bps[i]["A"]));
                  assert_eq!(p.A1, point(&bps[i]["A1"]));
                  assert_eq!(p.B, point(&bps[i]["B"]));
                  assert_eq!(p.r1, scalar(&bps[i]["r1"]));
                  assert_eq!(p.s1, scalar(&bps[i]["s1"]));
                  assert_eq!(p.d1, scalar(&bps[i]["d1"]));
                  assert_eq!(p.L, point_vector(&bps[i]["L"]));
                  assert_eq!(p.R, point_vector(&bps[i]["R"]));
                }
              }
            }
            */

            // check clsags
            let cls = v.tx["rctsig_prunable"]["CLSAGs"].as_array().unwrap();
            for (i, cl) in clsags.iter().enumerate() {
              assert_eq!(cl.D, point(&cls[i]["D"]));
              assert_eq!(cl.c1, scalar(&cls[i]["c1"]));
              assert_eq!(cl.s, scalar_vector(&cls[i]["s"]));
            }

            // check pseudo outs
            assert_eq!(pseudo_outs, &point_vector(&v.tx["rctsig_prunable"]["pseudoOuts"]));
          }
          // TODO: Add
          _ => panic!("non-null/CLSAG test vector"),
        }
      }
    }

    // check serialized hex
    let mut buf = Vec::new();
    tx.write(&mut buf).unwrap();
    let serialized_tx = hex::encode(&buf);
    assert_eq!(serialized_tx, v.hex);
  }
}

#[test]
fn signature_hash() {
  for v in tx_vectors() {
    let tx = Transaction::read(&mut hex::decode(v.hex.clone()).unwrap().as_slice()).unwrap();
    // check for signature hashes
    if let Some(sig_hash) = tx.signature_hash() {
      assert_eq!(sig_hash, hex::decode(v.signature_hash.clone()).unwrap().as_slice());
    } else {
      // make sure it is a miner tx.
      assert!(matches!(tx.prefix().inputs[0], Input::Gen(_)));
    }
  }
}

#[test]
fn hash() {
  for v in &tx_vectors() {
    let tx = Transaction::read(&mut hex::decode(v.hex.clone()).unwrap().as_slice()).unwrap();
    assert_eq!(tx.hash(), hex::decode(v.id.clone()).unwrap().as_slice());
  }
}

#[test]
fn clsag() {
  /*
    // following keys belong to the wallet that created the CLSAG_TX, and to the
    // CLSAG_TX itself and here for debug purposes in case this test unexpectedly fails some day.
    let view_key = "9df81dd2e369004d3737850e4f0abaf2111720f270b174acf8e08547e41afb0b";
    let spend_key = "25f7339ce03a0206129c0bdd78396f80bf28183ccd16084d4ab1cbaf74f0c204";
    let tx_key = "650c8038e5c6f1c533cacc1713ac27ef3ec70d7feedde0c5b37556d915b4460c";
  */

  #[derive(serde::Deserialize)]
  struct TxData {
    hex: String,
    tx: Value,
  }
  #[derive(serde::Deserialize)]
  struct OutData {
    key: Value,
    mask: Value,
  }
  let tx_data = serde_json::from_str::<TxData>(CLSAG_TX).unwrap();
  let out_data = serde_json::from_str::<Vec<Vec<OutData>>>(RING_DATA).unwrap();
  let tx =
    Transaction::<NotPruned>::read(&mut hex::decode(tx_data.hex).unwrap().as_slice()).unwrap();

  // gather rings
  let mut rings = vec![];
  for data in out_data {
    let mut ring = vec![];
    for out in &data {
      ring.push([point(&out.key), point(&out.mask)]);
    }
    rings.push(ring)
  }

  // gather key images
  let mut key_images = vec![];
  let inputs = tx_data.tx["vin"].as_array().unwrap();
  for input in inputs {
    key_images.push(point(&input["key"]["k_image"]));
  }

  // gather pseudo_outs
  let mut pseudo_outs = vec![];
  let pouts = tx_data.tx["rctsig_prunable"]["pseudoOuts"].as_array().unwrap();
  for po in pouts {
    pseudo_outs.push(point(po));
  }

  // verify clsags
  match tx {
    Transaction::V2 { proofs: Some(ref proofs), .. } => match &proofs.prunable {
      RctPrunable::Clsag { bulletproof: _, clsags, .. } => {
        for (i, cls) in clsags.iter().enumerate() {
          cls
            .verify(&rings[i], &key_images[i], &pseudo_outs[i], &tx.signature_hash().unwrap())
            .unwrap();
        }
      }
      // TODO: Add
      _ => panic!("non-CLSAG test vector"),
    },
    // TODO: Add
    _ => panic!("non-CLSAG test vector"),
  }
}
