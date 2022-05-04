use std::collections::HashSet;

use rand_core::{RngCore, CryptoRng};

use curve25519_dalek::edwards::EdwardsPoint;

use monero::VarInt;

use crate::{transaction::SpendableOutput, rpc::{RpcError, Rpc}};

const MIXINS: usize = 11;

async fn select_single<R: RngCore + CryptoRng>(
  rng: &mut R,
  rpc: &Rpc,
  height: usize,
  high: u64,
  used: &mut HashSet<u64>
) -> Result<(u64, [EdwardsPoint; 2]), RpcError> {
  let mut o;
  let mut output = None;
  while {
    o = rng.next_u64() % u64::try_from(high).unwrap();
    used.contains(&o) || {
      output = rpc.get_outputs(&[o], height).await?[0];
      output.is_none()
    }
  } {}
  used.insert(o);
  Ok((o, output.unwrap()))
}

// Uses VarInt as this is solely used for key_offsets which is serialized by monero-rs
fn offset(mixins: &[u64]) -> Vec<VarInt> {
  let mut res = vec![VarInt(mixins[0])];
  res.resize(mixins.len(), VarInt(0));
  for m in (1 .. mixins.len()).rev() {
    res[m] = VarInt(mixins[m] - mixins[m - 1]);
  }
  res
}

pub(crate) async fn select<R: RngCore + CryptoRng>(
  rng: &mut R,
  rpc: &Rpc,
  height: usize,
  inputs: &[SpendableOutput]
) -> Result<Vec<(Vec<VarInt>, u8, Vec<[EdwardsPoint; 2]>)>, RpcError> {
  // Convert the inputs in question to the raw output data
  let mut outputs = Vec::with_capacity(inputs.len());
  for input in inputs {
    outputs.push((
      rpc.get_o_indexes(input.tx).await?[input.o],
      [input.key, input.commitment.calculate()]
    ));
  }

  let high = rpc.get_high_output(height - 1).await?;
  let high_f = high as f64;
  if (high_f as u64) != high {
    panic!("Transaction output index exceeds f64");
  }

  let mut used = HashSet::<u64>::new();
  for o in &outputs {
    used.insert(o.0);
  }

  let mut res = Vec::with_capacity(inputs.len());
  for (i, o) in outputs.iter().enumerate() {
    let mut mixins = Vec::with_capacity(MIXINS);
    for _ in 0 .. MIXINS {
      mixins.push(select_single(rng, rpc, height, high, &mut used).await?);
    }
    mixins.sort_by(|a, b| a.0.cmp(&b.0));

    // Make sure the TX passes the sanity check that the median output is within the last 40%
    // This actually checks the median is within the last third, a slightly more aggressive boundary,
    // as the height used in this calculation will be slightly under the height this is sanity
    // checked against
    while mixins[MIXINS / 2].0 < (high * 2 / 3) {
      // If it's not, update the bottom half with new values to ensure the median only moves up
      for m in 0 .. MIXINS / 2 {
        // We could not remove this, saving CPU time and removing low values as possibilities, yet
        // it'd increase the amount of mixins required to create this transaction and some banned
        // outputs may be the best options
        used.remove(&mixins[m].0);
        mixins[m] = select_single(rng, rpc, height, high, &mut used).await?;
      }
      mixins.sort_by(|a, b| a.0.cmp(&b.0));
    }

    // Replace the closest selected decoy with the actual
    let mut replace = 0;
    let mut distance = u64::MAX;
    for m in 0 .. mixins.len() {
      let diff = mixins[m].0.abs_diff(o.0);
      if diff < distance {
        replace = m;
        distance = diff;
      }
    }

    mixins[replace] = outputs[i];
    res.push((
      offset(&mixins.iter().map(|output| output.0).collect::<Vec<_>>()),
      u8::try_from(replace).unwrap(),
      mixins.iter().map(|output| output.1).collect()
    ));
  }

  Ok(res)
}
