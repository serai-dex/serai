use std::collections::HashSet;

use lazy_static::lazy_static;

use rand_core::{RngCore, CryptoRng};
use rand_distr::{Distribution, Gamma};

use curve25519_dalek::edwards::EdwardsPoint;

use monero::VarInt;

use crate::{transaction::SpendableOutput, rpc::{RpcError, Rpc}};

const LOCK_WINDOW: usize = 10;
const RECENT_WINDOW: usize = 15;
const BLOCK_TIME: usize = 120;
const BLOCKS_PER_YEAR: usize = 365 * 24 * 60 * 60 / BLOCK_TIME;
const TIP_APPLICATION: f64 = (LOCK_WINDOW * BLOCK_TIME) as f64;

const MIXINS: usize = 11;

lazy_static! {
  static ref GAMMA: Gamma<f64> = Gamma::new(19.28, 1.0 / 1.61).unwrap();
}

async fn select_single<R: RngCore + CryptoRng>(
  rng: &mut R,
  rpc: &Rpc,
  height: usize,
  distribution: &[u64],
  high: u64,
  per_second: f64,
  used: &mut HashSet<u64>
) -> Result<(u64, [EdwardsPoint; 2]), RpcError> {
  let mut o;
  let mut output = None;
  while {
    let mut age = GAMMA.sample(rng).exp();
    if age > TIP_APPLICATION {
      age -= TIP_APPLICATION;
    } else {
      age = (rng.next_u64() % u64::try_from(RECENT_WINDOW * BLOCK_TIME).unwrap()) as f64;
    }

    o = (age * per_second) as u64;
    (o >= high) || {
      o = high - 1 - o;
      let i = distribution.partition_point(|s| *s < o);
      let prev = if i == 0 { 0 } else { i - 1 };
      let n = distribution[i] - distribution[prev];
      o = distribution[prev] + (rng.next_u64() % n);
      (n == 0) || used.contains(&o) || {
        output = rpc.get_outputs(&[o], height).await?[0];
        output.is_none()
      }
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

  let distribution = rpc.get_output_distribution(height).await?;
  let high = distribution[distribution.len() - 1];
  let per_second = {
    let blocks = distribution.len().min(BLOCKS_PER_YEAR);
    let outputs = high - distribution[distribution.len().saturating_sub(blocks + 1)];
    (outputs as f64) / ((blocks * BLOCK_TIME) as f64)
  };

  let mut used = HashSet::<u64>::new();
  for o in &outputs {
    used.insert(o.0);
  }

  let mut res = Vec::with_capacity(inputs.len());
  for (i, o) in outputs.iter().enumerate() {
    let mut mixins = Vec::with_capacity(MIXINS);
    for _ in 0 .. MIXINS {
      mixins.push(select_single(rng, rpc, height, &distribution, high, per_second, &mut used).await?);
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
        mixins[m] = select_single(rng, rpc, height, &distribution, high, per_second, &mut used).await?;
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
