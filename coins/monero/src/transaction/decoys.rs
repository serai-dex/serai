use std::collections::HashSet;

use lazy_static::lazy_static;

use rand_core::{RngCore, CryptoRng};
use rand_distr::{Distribution, Gamma};

use curve25519_dalek::edwards::EdwardsPoint;

use monero::VarInt;

use crate::{transaction::SpendableOutput, rpc::{RpcError, Rpc}};

const LOCK_WINDOW: usize = 10;
const MATURITY: u64 = 60;
const RECENT_WINDOW: usize = 15;
const BLOCK_TIME: usize = 120;
const BLOCKS_PER_YEAR: usize = 365 * 24 * 60 * 60 / BLOCK_TIME;
const TIP_APPLICATION: f64 = (LOCK_WINDOW * BLOCK_TIME) as f64;

const DECOYS: usize = 11;

lazy_static! {
  static ref GAMMA: Gamma<f64> = Gamma::new(19.28, 1.0 / 1.61).unwrap();
}

async fn select_n<R: RngCore + CryptoRng>(
  rng: &mut R,
  rpc: &Rpc,
  height: usize,
  distribution: &[u64],
  high: u64,
  per_second: f64,
  used: &mut HashSet<u64>,
  count: usize
) -> Result<Vec<(u64, [EdwardsPoint; 2])>, RpcError> {
  // Panic if not enough decoys are available
  // TODO: Simply create a TX with less than the target amount
  if (high - MATURITY) < u64::try_from(DECOYS).unwrap() {
    panic!("Not enough decoys available");
  }

  let mut confirmed = Vec::with_capacity(count);
  while confirmed.len() != count {
    let remaining = count - confirmed.len();
    let mut candidates = Vec::with_capacity(remaining);
    while candidates.len() != remaining {
      // Use a gamma distribution
      let mut age = GAMMA.sample(rng).exp();
      if age > TIP_APPLICATION {
        age -= TIP_APPLICATION;
      } else {
        // f64 does not have try_from available, which is why these are written with `as`
        age = (rng.next_u64() % u64::try_from(RECENT_WINDOW * BLOCK_TIME).unwrap()) as f64;
      }

      let o = (age * per_second) as u64;
      if o < high {
        let i = distribution.partition_point(|s| *s < (high - 1 - o));
        let prev = i.saturating_sub(1);
        let n = distribution[i] - distribution[prev];
        if n != 0 {
          let o = distribution[prev] + (rng.next_u64() % n);
          if !used.contains(&o) {
            // It will either actually be used, or is unusable and this prevents trying it again
            used.insert(o);
            candidates.push(o);
          }
        }
      }
    }

    let outputs = rpc.get_outputs(&candidates, height).await?;
    for i in 0 .. outputs.len() {
      if let Some(output) = outputs[i] {
        confirmed.push((candidates[i], output));
      }
    }
  }

  Ok(confirmed)
}

// Uses VarInt as this is solely used for key_offsets which is serialized by monero-rs
fn offset(decoys: &[u64]) -> Vec<VarInt> {
  let mut res = vec![VarInt(decoys[0])];
  res.resize(decoys.len(), VarInt(0));
  for m in (1 .. decoys.len()).rev() {
    res[m] = VarInt(decoys[m] - decoys[m - 1]);
  }
  res
}

#[derive(Clone, Debug)]
pub struct Decoys {
  pub i: u8,
  pub offsets: Vec<VarInt>,
  pub ring: Vec<[EdwardsPoint; 2]>
}

impl Decoys {
  pub fn len(&self) -> usize {
    self.offsets.len()
  }
}

pub(crate) async fn select<R: RngCore + CryptoRng>(
  rng: &mut R,
  rpc: &Rpc,
  height: usize,
  inputs: &[SpendableOutput]
) -> Result<Vec<Decoys>, RpcError> {
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
    // If there's only the target amount of decoys available, remove the index of the output we're spending
    // So we don't infinite loop while ignoring it
    // TODO: If we're spending 2 outputs of a possible 11 outputs, this will still fail
    used.remove(&o.0);

    // Select the full amount of ring members in decoys, instead of just the actual decoys, in order
    // to increase sample size
    let mut decoys = select_n(rng, rpc, height, &distribution, high, per_second, &mut used, DECOYS).await?;
    decoys.sort_by(|a, b| a.0.cmp(&b.0));

    // Add back this output
    used.insert(o.0);

    // Make sure the TX passes the sanity check that the median output is within the last 40%
    // This actually checks the median is within the last third, a slightly more aggressive boundary,
    // as the height used in this calculation will be slightly under the height this is sanity
    // checked against
    let target_median = high * 2 / 3;

    // Sanity checks are only run when 1000 outputs are available
    // We run this check whenever it's possible to satisfy
    // This means we need the middle possible decoy to be above the target_median
    // TODO: This will break if timelocks are used other than maturity on very small chains/chains
    // of any size which use timelocks extremely frequently, as it'll try to satisfy an impossible
    // condition
    // Reduce target_median by each timelocked output found?
    if (high - MATURITY) >= target_median {
      while decoys[DECOYS / 2].0 < target_median {
        // If it's not, update the bottom half with new values to ensure the median only moves up
        for m in 0 .. DECOYS / 2 {
          // We could not remove this, saving CPU time and removing low values as possibilities, yet
          // it'd increase the amount of decoys required to create this transaction and some banned
          // outputs may be the best options
          used.remove(&decoys[m].0);
        }

        decoys.splice(
          0 .. DECOYS / 2,
          select_n(rng, rpc, height, &distribution, high, per_second, &mut used, DECOYS / 2).await?
        );
        decoys.sort_by(|a, b| a.0.cmp(&b.0));
      }
    }

    // Replace the closest selected decoy with the actual
    let mut replace = 0;
    let mut distance = u64::MAX;
    for m in 0 .. decoys.len() {
      let diff = decoys[m].0.abs_diff(o.0);
      if diff < distance {
        replace = m;
        distance = diff;
      }
    }

    decoys[replace] = outputs[i];
    res.push(Decoys {
      i: u8::try_from(replace).unwrap(),
      offsets: offset(&decoys.iter().map(|output| output.0).collect::<Vec<_>>()),
      ring: decoys.iter().map(|output| output.1).collect()
    });
  }

  Ok(res)
}
