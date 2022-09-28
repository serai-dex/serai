use std::{sync::Mutex, collections::HashSet};

use lazy_static::lazy_static;

use rand_core::{RngCore, CryptoRng};
use rand_distr::{Distribution, Gamma};

use zeroize::{Zeroize, ZeroizeOnDrop};

use curve25519_dalek::edwards::EdwardsPoint;

use crate::{
  wallet::SpendableOutput,
  rpc::{RpcError, Rpc},
};

const LOCK_WINDOW: usize = 10;
const MATURITY: u64 = 60;
const RECENT_WINDOW: usize = 15;
const BLOCK_TIME: usize = 120;
const BLOCKS_PER_YEAR: usize = 365 * 24 * 60 * 60 / BLOCK_TIME;
const TIP_APPLICATION: f64 = (LOCK_WINDOW * BLOCK_TIME) as f64;

lazy_static! {
  static ref GAMMA: Gamma<f64> = Gamma::new(19.28, 1.0 / 1.61).unwrap();
  static ref DISTRIBUTION: Mutex<Vec<u64>> = Mutex::new(Vec::with_capacity(3000000));
}

#[allow(clippy::too_many_arguments)]
async fn select_n<R: RngCore + CryptoRng>(
  rng: &mut R,
  rpc: &Rpc,
  height: usize,
  high: u64,
  per_second: f64,
  real: &[u64],
  used: &mut HashSet<u64>,
  count: usize,
) -> Result<Vec<(u64, [EdwardsPoint; 2])>, RpcError> {
  let mut iters = 0;
  let mut confirmed = Vec::with_capacity(count);
  // Retries on failure. Retries are obvious as decoys, yet should be minimal
  while confirmed.len() != count {
    let remaining = count - confirmed.len();
    let mut candidates = Vec::with_capacity(remaining);
    while candidates.len() != remaining {
      iters += 1;
      // This is cheap and on fresh chains, thousands of rounds may be needed
      if iters == 10000 {
        Err(RpcError::InternalError("not enough decoy candidates".to_string()))?;
      }

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
        let distribution = DISTRIBUTION.lock().unwrap();
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

    // If this is the first time we're requesting these outputs, include the real one as well
    // Prevents the node we're connected to from having a list of known decoys and then seeing a
    // TX which uses all of them, with one additional output (the true spend)
    let mut real_indexes = HashSet::with_capacity(real.len());
    if confirmed.is_empty() {
      for real in real {
        candidates.push(*real);
      }
      // Sort candidates so the real spends aren't the ones at the end
      candidates.sort();
      for real in real {
        real_indexes.insert(candidates.binary_search(real).unwrap());
      }
    }

    for (i, output) in rpc.get_unlocked_outputs(&candidates, height).await?.iter_mut().enumerate() {
      // Don't include the real spend as a decoy, despite requesting it
      if real_indexes.contains(&i) {
        continue;
      }

      if let Some(output) = output.take() {
        confirmed.push((candidates[i], output));
      }
    }
  }

  Ok(confirmed)
}

fn offset(ring: &[u64]) -> Vec<u64> {
  let mut res = vec![ring[0]];
  res.resize(ring.len(), 0);
  for m in (1 .. ring.len()).rev() {
    res[m] = ring[m] - ring[m - 1];
  }
  res
}

/// Decoy data, containing the actual member as well (at index `i`).
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct Decoys {
  pub i: u8,
  pub offsets: Vec<u64>,
  pub ring: Vec<[EdwardsPoint; 2]>,
}

impl Decoys {
  pub fn len(&self) -> usize {
    self.offsets.len()
  }

  /// Select decoys using the same distribution as Monero.
  pub async fn select<R: RngCore + CryptoRng>(
    rng: &mut R,
    rpc: &Rpc,
    ring_len: usize,
    height: usize,
    inputs: &[SpendableOutput],
  ) -> Result<Vec<Decoys>, RpcError> {
    let decoy_count = ring_len - 1;

    // Convert the inputs in question to the raw output data
    let mut real = Vec::with_capacity(inputs.len());
    let mut outputs = Vec::with_capacity(inputs.len());
    for input in inputs {
      real.push(input.global_index);
      outputs.push((real[real.len() - 1], [input.key(), input.commitment().calculate()]));
    }

    let distribution_len = {
      let distribution = DISTRIBUTION.lock().unwrap();
      distribution.len()
    };
    if distribution_len <= height {
      let extension = rpc.get_output_distribution(distribution_len, height).await?;
      DISTRIBUTION.lock().unwrap().extend(extension);
    }

    let high;
    let per_second;
    {
      let mut distribution = DISTRIBUTION.lock().unwrap();
      // If asked to use an older height than previously asked, truncate to ensure accuracy
      // Should never happen, yet risks desyncing if it did
      distribution.truncate(height + 1); // height is inclusive, and 0 is a valid height

      high = distribution[distribution.len() - 1];
      per_second = {
        let blocks = distribution.len().min(BLOCKS_PER_YEAR);
        let outputs = high - distribution[distribution.len().saturating_sub(blocks + 1)];
        (outputs as f64) / ((blocks * BLOCK_TIME) as f64)
      };
    };

    let mut used = HashSet::<u64>::new();
    for o in &outputs {
      used.insert(o.0);
    }

    // TODO: Simply create a TX with less than the target amount
    if (high - MATURITY) < u64::try_from(inputs.len() * ring_len).unwrap() {
      Err(RpcError::InternalError("not enough decoy candidates".to_string()))?;
    }

    // Select all decoys for this transaction, assuming we generate a sane transaction
    // We should almost never naturally generate an insane transaction, hence why this doesn't
    // bother with an overage
    let mut decoys =
      select_n(rng, rpc, height, high, per_second, &real, &mut used, inputs.len() * decoy_count)
        .await?;
    real.zeroize();

    let mut res = Vec::with_capacity(inputs.len());
    for o in outputs {
      // Grab the decoys for this specific output
      let mut ring = decoys.drain((decoys.len() - decoy_count) ..).collect::<Vec<_>>();
      ring.push(o);
      ring.sort_by(|a, b| a.0.cmp(&b.0));

      // Sanity checks are only run when 1000 outputs are available in Monero
      // We run this check whenever the highest output index, which we acknowledge, is > 500
      // This means we assume (for presumably test blockchains) the height being used has not had
      // 500 outputs since while itself not being a sufficiently mature blockchain
      // Considering Monero's p2p layer doesn't actually check transaction sanity, it should be
      // fine for us to not have perfectly matching rules, especially since this code will infinite
      // loop if it can't determine sanity, which is possible with sufficient inputs on
      // sufficiently small chains
      if high > 500 {
        // Make sure the TX passes the sanity check that the median output is within the last 40%
        let target_median = high * 3 / 5;
        while ring[ring_len / 2].0 < target_median {
          // If it's not, update the bottom half with new values to ensure the median only moves up
          for removed in ring.drain(0 .. (ring_len / 2)).collect::<Vec<_>>() {
            // If we removed the real spend, add it back
            if removed.0 == o.0 {
              ring.push(o);
            } else {
              // We could not remove this, saving CPU time and removing low values as
              // possibilities, yet it'd increase the amount of decoys required to create this
              // transaction and some removed outputs may be the best option (as we drop the first
              // half, not just the bottom n)
              used.remove(&removed.0);
            }
          }

          // Select new outputs until we have a full sized ring again
          ring.extend(
            select_n(rng, rpc, height, high, per_second, &[], &mut used, ring_len - ring.len())
              .await?,
          );
          ring.sort_by(|a, b| a.0.cmp(&b.0));
        }

        // The other sanity check rule is about duplicates, yet we already enforce unique ring
        // members
      }

      res.push(Decoys {
        // Binary searches for the real spend since we don't know where it sorted to
        i: u8::try_from(ring.partition_point(|x| x.0 < o.0)).unwrap(),
        offsets: offset(&ring.iter().map(|output| output.0).collect::<Vec<_>>()),
        ring: ring.iter().map(|output| output.1).collect(),
      });
    }

    Ok(res)
  }
}
