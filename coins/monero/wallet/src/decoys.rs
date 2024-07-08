// TODO: Clean this

use std_shims::{io, vec::Vec, collections::HashSet};

use zeroize::{Zeroize, ZeroizeOnDrop};

use rand_core::{RngCore, CryptoRng};
use rand_distr::{Distribution, Gamma};
#[cfg(not(feature = "std"))]
use rand_distr::num_traits::Float;

use curve25519_dalek::{Scalar, EdwardsPoint};

use crate::{
  DEFAULT_LOCK_WINDOW, COINBASE_LOCK_WINDOW, BLOCK_TIME,
  primitives::Commitment,
  rpc::{RpcError, Rpc},
  output::OutputData,
  WalletOutput,
};

const RECENT_WINDOW: usize = 15;
const BLOCKS_PER_YEAR: usize = 365 * 24 * 60 * 60 / BLOCK_TIME;
#[allow(clippy::cast_precision_loss)]
const TIP_APPLICATION: f64 = (DEFAULT_LOCK_WINDOW * BLOCK_TIME) as f64;

#[allow(clippy::too_many_arguments)]
async fn select_n<'a, R: RngCore + CryptoRng>(
  rng: &mut R,
  rpc: &impl Rpc,
  distribution: &[u64],
  height: usize,
  high: u64,
  per_second: f64,
  real: &[u64],
  used: &mut HashSet<u64>,
  count: usize,
  fingerprintable_canonical: bool,
) -> Result<Vec<(u64, [EdwardsPoint; 2])>, RpcError> {
  // TODO: consider removing this extra RPC and expect the caller to handle it
  if fingerprintable_canonical && (height > rpc.get_height().await?) {
    // TODO: Don't use InternalError for the caller's failure
    Err(RpcError::InternalError("decoys being requested from too young blocks".to_string()))?;
  }

  #[cfg(test)]
  let mut iters = 0;
  let mut confirmed = Vec::with_capacity(count);
  // Retries on failure. Retries are obvious as decoys, yet should be minimal
  while confirmed.len() != count {
    let remaining = count - confirmed.len();
    // TODO: over-request candidates in case some are locked to avoid needing
    // round trips to the daemon (and revealing obvious decoys to the daemon)
    let mut candidates = Vec::with_capacity(remaining);
    while candidates.len() != remaining {
      #[cfg(test)]
      {
        iters += 1;
        // This is cheap and on fresh chains, a lot of rounds may be needed
        if iters == 100 {
          Err(RpcError::InternalError("hit decoy selection round limit".to_string()))?;
        }
      }

      // Use a gamma distribution
      let mut age = Gamma::<f64>::new(19.28, 1.0 / 1.61).unwrap().sample(rng).exp();
      #[allow(clippy::cast_precision_loss)]
      if age > TIP_APPLICATION {
        age -= TIP_APPLICATION;
      } else {
        // f64 does not have try_from available, which is why these are written with `as`
        age = (rng.next_u64() % u64::try_from(RECENT_WINDOW * BLOCK_TIME).unwrap()) as f64;
      }

      #[allow(clippy::cast_sign_loss, clippy::cast_possible_truncation)]
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

    // TODO: make sure that the real output is included in the response, and
    // that mask and key are equal to expected
    for (i, output) in rpc
      .get_unlocked_outputs(&candidates, height, fingerprintable_canonical)
      .await?
      .iter_mut()
      .enumerate()
    {
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

async fn select_decoys<R: RngCore + CryptoRng>(
  rng: &mut R,
  rpc: &impl Rpc,
  ring_len: usize,
  height: usize,
  input: &WalletOutput,
  fingerprintable_canonical: bool,
) -> Result<Decoys, RpcError> {
  let mut distribution = vec![];

  let decoy_count = ring_len - 1;

  // Convert the inputs in question to the raw output data
  let mut real = vec![input.relative_id.index_on_blockchain];
  let output = (real[0], [input.key(), input.commitment().calculate()]);

  if distribution.len() < height {
    // TODO: verify distribution elems are strictly increasing
    let extension = rpc.get_output_distribution(distribution.len() .. height).await?;
    distribution.extend(extension);
  }
  // If asked to use an older height than previously asked, truncate to ensure accuracy
  // Should never happen, yet risks desyncing if it did
  distribution.truncate(height);

  if distribution.len() < DEFAULT_LOCK_WINDOW {
    Err(RpcError::InternalError("not enough blocks to select decoys".to_string()))?;
  }

  #[allow(clippy::cast_precision_loss)]
  let per_second = {
    let blocks = distribution.len().min(BLOCKS_PER_YEAR);
    let initial = distribution[distribution.len().saturating_sub(blocks + 1)];
    let outputs = distribution[distribution.len() - 1].saturating_sub(initial);
    (outputs as f64) / ((blocks * BLOCK_TIME) as f64)
  };

  let mut used = HashSet::<u64>::new();
  used.insert(output.0);

  // TODO: Create a TX with less than the target amount, as allowed by the protocol
  let high = distribution[distribution.len() - DEFAULT_LOCK_WINDOW];
  // This assumes that each miner TX had one output (as sane) and checks we have sufficient
  // outputs even when excluding them (due to their own timelock requirements)
  if high.saturating_sub(u64::try_from(COINBASE_LOCK_WINDOW).unwrap()) <
    u64::try_from(ring_len).unwrap()
  {
    Err(RpcError::InternalError("not enough decoy candidates".to_string()))?;
  }

  // Select all decoys for this transaction, assuming we generate a sane transaction
  // We should almost never naturally generate an insane transaction, hence why this doesn't
  // bother with an overage
  let mut decoys = select_n(
    rng,
    rpc,
    &distribution,
    height,
    high,
    per_second,
    &real,
    &mut used,
    decoy_count,
    fingerprintable_canonical,
  )
  .await?;
  real.zeroize();

  // Grab the decoys for this specific output
  let mut ring = decoys.drain((decoys.len() - decoy_count) ..).collect::<Vec<_>>();
  ring.push(output);
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
        if removed.0 == output.0 {
          ring.push(output);
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
        select_n(
          rng,
          rpc,
          &distribution,
          height,
          high,
          per_second,
          &[],
          &mut used,
          ring_len - ring.len(),
          fingerprintable_canonical,
        )
        .await?,
      );
      ring.sort_by(|a, b| a.0.cmp(&b.0));
    }

    // The other sanity check rule is about duplicates, yet we already enforce unique ring
    // members
  }

  Ok(
    Decoys::new(
      offset(&ring.iter().map(|output| output.0).collect::<Vec<_>>()),
      // Binary searches for the real spend since we don't know where it sorted to
      u8::try_from(ring.partition_point(|x| x.0 < output.0)).unwrap(),
      ring.iter().map(|output| output.1).collect(),
    )
    .unwrap(),
  )
}

pub use monero_serai::primitives::Decoys;

/// An output with decoys selected.
#[derive(Clone, PartialEq, Eq, Debug, Zeroize, ZeroizeOnDrop)]
pub struct OutputWithDecoys {
  output: OutputData,
  decoys: Decoys,
}

impl OutputWithDecoys {
  /// Select decoys for this output.
  pub async fn new(
    rng: &mut (impl Send + Sync + RngCore + CryptoRng),
    rpc: &impl Rpc,
    ring_len: usize,
    height: usize,
    output: WalletOutput,
  ) -> Result<OutputWithDecoys, RpcError> {
    let decoys = select_decoys(rng, rpc, ring_len, height, &output, false).await?;
    Ok(OutputWithDecoys { output: output.data.clone(), decoys })
  }

  /// Select a set of decoys for this output with a deterministic process.
  ///
  /// This function will always output the same set of decoys when called with the same arguments.
  /// This makes it very useful in multisignature contexts, where instead of having one participant
  /// select the decoys, everyone can locally select the decoys while coming to the same result.
  ///
  /// The set of decoys selected may be fingerprintable as having been produced by this
  /// methodology.
  pub async fn fingerprintable_deterministic_new(
    rng: &mut (impl Send + Sync + RngCore + CryptoRng),
    rpc: &impl Rpc,
    ring_len: usize,
    height: usize,
    output: WalletOutput,
  ) -> Result<OutputWithDecoys, RpcError> {
    let decoys = select_decoys(rng, rpc, ring_len, height, &output, true).await?;
    Ok(OutputWithDecoys { output: output.data.clone(), decoys })
  }

  /// The key this output may be spent by.
  pub fn key(&self) -> EdwardsPoint {
    self.output.key()
  }

  /// The scalar to add to the private spend key for it to be the discrete logarithm of this
  /// output's key.
  pub fn key_offset(&self) -> Scalar {
    self.output.key_offset
  }

  /// The commitment this output created.
  pub fn commitment(&self) -> &Commitment {
    &self.output.commitment
  }

  /// The decoys this output selected.
  pub fn decoys(&self) -> &Decoys {
    &self.decoys
  }

  /// Write the OutputWithDecoys.
  ///
  /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
  /// defined serialization.
  pub fn write<W: io::Write>(&self, w: &mut W) -> io::Result<()> {
    self.output.write(w)?;
    self.decoys.write(w)
  }

  /// Serialize the OutputWithDecoys to a `Vec<u8>`.
  ///
  /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
  /// defined serialization.
  pub fn serialize(&self) -> Vec<u8> {
    let mut serialized = Vec::with_capacity(128);
    self.write(&mut serialized).unwrap();
    serialized
  }

  /// Read an OutputWithDecoys.
  ///
  /// This is not a Monero protocol defined struct, and this is accordingly not a Monero protocol
  /// defined serialization.
  pub fn read<R: io::Read>(r: &mut R) -> io::Result<Self> {
    Ok(Self { output: OutputData::read(r)?, decoys: Decoys::read(r)? })
  }
}
