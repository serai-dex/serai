#[cfg(feature = "std")]
mod std {
  use core::{
    pin::Pin,
    task::{Poll, Context},
  };

  use std::collections::{hash_map::Entry, HashMap};

  use crate::{InvalidBlock, Block, Blockchain};

  struct IndexValue<B: Blockchain> {
    /// The hash of the block this validator last proposed.
    hash: <B::Block as Block>::Hash,
    /// Whether this block, proposed by this validator, was fatally invalid.
    fatal: bool,
  }
  type IndexEntry<'map, B> = Entry<'map, <B as Blockchain>::Validator, IndexValue<B>>;

  struct CacheValue {
    /// The amount of times this block has been proposed _by distinct validators_ and been valid.
    ///
    /// Note if this was ever cached as valid, any future occurrences of this block will
    /// automatically be considered valid, independently of who proposes it.
    count: u16,
  }
  type CacheEntry<'map, B> = Entry<'map, <<B as Blockchain>::Block as Block>::Hash, CacheValue>;

  pub(crate) struct BlockValidityCache<B: Blockchain> {
    index: HashMap<<B as Blockchain>::Validator, IndexValue<B>>,
    cache: HashMap<<<B as Blockchain>::Block as Block>::Hash, CacheValue>,
  }

  pin_project_lite::pin_project! {
    #[project = ValidateBlockProjection]
    pub(crate) enum ValidateBlock<'cache, B: Blockchain> {
      CacheHit { result: Result<(), InvalidBlock> },
      CacheMiss {
        proposal_hash: <B::Block as Block>::Hash,
        entries: Option<(IndexEntry<'cache, B>, CacheEntry<'cache, B>)>,
        #[pin]
        future: B::Validate,
      }
    }
  }

  impl<B: Blockchain> BlockValidityCache<B> {
    #[must_use]
    pub(crate) fn with_capacity(capacity: usize) -> Self {
      Self { index: HashMap::with_capacity(capacity), cache: HashMap::with_capacity(capacity) }
    }

    pub(crate) fn clear(&mut self) {
      let Self { index, cache } = self;
      index.clear();
      cache.clear();
    }

    pub(crate) fn validate_block<'cache>(
      &'cache mut self,
      blockchain: &mut B,
      proposer: B::Validator,
      block: &B::Block,
    ) -> ValidateBlock<'cache, B> {
      let proposal_hash = block.proposal_hash();
      let Self { index, cache } = self;

      let index = index.entry(proposer);
      let was_distinct = if let Entry::Occupied(index) = &index {
        let IndexValue { fatal, hash } = index.get();
        if *fatal {
          /*
            If the proposer prior proposed this block, and it was fatally invalid, it's still
            fatally invalid per the documentation on `InvalidBlock::Fatal`.
          */
          if (*hash) == proposal_hash {
            return ValidateBlock::CacheHit { result: Err(InvalidBlock::Fatal) };
          }
          /*
            If this is a _different_ block which was fatally invalid, this validator's index was to
            a distinct block.
          */
          true
        } else if (*hash) == proposal_hash {
          // If this wasn't fatally invalid, and is for the same block, it isn't distinct
          false
        } else {
          /*
            Because this was not fatally invalid, and was for a distinct block, there is a cached
            validity entry. We need to decrement its reference count.
          */
          let Entry::Occupied(mut entry) = cache.entry(*hash) else {
            panic!("indexed value without cache result")
          };
          if entry.get_mut().count == 0 {
            entry.remove();
          } else {
            entry.get_mut().count -= 1;
          }
          true
        }
      } else {
        // If this proposer doesn't have an indexed block, this block is distinct
        true
      };

      /*
        If the block is in the cache, it was valid, and we have a cache hit.

        This does mean a proposer from which any block is fatally invalid may be able to
        successfully propose a block, if it was valid when prior proposed by a distinct validator.
        Such semantics are allowed by the bounds on [`Blockchain::validate`].
      */
      let mut cache = cache.entry(proposal_hash);
      if let Entry::Occupied(cache) = &mut cache {
        if was_distinct {
          cache.get_mut().count += 1;
        }
        return ValidateBlock::CacheHit { result: Ok(()) };
      }

      // Validate the block and cache the result, if possible
      let future = ValidateBlock::CacheMiss {
        proposal_hash,
        entries: Some((index, cache)),
        future: blockchain.validate(proposer, block),
      };

      impl<B: Blockchain> Future for ValidateBlock<'_, B> {
        type Output = Result<(), InvalidBlock>;
        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
          match self.project() {
            ValidateBlockProjection::CacheHit { result } => Poll::Ready(*result),
            ValidateBlockProjection::CacheMiss { proposal_hash, entries, future } => {
              let Poll::Ready(result) = future.poll(cx) else { return Poll::Pending };
              let (index, cache) =
                entries.take().expect("`ValidateBlock` polled after `Poll::Ready`");
              match result {
                Ok(()) => {
                  // If this was valid, populate the entries
                  index.insert_entry(IndexValue { hash: *proposal_hash, fatal: false });
                  cache.insert_entry(CacheValue { count: 0 });
                }
                // If this is temporally invalid, cache nothing, re-validate on the next instance
                Err(InvalidBlock::Temporal) => {}
                /*
                  If this was fatally invalid, mark this proposer's index but do not populate any
                  cache value. A block proposed by one proposer may be fatally invalid only until
                  it's proposed by a distinct proposer.
                */
                Err(InvalidBlock::Fatal) => {
                  index.insert_entry(IndexValue { hash: *proposal_hash, fatal: true });
                }
              }
              Poll::Ready(result)
            }
          }
        }
      }

      future
    }
  }
}
#[cfg(feature = "std")]
pub(super) use std::*;

// On no-`std`, fallback to a cache which doesn't cache anything
#[cfg(not(feature = "std"))]
mod no_std {
  use core::{
    marker::PhantomData,
    pin::Pin,
    task::{Poll, Context},
  };

  use crate::{InvalidBlock, Blockchain};

  pub(crate) struct BlockValidityCache<B: Blockchain>(PhantomData<B>);

  pin_project_lite::pin_project! {
    #[repr(transparent)]
    pub(crate) struct ValidateBlock<'cache, B: Blockchain> {
      #[pin]
      future: B::Validate,
      _phantom: PhantomData<&'cache mut B>
    }
  }

  impl<B: Blockchain> BlockValidityCache<B> {
    pub(crate) fn with_capacity(_capacity: usize) -> Self {
      Self(PhantomData)
    }

    pub(crate) fn clear(&mut self) {
      let _ = self;
    }

    pub(crate) fn validate_block<'cache>(
      &'cache mut self,
      blockchain: &mut B,
      proposer: B::Validator,
      block: &B::Block,
    ) -> ValidateBlock<'cache, B> {
      let _ = self;

      impl<B: Blockchain> Future for ValidateBlock<'_, B> {
        type Output = Result<(), InvalidBlock>;
        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
          self.project().future.poll(cx)
        }
      }

      ValidateBlock { future: blockchain.validate(proposer, block), _phantom: PhantomData }
    }
  }
}
#[cfg(not(feature = "std"))]
pub(super) use no_std::*;
