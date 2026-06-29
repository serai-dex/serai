#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
#![no_std]
#![cfg_attr(all(zalloc_rustc_nightly, feature = "allocator"), feature(allocator_api))]

use core::{
  slice,
  alloc::{Layout, GlobalAlloc},
};

use zeroize::Zeroize as _;

/// An allocator which zeroizes all memory on deallocation.
///
/// This will only zeroize the memory corresponding to the pointer and the associated
/// [`Layout::size`]. This _assumes_ the underlying allocator will never inspect memory being
/// deallocated _except_ as outside of this layout.
pub struct ZeroizingAlloc<A>(A);

impl<A> ZeroizingAlloc<A> {
  /// Wrap an existing allocator into one which zeroizes memory before deallocating.
  pub const fn wrap(allocator: A) -> Self {
    Self(allocator)
  }
}

unsafe impl<A: GlobalAlloc> GlobalAlloc for ZeroizingAlloc<A> {
  unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
    self.0.alloc(layout)
  }

  unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
    slice::from_raw_parts_mut(ptr, layout.size()).zeroize();
    self.0.dealloc(ptr, layout);
  }
}

#[cfg(all(zalloc_rustc_nightly, feature = "allocator"))]
use core::{
  ptr::NonNull,
  alloc::{AllocError, Allocator},
};
#[cfg(all(zalloc_rustc_nightly, feature = "allocator"))]
unsafe impl<A: Allocator> Allocator for ZeroizingAlloc<A> {
  fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
    self.0.allocate(layout)
  }

  unsafe fn deallocate(&self, mut ptr: NonNull<u8>, layout: Layout) {
    slice::from_raw_parts_mut(ptr.as_mut(), layout.size()).zeroize();
    self.0.deallocate(ptr, layout);
  }
}
