#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(all(zalloc_rustc_nightly, feature = "allocator"), feature(allocator_api))]

//! Implementation of a Zeroizing Allocator, enabling zeroizing memory on deallocation.
//! This can either be used with Box (requires nightly and the "allocator" feature) to provide the
//! functionality of zeroize on types which don't implement zeroize, or used as a wrapper around
//! the global allocator to ensure *all* memory is zeroized.

use core::{
  slice,
  alloc::{Layout, GlobalAlloc},
};

use zeroize::Zeroize;

/// An allocator wrapper which zeroizes its memory on dealloc.
pub struct ZeroizingAlloc<T>(pub T);

#[cfg(all(zalloc_rustc_nightly, feature = "allocator"))]
use core::{
  ptr::NonNull,
  alloc::{AllocError, Allocator},
};
#[cfg(all(zalloc_rustc_nightly, feature = "allocator"))]
unsafe impl<T: Allocator> Allocator for ZeroizingAlloc<T> {
  fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
    self.0.allocate(layout)
  }

  unsafe fn deallocate(&self, mut ptr: NonNull<u8>, layout: Layout) {
    slice::from_raw_parts_mut(ptr.as_mut(), layout.size()).zeroize();
    self.0.deallocate(ptr, layout);
  }
}

unsafe impl<T: GlobalAlloc> GlobalAlloc for ZeroizingAlloc<T> {
  unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
    self.0.alloc(layout)
  }

  unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
    slice::from_raw_parts_mut(ptr, layout.size()).zeroize();
    self.0.dealloc(ptr, layout);
  }
}
