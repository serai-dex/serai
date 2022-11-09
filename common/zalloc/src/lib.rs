use core::{
  slice,
  alloc::{Layout, GlobalAlloc},
};

use zeroize::Zeroize;

pub struct ZeroizingAlloc<T: GlobalAlloc>(pub T);

unsafe impl<T: GlobalAlloc> GlobalAlloc for ZeroizingAlloc<T> {
  unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
    self.0.alloc(layout)
  }

  unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
    slice::from_raw_parts_mut(ptr, layout.size()).zeroize();
    self.0.dealloc(ptr, layout);
  }
}
