use core::alloc::{GlobalAlloc, Layout};

use crate::wdk;


struct PortmasterAllocator {}

unsafe impl Sync for PortmasterAllocator {}

unsafe impl GlobalAlloc for PortmasterAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        return wdk::malloc(layout.size());
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _: Layout) {
        return wdk::free(ptr);
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        return self.alloc(layout)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: the caller must ensure that the `new_size` does not overflow.
        // `layout.align()` comes from a `Layout` and is thus guaranteed to be valid.
        let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
        // SAFETY: the caller must ensure that `new_layout` is greater than zero.
        let new_ptr = unsafe { self.alloc(new_layout) };
        if !new_ptr.is_null() {
            // SAFETY: the previously allocated block cannot overlap the newly allocated block.
            // The safety contract for `dealloc` must be upheld by the caller.
            unsafe {
                core::ptr::copy_nonoverlapping(ptr, new_ptr, core::cmp::min(layout.size(), new_size));
                self.dealloc(ptr, layout);
            }
        }
        new_ptr
    }
}

// Declaration of the global memory allocator
#[global_allocator]
static HEAP: PortmasterAllocator = PortmasterAllocator {};
