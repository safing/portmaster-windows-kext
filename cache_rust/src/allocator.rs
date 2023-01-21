use core::alloc::{GlobalAlloc, Layout};


extern {
    pub fn portmasterMalloc(size: usize, paged: bool) -> *mut u8;
    pub fn portmasterFree(ptr: *mut u8);
}

struct PortmasterAllocator {}

unsafe impl Sync for PortmasterAllocator {}

unsafe impl GlobalAlloc for PortmasterAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        return portmasterMalloc(layout.size(), false);
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _: Layout) {
        return portmasterFree(ptr);
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

#[alloc_error_handler]
fn alloc_error(_layout: core::alloc::Layout) -> ! {
    //panic!("memory allocation of {} bytes failed", layout.size())
    loop {}
}
