use core::{ffi::c_void, ptr};


extern "C" {
    fn KeInitializeSpinLock(lock: *mut KSpinLock);
    fn KeAcquireInStackQueuedSpinLock(handle: *mut KSpinLock, lock: *mut KLockQueueHandle);
    fn KeReleaseInStackQueuedSpinLock(handle: *mut KLockQueueHandle); 
}

// Copy of KSPIN_LOCK_QUEUE WDK C struct
#[repr(C)]
#[allow(dead_code)]
struct KSpinLockQueue { // 
    next: *mut c_void, // struct _KSPIN_LOCK_QUEUE * volatile Next;
    lock: *mut c_void, // PKSPIN_LOCK volatile Lock;
}

// Copy of KLOCK_QUEUE_HANDLE WDK C struct
#[repr(C)]
#[allow(dead_code)]
pub struct KLockQueueHandle {
    lock_queue: KSpinLockQueue, // KSPIN_LOCK_QUEUE LockQueue;
    old_irql: u8, // KIRQL OldIrql;
}

// Copy of KSpinLock WDK C struct
#[repr(C)]
pub struct KSpinLock {
    ptr: *mut c_void,
}

impl KSpinLock {
    pub fn create() -> Self {
        unsafe {
            let mut p: KSpinLock = KSpinLock { ptr: ptr::null_mut() };
            KeInitializeSpinLock(ptr::addr_of_mut!(p));
            return p;
        }
    }

    pub fn lock(&mut self) -> KLockQueueHandle {
        let mut handle = KLockQueueHandle { lock_queue: KSpinLockQueue { next: ptr::null_mut(), lock: ptr::null_mut() }, old_irql: 0 };
        unsafe {
            KeAcquireInStackQueuedSpinLock(self, &mut handle);
        }

        return handle;
    }
}

impl Drop for KLockQueueHandle {
    fn drop(&mut self) {
        unsafe {
            KeReleaseInStackQueuedSpinLock(self as *mut KLockQueueHandle);
        }
    }
}