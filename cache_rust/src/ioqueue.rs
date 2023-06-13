use core::ptr;

use alloc::boxed::Box;
use windows_sys::{
    Wdk::Foundation::{DISPATCHER_HEADER, DISPATCHER_HEADER_0, DISPATCHER_HEADER_0_0, KQUEUE},
    Win32::System::Kernel::LIST_ENTRY,
};

extern "C" {
    fn KeInitializeQueue(queue: *mut IOQueue, arg: i32);
    fn KeRemoveQueue(queue: *mut IOQueue, mode: i32, timeout: *mut i64) -> LIST_ENTRY;
    fn KeRundownQueue(queue: *mut IOQueue) -> *mut LIST_ENTRY;
}

struct IOQueue {
    kernel_queue: KQUEUE,
}

impl IOQueue {
    fn new() -> Box<IOQueue> {
        let queue = Box::new(IOQueue {
            kernel_queue: KQUEUE {
                Header: DISPATCHER_HEADER {
                    Anonymous: DISPATCHER_HEADER_0 {
                        Anonymous1: DISPATCHER_HEADER_0_0 { Lock: 0 },
                    },
                    SignalState: 0,
                    WaitListHead: windows_sys::Win32::System::Kernel::LIST_ENTRY {
                        Flink: ptr::null_mut(),
                        Blink: ptr::null_mut(),
                    },
                },
                EntryListHead: windows_sys::Win32::System::Kernel::LIST_ENTRY {
                    Flink: ptr::null_mut(),
                    Blink: ptr::null_mut(),
                },
                CurrentCount: 0,
                MaximumCount: 0,
                ThreadListHead: windows_sys::Win32::System::Kernel::LIST_ENTRY {
                    Flink: ptr::null_mut(),
                    Blink: ptr::null_mut(),
                },
            },
        });

        unsafe {
            KeInitializeQueue(Box::into_raw(queue), 1);
        }

        return queue;
    }
}
