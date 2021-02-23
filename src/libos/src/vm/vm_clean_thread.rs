use super::*;
use crate::libc::{pthread_attr_t, pthread_t};
use crate::process::table::{get_all_processes, get_all_threads};
use async_rt::task::JoinHandle;
use core::mem;
use core::ptr;
use flume::{Receiver, Sender};
use std::sync::atomic::{AtomicBool, Ordering};

// pub static mut VM_CLEAN_THREAD_RUNNING: AtomicBool = AtomicBool::new(false);
const MAX_QUEUED_MEMSET_REQS: usize = 1_000;

lazy_static! {
// Clean all munmapped ranges before exit
    // pub static ref VM_CLEAN_DONE: Arc<SgxMutex<bool>> = Arc::new(SgxMutex::new(false)); // safe between threads
    pub static ref MPMC: (Sender<VMRange>, Receiver<VMRange>) = flume::bounded(MAX_QUEUED_MEMSET_REQS);
    pub static ref CLEAN_REQ_QUEUE: &'static Sender<VMRange> = &(*MPMC).0;
    pub static ref CLEAN_RUNNER: &'static Receiver<VMRange> = &(*MPMC).1;
}

pub fn init_vm_clean_thread() -> Result<()> {
    // unsafe { *VM_CLEAN_THREAD_RUNNING.get_mut() = true };
    async_rt::task::spawn(mem_worker_thread_func());
    Ok(())
}

async fn mem_worker_thread_func() {
    // let (tx, rx) = flume::bounded(MAX_QUEUED_MEMSET_REQS);
    mem_worker_thread_func_inner().await;
}

async fn mem_worker_thread_func_inner() -> Result<()> {
    // let mut done = *VM_CLEAN_DONE.lock().unwrap();
    while let Ok(req) = CLEAN_RUNNER.recv_async().await {
        USER_SPACE_VM_MANAGER
            .vm_manager()
            .clean_dirty_range_in_bgthread(req)?;
    }
    // this never reaches
    assert!(CLEAN_RUNNER.is_empty() == true);
    // while unsafe { VM_CLEAN_THREAD_RUNNING.load(Ordering::Relaxed) } {
    //     let all_process = get_all_processes();
    //     for process in all_process.iter() {
    //         if let Some(thread) = process.main_thread() {
    //             thread
    //                 .vm()
    //                 .get_mmap_manager()
    //                 .clean_dirty_range_in_bgthread()?;
    //         }
    //     }
    // }
    //let mut done = VM_CLEAN_DONE.lock().unwrap();
    // done = true;
    // drop(done);
    println!("vm clean thread really exit");
    Ok(())
}

// extern "C" {
//     fn pthread_create(
//         native: *mut pthread_t,
//         attr: *const pthread_attr_t,
//         f: extern "C" fn(*mut c_void) -> *mut c_void,
//         value: *mut c_void,
//     ) -> c_int;
// }
