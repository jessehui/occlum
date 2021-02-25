use super::*;
use crate::libc::{pthread_attr_t, pthread_t};
use crate::process::table::{get_all_processes, get_all_threads};
use async_rt::task::JoinHandle;
use core::mem;
use core::ptr;
use flume::{Receiver, Sender};
use std::sync::atomic::{AtomicBool, Ordering};

const MAX_QUEUED_MEMSET_REQS: usize = 10_000;

lazy_static! {
    pub static ref MPMC: (Sender<VMRange>, Receiver<VMRange>) = flume::unbounded();
    pub static ref CLEAN_REQ_QUEUE: &'static Sender<VMRange> = &(*MPMC).0;
    pub static ref CLEAN_RUNNER: &'static Receiver<VMRange> = &(*MPMC).1;
}
enum LiveTime {
    Global,
    Temporal,
}

pub fn init_vm_clean_thread() -> Result<()> {
    async_rt::task::spawn(mem_worker_thread_func(LiveTime::Global));
    // async_rt::task::spawn(mem_worker_thread_func(LiveTime::Global));
    Ok(())
}

pub fn create_tmp_vm_clean_thread() -> Result<()> {
    async_rt::task::spawn(mem_worker_thread_func(LiveTime::Temporal));
    Ok(())
}

// This will exit when the channel is empty
pub fn become_clean_thread() -> Result<()> {
    mem_worker_thread_func_tmp();
    Ok(())
}

async fn mem_worker_thread_func(live_time: LiveTime) {
    match live_time {
        LiveTime::Global => mem_worker_thread_func_global().await,
        LiveTime::Temporal => mem_worker_thread_func_tmp(),
    };
}

async fn mem_worker_thread_func_global() -> Result<()> {
    // let mut done = *VM_CLEAN_DONE.lock().unwrap();
    // let runner = CLEAN_RUNNER.clone();
    while let Ok(req) = CLEAN_RUNNER.recv_async().await {
        USER_SPACE_VM_MANAGER.vm_manager().clean_dirty_range(req)?;
        // println!("global cleaning thread is cleaning");
    }
    // this never reaches
    assert!(CLEAN_RUNNER.is_empty() == true);
    println!("vm clean thread really exit");
    Ok(())
}

fn mem_worker_thread_func_tmp() -> Result<()> {
    // let mut done = *VM_CLEAN_DONE.lock().unwrap();
    let tmp_runner = CLEAN_RUNNER.clone();
    while let Ok(req) = tmp_runner.try_recv() {
        USER_SPACE_VM_MANAGER.vm_manager().clean_dirty_range(req)?;
        // println!("a tmp thread is help cleaning");
    }
    // println!("tmp runner exit");
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
