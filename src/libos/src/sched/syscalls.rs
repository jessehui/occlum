use super::cpu_set::{CpuSet, AVAIL_CPUSET};
use crate::prelude::*;
use crate::util::mem_util::from_user::*;

pub fn do_sched_yield() -> Result<isize> {
    super::do_sched_yield::do_sched_yield();
    Ok(0)
}

extern "C" {
    fn occlum_ocall_sched_setaffinity(
        ret: *mut i32,
        host_tid: i32,
        cpusetsize: size_t,
        mask: *const c_uchar,
    ) -> sgx_status_t;
}

extern "C" {
    fn occlum_ocall_sched_getaffinity(
        ret: *mut i32,
        cpusetsize: size_t,
        mask: *mut c_uchar,
    ) -> sgx_status_t;
}

pub fn do_sched_getaffinity(pid: pid_t, buf_size: size_t, buf_ptr: *mut u8) -> Result<isize> {
    let mut retval = 0;
    let sgx_status = unsafe { occlum_ocall_sched_getaffinity(&mut retval, buf_size, buf_ptr) };
    assert!(sgx_status == sgx_status_t::SGX_SUCCESS);
    Ok(retval as isize)
}

pub fn do_sched_setaffinity(pid: pid_t, buf_size: size_t, buf_ptr: *const u8) -> Result<isize> {
    use crate::process::table;
    let thread = if pid == 0 {
        current!()
    } else {
        table::get_thread(pid)?
    };
    let host_tid = thread.sched().lock().unwrap().host_tid().unwrap();
    let mut retval = 0;
    let sgx_status =
        unsafe { occlum_ocall_sched_setaffinity(&mut retval, host_tid as i32, buf_size, buf_ptr) };
    assert!(sgx_status == sgx_status_t::SGX_SUCCESS);
    Ok(retval as isize)
}

pub fn do_getcpu(cpu_ptr: *mut u32, node_ptr: *mut u32) -> Result<isize> {
    // Do pointers check
    match (cpu_ptr.is_null(), node_ptr.is_null()) {
        (true, true) => return Ok(0),
        (false, true) => check_mut_ptr(cpu_ptr)?,
        (true, false) => check_mut_ptr(node_ptr)?,
        (false, false) => {
            check_mut_ptr(cpu_ptr)?;
            check_mut_ptr(node_ptr)?;
        }
    }
    // Call the memory-safe do_getcpu
    let (cpu, node) = super::do_getcpu::do_getcpu()?;
    // Copy to user
    if !cpu_ptr.is_null() {
        unsafe {
            cpu_ptr.write(cpu);
        }
    }
    if !node_ptr.is_null() {
        unsafe {
            node_ptr.write(node);
        }
    }
    Ok(0)
}
