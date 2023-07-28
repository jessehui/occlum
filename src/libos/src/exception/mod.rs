//! Exception handling subsystem.

use self::cpuid::{handle_cpuid_exception, setup_cpuid_info, CPUID_OPCODE};
use self::rdtsc::{handle_rdtsc_exception, RDTSC_OPCODE};
use self::syscall::{handle_syscall_exception, SYSCALL_OPCODE};
use super::*;
use crate::signal::{FaultSignal, SigSet};
use crate::syscall::exception_interrupt_syscall_c_abi;
use crate::syscall::{CpuContext, FpRegs, SyscallNum};
use crate::vm::{enclave_page_fault_handler, USER_SPACE_VM_MANAGER};
use aligned::{Aligned, A16};
use core::arch::x86_64::_fxsave;
use sgx_types::*;
use sgx_types::{
    sgx_cpu_context_t, sgx_exception_type_t, sgx_exception_vector_t, sgx_misc_exinfo_t,
};

use std::collections::HashSet;
use std::sync::SgxMutex;

const ENCLU: u32 = 0xd7010f;
const EACCEPT: u32 = 0x5;
const EACCEPTCOPY: u32 = 0x7;

// lazy_static! {
//     static ref HANDLE_PF_TRACKER: SgxMutex<HashSet<u32>> = SgxMutex::new(HashSet::new());
// }

// Modules for instruction simulation
mod cpuid;
mod rdtsc;
mod syscall;

extern "C" {
    pub fn sgx_register_exception_handler(
        is_first_handler: uint32_t,
        exception_handler: new_sgx_exception_handler_t,
    ) -> *const c_void;
}

#[allow(non_camel_case_types)]
#[repr(C)]
pub struct new_sgx_exception_info_t {
    pub cpu_context: sgx_cpu_context_t,
    pub exception_vector: sgx_exception_vector_t,
    pub exception_type: sgx_exception_type_t,
    pub exinfo: sgx_misc_exinfo_t,
    xsave_size: u64,
    reserved: [u64; 2],
    xsave_area: [u8; 0],
}

#[allow(non_camel_case_types)]
pub type new_sgx_exception_handler_t =
    extern "C" fn(info: *mut new_sgx_exception_info_t) -> int32_t;

pub fn register_exception_handlers() {
    setup_cpuid_info();
    // Register handlers whose priorities go from low to high
    unsafe {
        let is_first = 1;
        sgx_register_exception_handler(is_first, handle_exception);
    }
}

#[no_mangle]
extern "C" fn handle_exception(info: *mut new_sgx_exception_info_t) -> i32 {
    let mut xsave_area = unsafe { &mut *info }.xsave_area.as_mut_ptr();
    let mut fpregs: FpRegs = FpRegs::save();
    {
        let info = unsafe { &mut *info };
        // If it is #PF, but the triggered code is not user's code and the #PF address is in the userspace, then
        // it is a kernel-triggered #PF that we can handle.
        if !USER_SPACE_VM_MANAGER
            .range()
            .contains(info.cpu_context.rip as usize)
        {
            if info.exception_vector == sgx_exception_vector_t::SGX_EXCEPTION_VECTOR_PF {
                // The PF address must be in the user space
                let pf_addr = info.exinfo.faulting_address as usize;
                if !USER_SPACE_VM_MANAGER.range().contains(pf_addr) {
                    return SGX_MM_EXCEPTION_CONTINUE_SEARCH;
                } else {
                    let rip = info.cpu_context.rip as *const u32;
                    let rax = info.cpu_context.rax as u32;
                    // This can happen when two threads both try to EAUG a new page. Thread 1 EAUG because it first
                    // touches the memory and triggers #PF. Thread 2 EAUG because it uses sgx_mm_commit to commit a
                    // new page with EACCEPT and triggers #PF. If Thread 1 first acquires the lock to do EAUG, Thread 2 will
                    // raise a signal because it can't do EAUG again. This signal will eventually be handled here. And the
                    // instruction that triggers this exception is EACCEPT.
                    // In this case, since the new page is EAUG-ed already, just need to excecute the EACCEPT again. Thus here
                    // just return SGX_MM_EXCEPTION_CONTINUE_EXECUTION.
                    if ENCLU == (unsafe { *rip } as u32) & 0xffffff
                        && (EACCEPT == rax || EACCEPTCOPY == rax)
                    {
                        return SGX_MM_EXCEPTION_CONTINUE_EXECUTION;
                    }

                    // kernel code triggers #PF. This can happen e.g. when read syscall triggers user buffer #PF.
                    // FIXME: Don't use the exception stack as it is small and can cause
                    // stack overrun potentially. Try to switch to the kernel stack.
                    info!("kernel code triggers #PF");
                    let kernel_triggers = true;
                    enclave_page_fault_handler(
                        info.cpu_context.rip as usize,
                        info.exinfo,
                        kernel_triggers,
                    )
                    .expect("handle PF failure");
                    return SGX_MM_EXCEPTION_CONTINUE_EXECUTION;
                }
            } else {
                println!("exception vector = {:?}", info.exception_vector);
                return SGX_MM_EXCEPTION_CONTINUE_SEARCH;
            }
        }
    }

    unsafe {
        exception_interrupt_syscall_c_abi(
            SyscallNum::HandleException as u32,
            info as *mut _,
            &mut fpregs as *mut FpRegs,
            xsave_area,
        )
    };
    unreachable!();
}

/// Exceptions are handled as a special kind of system calls.
pub fn do_handle_exception(
    info: *mut new_sgx_exception_info_t,
    fpregs: *mut FpRegs,
    xsave_area: *mut u8,
    user_context: *mut CpuContext,
) -> Result<isize> {
    let info = unsafe { &mut *info };
    check_exception_type(info.exception_type)?;
    info!("do handle exception vector = {:?}", info.exception_vector);

    let user_context = unsafe { &mut *user_context };
    *user_context = CpuContext::from_sgx(&info.cpu_context);
    user_context.fpregs = fpregs;
    user_context.xsave_area = xsave_area;

    // Try to do instruction emulation first
    if info.exception_vector == sgx_exception_vector_t::SGX_EXCEPTION_VECTOR_UD {
        // Assume the length of opcode is 2 bytes
        let ip_opcode: u16 = unsafe { *(user_context.rip as *const u16) };
        if ip_opcode == RDTSC_OPCODE {
            return handle_rdtsc_exception(user_context);
        } else if ip_opcode == SYSCALL_OPCODE {
            return handle_syscall_exception(user_context);
        } else if ip_opcode == CPUID_OPCODE {
            return handle_cpuid_exception(user_context);
        }
    }

    // Normally, We should only handled PF exception with SGX bit set which is due to uncommitted EPC.
    // However, it happens that when committing a no-read-write page (e.g. RWX), there is a short gap
    // after EACCEPTCOPY and before the mprotect ocall. And if the user touches memory during this short
    // gap, the SGX bit will not be set. Thus, here we don't check the SGX bit.
    if info.exception_vector == sgx_exception_vector_t::SGX_EXCEPTION_VECTOR_PF {
        info!("Userspace #PF caught, try handle");
        // let current_tid = current!().tid();
        // let ret = { HANDLE_PF_TRACKER.lock().unwrap().insert(current_tid) };
        // assert!(ret == true);
        if enclave_page_fault_handler(info.cpu_context.rip as usize, info.exinfo, false).is_ok() {
            info!("#PF handling is done successfully");
            // HANDLE_PF_TRACKER.lock().unwrap().remove(&current_tid);
            return Ok(0);
        }

        // HANDLE_PF_TRACKER.lock().unwrap().remove(&current_tid);
        warn!(
            "#PF not handled. Turn to signal. user context = {:?}",
            user_context
        );
    }

    // Then, it must be a "real" exception. Convert it to signal and force delivering it.
    // The generated signal is SIGBUS, SIGFPE, SIGILL, or SIGSEGV.
    //
    // So what happens if the signal is masked? The man page of sigprocmask(2) states:
    //
    // > If SIGBUS, SIGFPE, SIGILL, or SIGSEGV are generated while they are blocked, the result is
    // undefined, unless the signal was generated by kill(2), sigqueue(3), or raise(3).
    //
    // As the thread cannot proceed without handling the exception, we choose to force
    // delivering the signal regardless of the current signal mask.
    let signal = Box::new(FaultSignal::new(info));
    crate::signal::force_signal(signal, user_context);

    Ok(0)
}

// Notes about #PF and #GP exception simulation for SGX 1.
//
// SGX 1 cannot capture #PF and #GP exceptions inside enclaves. This leaves us
// no choice but to rely on untrusted info about #PF or #PG exceptions from
// outside the enclave. Due to the obvious security risk, the feature can be
// disabled.
//
// On the bright side, SGX 2 has native support for #PF and #GP exceptions. So
// this exception simulation and its security risk is not a problem in the long
// run.

#[cfg(not(feature = "sgx1_exception_sim"))]
fn check_exception_type(type_: sgx_exception_type_t) -> Result<()> {
    if type_ != sgx_exception_type_t::SGX_EXCEPTION_HARDWARE {
        return_errno!(EINVAL, "Can only handle hardware exceptions");
    }
    Ok(())
}

#[cfg(feature = "sgx1_exception_sim")]
fn check_exception_type(type_: sgx_exception_type_t) -> Result<()> {
    if type_ != sgx_exception_type_t::SGX_EXCEPTION_HARDWARE
        && type_ != sgx_exception_type_t::SGX_EXCEPTION_SIMULATED
    {
        return_errno!(EINVAL, "Can only handle hardware / simulated exceptions");
    }
    Ok(())
}

// Based on Page-Fault Error Code of Intel Mannul
const PF_EXCEPTION_SGX_BIT: u32 = 0x1;
const PF_EXCEPTION_RW_BIT: u32 = 0x2;

// Return value:
// True     - SGX bit is set
// False    - SGX bit is not set
pub fn check_sgx_bit(exception_error_code: u32) -> bool {
    exception_error_code & PF_EXCEPTION_SGX_BIT == PF_EXCEPTION_SGX_BIT
}

// Return value:
// True     - write bit is set, #PF caused by write
// False    - read bit is set, #PF caused by read
pub fn check_rw_bit(exception_error_code: u32) -> bool {
    exception_error_code & PF_EXCEPTION_RW_BIT == PF_EXCEPTION_RW_BIT
}
