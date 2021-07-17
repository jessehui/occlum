//! Exception handling subsystem.

use self::cpuid::{handle_cpuid_exception, setup_cpuid_info, CPUID_OPCODE};
use self::rdtsc::{handle_rdtsc_exception, RDTSC_OPCODE};
use self::syscall::{handle_syscall_exception, SYSCALL_OPCODE};
use super::*;
use crate::signal::{FaultSignal, SigSet};
use crate::syscall::exception_interrupt_syscall_c_abi;
use crate::syscall::{CpuContext, FpRegs, SyscallNum};
use aligned::{Aligned, A16};
use core::arch::x86_64::_fxsave;
use sgx_types::*;

// Modules for instruction simulation
mod cpuid;
mod rdtsc;
mod syscall;

pub fn register_exception_handlers() {
    setup_cpuid_info();
    // Register handlers whose priorities go from low to high
    unsafe {
        let is_first = 1;
        sgx_register_exception_handler(is_first, handle_exception);
    }
}

#[no_mangle]
extern "C" fn handle_exception(info: *mut sgx_exception_info_t) -> i32 {
    let mut fpregs = FpRegs::save();
    unsafe {
        exception_interrupt_syscall_c_abi(
            SyscallNum::HandleException as u32,
            info as *mut _,
            &mut fpregs as *mut FpRegs,
        )
    };
    unreachable!();
}

/// Exceptions are handled as a special kind of system calls.
pub fn do_handle_exception(
    info: *mut sgx_exception_info_t,
    fpregs: *mut FpRegs,
    user_context: *mut CpuContext,
) -> Result<isize> {
    let info = unsafe { &mut *info };
    check_exception_type(info.exception_type)?;

    let user_context = unsafe { &mut *user_context };
    *user_context = CpuContext::from_sgx(&info.cpu_context);
    user_context.fpregs = fpregs;

    // Try to do instruction emulation first
    if info.exception_vector == sgx_exception_vector_t::SGX_EXCEPTION_VECTOR_UD {
        // Assume the length of opcode is 2 bytes
        let ip_opcode = unsafe { *(user_context.rip as *const u16) };
        if ip_opcode == RDTSC_OPCODE {
            return handle_rdtsc_exception(user_context);
        } else if ip_opcode == SYSCALL_OPCODE {
            return handle_syscall_exception(user_context);
        } else if ip_opcode == CPUID_OPCODE {
            return handle_cpuid_exception(user_context);
        }
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
