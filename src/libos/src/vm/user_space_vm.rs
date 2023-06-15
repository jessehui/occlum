use super::ipc::SHM_MANAGER;
use super::*;
use crate::ctor::dtor;
use crate::util::pku_util;
use config::LIBOS_CONFIG;
use std::ops::{Deref, DerefMut};
use vm_epc::SGXPlatform;
use vm_manager::VMManager;
use vm_perms::VMPerms;

const RSRV_MEM_PERM: VMPerms = VMPerms::DEFAULT;

/// The virtual memory manager for the entire user space
pub struct UserSpaceVMManager {
    inner: VMManager,
    sgx_platform: SGXPlatform,
}

impl UserSpaceVMManager {
    fn new() -> Result<UserSpaceVMManager> {
        let sgx_platform = SGXPlatform::new();
        let init_size = LIBOS_CONFIG.resource_limits.user_space_init_size;
        let max_size = LIBOS_CONFIG.resource_limits.user_space_max_size;

        let (userspace_vm_range, gap_range) = sgx_platform.alloc_user_space(init_size, max_size)?;

        info!(
            "user space allocated, range = {:?}, gap_range = {:?}",
            userspace_vm_range, gap_range
        );

        // FIXME
        // pku_util::pkey_mprotect_userspace_mem(addr, user_space_mem_size, RSRV_MEM_PERM.bits());

        let vm_manager = VMManager::init_with_mem_gap(userspace_vm_range, gap_range)?;

        Ok(Self {
            inner: vm_manager,
            sgx_platform,
        })
    }

    // fn new() -> Result<UserSpaceVMManager> {
    //     let rsrv_mem_size = LIBOS_CONFIG.resource_limits.user_space_size;
    //     let vm_range = unsafe {
    //         // TODO: Current sgx_alloc_rsrv_mem implmentation will commit all the pages of the desired size, which will consume
    //         // a lot of time. When EDMM is supported, there is no need to commit all the pages at the initialization stage. A function
    //         // which reserves memory but not commit pages should be provided then.
    //         let ptr = sgx_alloc_rsrv_mem(rsrv_mem_size);
    //         if ptr.is_null() {
    //             return_errno!(ENOMEM, "run out of reserved memory");
    //         }

    //         // Without EDMM support and the ReservedMemExecutable is set to 1, the reserved memory will be RWX. And we can't change the reserved memory permission.
    //         // With EDMM support, the reserved memory permission is RW by default. And we can change the permissions when needed.

    //         let addr = ptr as usize;
    //         debug!(
    //             "allocated rsrv addr is 0x{:x}, len is 0x{:x}",
    //             addr, rsrv_mem_size
    //         );
    //         pku_util::pkey_mprotect_userspace_mem(addr, rsrv_mem_size, RSRV_MEM_PERM.bits());
    //         VMRange::new(addr, addr + rsrv_mem_size)?
    //     };

    //     let vm_manager = VMManager::init(vm_range)?;

    //     Ok(UserSpaceVMManager(vm_manager))
    // }

    pub fn get_total_size(&self) -> usize {
        self.range().size()
    }
}

// This provides module teardown function attribute similar with `__attribute__((destructor))` in C/C++ and will
// be called after the main function. Static variables are still safe to visit at this time.
#[dtor]
fn free_user_space() {
    info!("free user space at the end");
    SHM_MANAGER.clean_when_libos_exit();
    let total_user_space_range = USER_SPACE_VM_MANAGER.range();
    assert!(USER_SPACE_VM_MANAGER.verified_clean_when_exit());
    let addr = total_user_space_range.start();
    let size = total_user_space_range.size();
    info!("free user space VM: {:?}", total_user_space_range);

    // FIXME
    // pku_util::clear_pku_when_libos_exit(addr, size, RSRV_MEM_PERM.bits());

    let gap_range = USER_SPACE_VM_MANAGER
        .gap_range()
        .expect("Gap range must exists");
    USER_SPACE_VM_MANAGER
        .sgx_platform
        .free_user_space(total_user_space_range, &gap_range);
}

impl Deref for UserSpaceVMManager {
    type Target = VMManager;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

lazy_static! {
    pub static ref USER_SPACE_VM_MANAGER: UserSpaceVMManager = UserSpaceVMManager::new().unwrap();
}

// bitflags! {
//     struct MemPerm: i32 {
//         const READ  = 1;
//         const WRITE = 2;
//         const EXEC  = 4;
//     }
// }

// extern "C" {
//     // Allocate a range of EPC memory from the reserved memory area with RW permission
//     //
//     // Parameters:
//     // Inputs: length [in]: Size of region to be allocated in bytes. Page aligned
//     // Return: Starting address of the new allocated memory area on success; otherwise NULL
//     //
//     fn sgx_alloc_rsrv_mem(length: usize) -> *const c_void;

//     // Free a range of EPC memory from the reserved memory area
//     //
//     // Parameters:
//     // Inputs: addr[in]: Starting address of region to be freed. Page aligned.
//     //         length[in]: The length of the memory to be freed in bytes.  Page aligned
//     // Return: 0 on success; otherwise -1
//     //
//     fn sgx_free_rsrv_mem(addr: *const c_void, length: usize) -> i32;
// }
