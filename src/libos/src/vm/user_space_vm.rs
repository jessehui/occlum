use super::*;
use chunk::{Chunk, ChunkRef};
use config::LIBOS_CONFIG;
use vm_manager::VMManager;
use vm_util::{VMMapOptions, VMRemapOptions};

/// The virtual memory manager for the entire user space
pub struct UserSpaceVMManager {
    vm_manager: VMManager,
    // range: VMRange,
    total_size: usize,
}

impl UserSpaceVMManager {
    fn new() -> Result<UserSpaceVMManager> {
        let rsrv_mem_size = LIBOS_CONFIG.resource_limits.user_space_size;
        let vm_range = unsafe {
            let ptr = sgx_alloc_rsrv_mem(rsrv_mem_size);
            let perm = MemPerm::READ | MemPerm::WRITE;
            if ptr.is_null() {
                return_errno!(ENOMEM, "run out of reserved memory");
            }
            // Change the page permission to RW (default)
            assert!(
                sgx_tprotect_rsrv_mem(ptr, rsrv_mem_size, perm.bits()) == sgx_status_t::SGX_SUCCESS
            );

            let addr = ptr as usize;
            debug!(
                "allocated rsrv addr is 0x{:x}, len is 0x{:x}",
                addr, rsrv_mem_size
            );
            VMRange::from_unchecked(addr, addr + rsrv_mem_size)
        };

        let vm_manager = VMManager::init(vm_range)?;

        Ok(UserSpaceVMManager {
            vm_manager,
            total_size: rsrv_mem_size,
        })
    }

    // Since userspace vm manager is a global variable, it will not be freed until exit.
    // Thus, this needs to be called in a ECALL before destroying the enclave.
    pub fn free_user_space(&self) -> Result<isize> {
        info!("free user space vm manager");
        let addr = self.range().start() as *const c_void;
        let size = self.range().size();
        assert!(unsafe { sgx_free_rsrv_mem(addr, size) == 0 });
        Ok(0)
    }

    pub fn range(&self) -> &VMRange {
        &self.vm_manager.range()
    }

    pub fn vm_manager(&self) -> &VMManager {
        &self.vm_manager
    }

    // Allocate a single VMA chunk. Return the chunk range and the chunk reference
    pub fn alloc(&self, vm_options: VMMapOptions) -> Result<(VMRange, ChunkRef)> {
        self.vm_manager.alloc(&vm_options)
    }

    pub fn mmap(&self, vm_options: VMMapOptions) -> Result<usize> {
        self.vm_manager.mmap(&vm_options)
    }

    pub fn munmap(&self, addr: usize, size: usize) -> Result<()> {
        self.vm_manager.munmap(addr, size)
    }

    pub fn mprotect(&self, addr: usize, size: usize, perms: VMPerms) -> Result<()> {
        self.vm_manager.mprotect(addr, size, perms)
    }

    pub fn msync(&self, addr: usize, size: usize) -> Result<()> {
        self.vm_manager.msync(addr, size)
    }

    pub fn mremap(&self, options: &VMRemapOptions) -> Result<usize> {
        self.vm_manager.mremap(options)
    }

    pub fn msync_by_file(&self, sync_file: &FileRef) {
        self.vm_manager.msync_by_file(sync_file)
    }

    pub fn get_total_size(&self) -> usize {
        self.total_size
    }
}

lazy_static! {
    pub static ref USER_SPACE_VM_MANAGER: UserSpaceVMManager = UserSpaceVMManager::new().unwrap();
}

bitflags! {
    struct MemPerm: i32 {
        const READ  = 1;
        const WRITE = 2;
        const EXEC  = 4;
    }
}

extern "C" {
    // Allocate a range of EPC memory from the reserved memory area with RW permission
    //
    // Parameters:
    // Inputs: length [in]: Size of region to be allocated in bytes. Page aligned
    // Return: Starting address of the new allocated memory area on success; otherwise NULL
    //
    fn sgx_alloc_rsrv_mem(length: usize) -> *const c_void;

    // Free a range of EPC memory from the reserved memory area
    //
    // Parameters:
    // Inputs: addr[in]: Starting address of region to be freed. Page aligned.
    //         length[in]: The length of the memory to be freed in bytes.  Page aligned
    // Return: 0 on success; otherwise -1
    //
    fn sgx_free_rsrv_mem(addr: *const c_void, length: usize) -> i32;

    // Modify the access permissions of the pages in the reserved memory area
    //
    // Parameters:
    // Inputs: addr[in]: Starting address of region which needs to change access
    //         permission. Page aligned.
    //         length[in]: The length of the memory to be manipulated in bytes. Page aligned.
    //         prot[in]: The target memory protection.
    // Return: sgx_status_t
    //
    fn sgx_tprotect_rsrv_mem(addr: *const c_void, length: usize, prot: i32) -> sgx_status_t;
}

// #[derive(Debug)]
// pub struct UserSpaceVMRange {
//     vm_range: VMRange,
// }

// impl UserSpaceVMRange {
//     fn new(vm_range: VMRange) -> UserSpaceVMRange {
//         UserSpaceVMRange { vm_range }
//     }

//     pub fn range(&self) -> &VMRange {
//         &self.vm_range
//     }
// }

// impl Drop for UserSpaceVMRange {
//     fn drop(&mut self) {
//         info!("WHOLE user space vm free: {:?}", self.vm_range);
//     }
// }
