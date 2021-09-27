use super::*;

use super::chunk::{Chunk, ChunkID, ChunkRef, ChunkType, CHUNK_DEFAULT_SIZE};
use super::free_space_manager::VMFreeSpaceManager;
use super::vm_area::VMArea;
use super::vm_chunk_manager::ChunkManager;
use super::vm_perms::VMPerms;
use super::vm_util::{SizeType, VMMapAddr, VMMapOptions, VMMapOptionsBuilder, VMRemapOptions};
use crate::process::ThreadRef;
use std::ops::Bound::{Excluded, Included};

use crate::util::sync::rw_lock;
use std::collections::{BTreeSet, HashSet};

#[derive(Debug)]
pub struct VMManager {
    range: VMRange,
    internal: SgxMutex<InternalVMManager>,
}

impl VMManager {
    pub fn init(vm_range: VMRange) -> Result<Self> {
        let internal = InternalVMManager::init(vm_range.clone());
        Ok(VMManager {
            range: vm_range,
            internal: SgxMutex::new(internal),
        })
    }

    pub fn range(&self) -> &VMRange {
        &self.range
    }

    // Allocate single VMA chunk for new process whose process VM is not ready yet
    pub fn alloc(&self, options: &VMMapOptions) -> Result<(VMRange, ChunkRef)> {
        let addr = *options.addr();
        let size = *options.size();
        if let Ok(new_chunk) = self.internal.lock().unwrap().mmap_chunk(options) {
            return Ok((new_chunk.range().clone(), new_chunk));
        }
        return_errno!(ENOMEM, "can't allocate free chunks");
    }

    pub fn mmap(&self, options: &VMMapOptions) -> Result<usize> {
        let addr = *options.addr();
        let size = *options.size();
        let align = *options.align();

        match addr {
            VMMapAddr::Any => {}
            VMMapAddr::Hint(addr) => {
                let target_range = unsafe { VMRange::from_unchecked(addr, addr + size) };
                let ret = self.mmap_with_addr(target_range, options);
                if ret.is_ok() {
                    return ret;
                }
            }
            VMMapAddr::Need(addr) | VMMapAddr::Force(addr) => {
                let target_range = unsafe { VMRange::from_unchecked(addr, addr + size) };
                return self.mmap_with_addr(target_range, options);
            }
        }

        if size > CHUNK_DEFAULT_SIZE {
            if let Ok(new_chunk) = self.internal.lock().unwrap().mmap_chunk(options) {
                let start = new_chunk.range().start();
                current!().vm().add_mem_chunk(new_chunk);
                return Ok(start);
            } else {
                return_errno!(ENOMEM, "can't allocate free chunks");
            }
        }

        // Allocate in default chunk
        let current = current!();
        {
            // Fast path: Try to go to assigned chunks to do mmap
            // There is no lock on VMManager in this path.
            let process_mem_chunks = current.vm().mem_chunks().read().unwrap();
            for chunk in process_mem_chunks
                .iter()
                .filter(|&chunk| !chunk.is_single_vma())
            {
                let result_start = chunk.try_mmap(options);
                if result_start.is_ok() {
                    return result_start;
                }
            }
        }

        // Process' chunks are all busy or can't allocate from process_mem_chunks list.
        // Allocate a new chunk with chunk default size.
        // Lock on ChunkManager.
        if let Ok(new_chunk) = self.internal.lock().unwrap().mmap_chunk_default(addr) {
            // Allocate in the new chunk
            let start = new_chunk.mmap(options);
            debug_assert!(start.is_ok()); // We just allocate a chunk for you. You must succeed.
                                          // Add this new chunk to process' chunk list
            new_chunk.add_process(&current);
            current.vm().add_mem_chunk(new_chunk);
            return start;
        }

        // Slow path: Sadly, there is no free chunk, iterate every chunk to find a range
        {
            // Release lock after this block
            let mut result_start = Ok(0);
            let chunks = &self.internal.lock().unwrap().chunks;
            let chunk = chunks
                .iter()
                .filter(|&chunk| !chunk.is_single_vma())
                .find(|&chunk| {
                    result_start = chunk.mmap(options);
                    result_start.is_ok()
                });
            if let Some(chunk) = chunk {
                chunk.add_process(&current);
                current.vm().add_mem_chunk(chunk.clone());
                return result_start;
            }
        }

        // Can't find a range in default chunks. Maybe there is still free range in the global free list.
        if let Ok(new_chunk) = self.internal.lock().unwrap().mmap_chunk(options) {
            let start = new_chunk.range().start();
            current!().vm().add_mem_chunk(new_chunk);
            return Ok(start);
        }

        // No free range
        return_errno!(ENOMEM, "Can't find a free chunk for this allocation");
    }

    // If addr is specified, use single VMA chunk to record this
    fn mmap_with_addr(&self, range: VMRange, options: &VMMapOptions) -> Result<usize> {
        let addr = *options.addr();
        let size = *options.size();

        let current = current!();

        let chunk = {
            let process_mem_chunks = current.vm().mem_chunks().read().unwrap();
            process_mem_chunks
                .iter()
                .find(|&chunk| chunk.range().intersect(&range).is_some())
                .cloned()
        };

        if let Some(chunk) = chunk {
            // This range is currently in a allocated chunk
            match chunk.internal() {
                ChunkType::MultiVMA(chunk_internal) => {
                    // If the chunk only intersect, but not a superset, we can't handle this.
                    if !chunk.range().is_superset_of(&range) {
                        return_errno!(EINVAL, "mmap with specified addr spans over two chunks");
                    }
                    trace!(
                        "mmap with addr in existing default chunk: {:?}",
                        chunk.range()
                    );
                    return chunk_internal.lock().unwrap().chunk_manager().mmap(options);
                }
                ChunkType::SingleVMA(_) => {
                    match addr {
                        VMMapAddr::Hint(addr) => {
                            return_errno!(ENOMEM, "Single VMA is currently in use. Hint failure");
                        }
                        VMMapAddr::Need(addr) => {
                            return_errno!(ENOMEM, "Single VMA is currently in use. Need failure");
                        }
                        VMMapAddr::Force(addr) => {
                            // Munmap the corresponding single vma chunk
                            // If the chunk only intersect, but not a superset, we can't handle this.
                            if !chunk.range().is_superset_of(&range) {
                                trace!(
                                    "chunk range = {:?}, target range = {:?}",
                                    chunk.range(),
                                    range
                                );
                                return_errno!(EINVAL, "mmap with specified addr spans two chunks");
                            }
                            let mut internal_manager = self.internal.lock().unwrap();
                            internal_manager.munmap_single_vma_chunk(&chunk, &range)?;
                        }
                        VMMapAddr::Any => unreachable!(),
                    }
                }
            }
        }

        // This range is not currently using, allocate one in global list
        if let Ok(new_chunk) = self.internal.lock().unwrap().mmap_chunk(options) {
            let start = new_chunk.range().start();
            debug_assert!({
                match addr {
                    VMMapAddr::Force(addr) | VMMapAddr::Need(addr) => start == range.start(),
                    _ => true,
                }
            });
            current.vm().add_mem_chunk(new_chunk);
            return Ok(start);
        } else {
            return_errno!(ENOMEM, "can't allocate a chunk in global list")
        }
    }

    pub fn munmap(&self, addr: usize, size: usize) -> Result<()> {
        // Go to every process chunk to see if it contains the range.
        let size = {
            if size == 0 {
                return_errno!(EINVAL, "size of munmap must not be zero");
            }
            align_up(size, PAGE_SIZE)
        };
        let munmap_range = { VMRange::new(addr, addr + size) }?;
        let chunk = {
            let current = current!();
            let process_mem_chunks = current.vm().mem_chunks().read().unwrap();
            let chunk = process_mem_chunks
                .iter()
                .find(|&chunk| chunk.range().intersect(&munmap_range).is_some());
            if chunk.is_none() {
                // Note:
                // The man page of munmap states that "it is not an error if the indicated
                // range does not contain any mapped pages". This is not considered as
                // an error!
                trace!("the munmap range is not mapped");
                return Ok(());
            }
            chunk.unwrap().clone()
        };

        if !chunk.range().is_superset_of(&munmap_range) {
            // munmap range spans multiple chunks
            let munmap_single_vma_chunks = {
                let current = current!();
                let mut process_mem_chunks = current.vm().mem_chunks().write().unwrap();
                let munmap_single_vma_chunks = process_mem_chunks
                    .drain_filter(|p_chunk| {
                        p_chunk.is_single_vma() && p_chunk.range().overlap_with(&munmap_range)
                    })
                    .collect::<Vec<ChunkRef>>();
                if munmap_single_vma_chunks
                    .iter()
                    .find(|chunk| !munmap_range.is_superset_of(chunk.range()))
                    .is_some()
                {
                    // TODO: Support munmap multiple single VMA chunk with remaining ranges.
                    return_errno!(
                        EINVAL,
                        "munmap multiple chunks with remaining ranges is not supported"
                    );
                }

                // TODO: Support munmap a part of default chunks
                // Check munmap default chunks
                if process_mem_chunks
                    .iter()
                    .find(|p_chunk| p_chunk.range().overlap_with(&munmap_range))
                    .is_some()
                {
                    return_errno!(
                        EINVAL,
                        "munmap range overlap with default chunks is not supported"
                    );
                }
                munmap_single_vma_chunks
            };

            let mut chunk_manager = self.internal.lock().unwrap();
            munmap_single_vma_chunks.iter().for_each(|p_chunk| {
                chunk_manager.munmap_single_vma_chunk(p_chunk, p_chunk.range());
            });
            return Ok(());
        }

        match chunk.internal() {
            ChunkType::MultiVMA(manager) => {
                return manager
                    .lock()
                    .unwrap()
                    .chunk_manager()
                    .munmap_range(munmap_range);
            }
            ChunkType::SingleVMA(_) => {
                let mut internal_manager = self.internal.lock().unwrap();
                return internal_manager.munmap_single_vma_chunk(&chunk, &munmap_range);
            }
        }
    }

    pub fn find_mmap_region(&self, addr: usize) -> Result<VMRange> {
        let current = current!();
        let process_mem_chunks = current.vm().mem_chunks().read().unwrap();
        let mut vm_range = Ok(Default::default());
        process_mem_chunks.iter().find(|&chunk| {
            vm_range = chunk.find_mmap_region(addr);
            vm_range.is_ok()
        });
        return vm_range;
    }

    pub fn mprotect(&self, addr: usize, size: usize, perms: VMPerms) -> Result<()> {
        let protect_range = VMRange::new_with_size(addr, size)?;
        let chunk = {
            let current = current!();
            let process_mem_chunks = current.vm().mem_chunks().read().unwrap();
            let chunk = process_mem_chunks
                .iter()
                .find(|&chunk| chunk.range().intersect(&protect_range).is_some());
            if chunk.is_none() {
                return_errno!(ENOMEM, "invalid range");
            }
            chunk.unwrap().clone()
        };

        // TODO: Support mprotect range spans multiple chunks
        if !chunk.range().is_superset_of(&protect_range) {
            return_errno!(EINVAL, "mprotect range is not in a single chunk");
        }

        match chunk.internal() {
            ChunkType::MultiVMA(manager) => {
                trace!("mprotect default chunk: {:?}", chunk.range());
                return manager
                    .lock()
                    .unwrap()
                    .chunk_manager()
                    .mprotect(addr, size, perms);
            }
            ChunkType::SingleVMA(_) => {
                let mut internal_manager = self.internal.lock().unwrap();
                return internal_manager.mprotect_single_vma_chunk(&chunk, protect_range, perms);
            }
        }
    }

    pub fn msync(&self, addr: usize, size: usize) -> Result<()> {
        let sync_range = VMRange::new_with_size(addr, size)?;
        let chunk = {
            let current = current!();
            let process_mem_chunks = current.vm().mem_chunks().read().unwrap();
            let chunk = process_mem_chunks
                .iter()
                .find(|&chunk| chunk.range().is_superset_of(&sync_range));
            if chunk.is_none() {
                return_errno!(ENOMEM, "invalid range");
            }
            chunk.unwrap().clone()
        };

        match chunk.internal() {
            ChunkType::MultiVMA(manager) => {
                trace!("msync default chunk: {:?}", chunk.range());
                return manager
                    .lock()
                    .unwrap()
                    .chunk_manager()
                    .msync_by_range(&sync_range);
            }
            ChunkType::SingleVMA(vma) => {
                let vma = vma.lock().unwrap();
                ChunkManager::flush_file_vma(&vma);
            }
        }
        Ok(())
    }

    pub fn msync_by_file(&self, sync_file: &FileRef) {
        let current = current!();
        let process_mem_chunks = current.vm().mem_chunks().read().unwrap();
        let is_same_file = |file: &FileRef| -> bool { Arc::ptr_eq(&file, &sync_file) };
        process_mem_chunks
            .iter()
            .for_each(|chunk| match chunk.internal() {
                ChunkType::MultiVMA(manager) => {
                    manager
                        .lock()
                        .unwrap()
                        .chunk_manager()
                        .msync_by_file(sync_file);
                }
                ChunkType::SingleVMA(vma) => {
                    ChunkManager::flush_file_vma_with_cond(&vma.lock().unwrap(), is_same_file);
                }
            });
    }

    pub fn mremap(&self, options: &VMRemapOptions) -> Result<usize> {
        return_errno!(ENOSYS, "Under development");
    }

    // When process exit, free all owned default chunks
    pub fn free_vm_when_exit(&self, mut mem_chunks: rw_lock::RwLockWriteGuard<HashSet<ChunkRef>>) {
        let mut default_chunks = mem_chunks
            .drain_filter(|chunk| !chunk.is_single_vma())
            .collect::<Vec<ChunkRef>>();
        trace!("default chunks = {:?}", default_chunks);

        // Free all owned default chunks
        let owned_default_chunks = default_chunks.drain_filter(|chunk| match chunk.internal() {
            ChunkType::SingleVMA(_) => unreachable!(),
            ChunkType::MultiVMA(chunk_internal) => {
                chunk_internal.lock().unwrap().is_owned_by_current_process()
            }
        });
        let mut internal_manager = self.internal.lock().unwrap();
        owned_default_chunks.for_each(|chunk| {
            trace!("owned default chunk = {:?}", chunk);
            internal_manager.munmap_default_chunk(&chunk);
        });

        // For other default chunks, remove pid from process_set
        default_chunks
            .iter()
            .for_each(|chunk| match chunk.internal() {
                ChunkType::SingleVMA(_) => unreachable!(),
                ChunkType::MultiVMA(chunk_internal) => {
                    chunk_internal.lock().unwrap().remove_current_process()
                }
            });
    }

    // When process vm is dropping, destroy all single vma chunks
    pub fn free_all_single_vma_chunk_when_exit(
        &self,
        mut mem_chunks: rw_lock::RwLockWriteGuard<HashSet<ChunkRef>>,
    ) {
        let single_vma_chunks = mem_chunks.drain_filter(|chunk| chunk.is_single_vma());
        let mut chunk_manager = self.internal.lock().unwrap();
        single_vma_chunks.for_each(|chunk| {
            chunk_manager.munmap_single_vma_chunk(&chunk, chunk.range());
        });

        trace!("mem_chunks = {:?}", mem_chunks.iter());
        debug_assert!(mem_chunks.len() == 0);
    }
}

// Modification on this structure must aquire the global lock.
// TODO: Enable fast_default_chunks for faster chunk allocation
#[derive(Debug)]
pub struct InternalVMManager {
    chunks: BTreeSet<ChunkRef>,         // in use
    fast_default_chunks: Vec<ChunkRef>, // process exit, empty default chunk
    free_manager: VMFreeSpaceManager,
}

impl InternalVMManager {
    pub fn init(vm_range: VMRange) -> Self {
        let chunks = BTreeSet::new();
        let fast_default_chunks = Vec::new();
        let free_manager = VMFreeSpaceManager::new(vm_range);
        Self {
            chunks,
            fast_default_chunks,
            free_manager,
        }
    }

    // Allocate a new chunk with default size
    pub fn mmap_chunk_default(&mut self, addr: VMMapAddr) -> Result<ChunkRef> {
        // Find a free range from free_manager
        let free_range = self.find_free_gaps(CHUNK_DEFAULT_SIZE, PAGE_SIZE, addr)?;

        // Add this range to chunks
        let chunk = Arc::new(Chunk::new_default_chunk(free_range)?);
        trace!("allocate a default chunk = {:?}", chunk);
        self.chunks.insert(chunk.clone());
        Ok(chunk)
    }

    // Allocate a chunk with single vma
    pub fn mmap_chunk(&mut self, options: &VMMapOptions) -> Result<ChunkRef> {
        let addr = *options.addr();
        let size = *options.size();
        let align = *options.align();
        let free_range = self.find_free_gaps(size, align, addr)?;
        let chunk = Arc::new(Chunk::new_single_vma_chunk(free_range, options));
        trace!("allocate a new single vma chunk: {:?}", chunk);
        self.chunks.insert(chunk.clone());
        Ok(chunk)
    }

    pub fn munmap_default_chunk(&mut self, chunk: &ChunkRef) -> Result<()> {
        // Before free the chunk, clean all the vmas in the chunk.
        chunk.clean_multi_vmas();
        self.free_chunk(chunk)?;
        Ok(())
    }

    pub fn munmap_single_vma_chunk(
        &mut self,
        chunk: &ChunkRef,
        munmap_range: &VMRange,
    ) -> Result<()> {
        let vma = match chunk.internal() {
            ChunkType::MultiVMA(_) => {
                unreachable!();
            }
            ChunkType::SingleVMA(vma) => vma,
        };

        let mut vma = vma.lock().unwrap();
        trace!(
            "munmap_single_vma_chunk range = {:?}, munmap_range = {:?}",
            chunk.range(),
            munmap_range
        );
        debug_assert!(chunk.range() == vma.range());
        let intersection_vma = match vma.intersect(munmap_range) {
            Some(intersection_vma) => intersection_vma,
            _ => unreachable!(),
        };

        // File-backed VMA needs to be flushed upon munmap
        ChunkManager::flush_file_vma(&intersection_vma);

        // Reset memory permissions
        if !&intersection_vma.perms().is_default() {
            VMPerms::apply_perms(&intersection_vma, VMPerms::default());
        }

        // Reset to zero
        unsafe {
            let buf = intersection_vma.as_slice_mut();
            buf.iter_mut().for_each(|b| *b = 0)
        }

        let mut new_vmas = vma.subtract(&intersection_vma);
        let current = current!();

        match new_vmas.len() {
            0 => {
                // Exact size
                self.free_chunk(&chunk);
                if current.tid() != 0 {
                    // Idle thread will help to munmap all the single vmas after the process VM is dropped.
                    // Only remove memory chunk from the process VM for non idle thread.
                    current.vm().remove_mem_chunk(&chunk);
                }
            }
            1 => {
                // Set the current vma to the new vma
                let updated_vma = new_vmas.pop().unwrap();
                if updated_vma.start() == vma.start() {
                    vma.set_end(updated_vma.end());
                } else {
                    debug_assert!(updated_vma.end() == vma.end());
                    vma.set_start(updated_vma.start());
                }
                trace!("updated_vma = {:?}, vma = {:?}", updated_vma, vma);
                self.update_single_vma_chunk(&current, &chunk, updated_vma);

                // Return the intersection range to free list
                self.free_manager
                    .add_range_back_to_free_manager(intersection_vma.range());
            }
            2 => {
                trace!("vmas = {:?}", new_vmas);
                self.free_manager
                    .add_range_back_to_free_manager(intersection_vma.range());
                vma.set_end(new_vmas[0].end());
                self.update_single_vma_chunk(&current, &chunk, vma.clone());

                let new_vma_chunk = Arc::new(Chunk::new_chunk_with_vma(new_vmas[1].clone()));
                self.chunks.insert(new_vma_chunk.clone());

                // Add to process chunk list
                current.vm().add_mem_chunk(new_vma_chunk);
            }
            _ => unreachable!(),
        }
        Ok(())
    }

    fn update_single_vma_chunk(
        &mut self,
        current_thread: &ThreadRef,
        old_chunk: &ChunkRef,
        new_vma: VMArea,
    ) {
        let new_chunk = Arc::new(Chunk::new_chunk_with_vma(new_vma));
        current_thread
            .vm()
            .replace_mem_chunk(old_chunk, new_chunk.clone());
        self.chunks.remove(old_chunk);
        self.chunks.insert(new_chunk);
    }

    pub fn mprotect_single_vma_chunk(
        &mut self,
        chunk: &ChunkRef,
        protect_range: VMRange,
        new_perms: VMPerms,
    ) -> Result<()> {
        let vma = match chunk.internal() {
            ChunkType::MultiVMA(_) => {
                unreachable!();
            }
            ChunkType::SingleVMA(vma) => vma,
        };

        let mut containing_vma = vma.lock().unwrap();
        trace!(
            "mprotect_single_vma_chunk range = {:?}, mprotect_range = {:?}",
            chunk.range(),
            protect_range
        );
        debug_assert!(chunk.range() == containing_vma.range());

        if containing_vma.perms() == new_perms {
            return Ok(());
        }

        let same_start = protect_range.start() == containing_vma.start();
        let same_end = protect_range.end() == containing_vma.end();
        let current = current!();
        match (same_start, same_end) {
            (true, true) => {
                // Exact the same vma
                containing_vma.set_perms(new_perms);
                VMPerms::apply_perms(&containing_vma, containing_vma.perms());
            }
            (false, false) => {
                // The containing VMA is divided into three VMAs:
                // Shrinked old VMA:    [containing_vma.start,     protect_range.start)
                // New VMA:             [protect_range.start,      protect_range.end)
                // remaining old VMA:     [protect_range.end,        containing_vma.end)

                let old_end = containing_vma.end();
                let old_perms = containing_vma.perms();

                containing_vma.set_end(protect_range.start());
                self.update_single_vma_chunk(&current, &chunk, containing_vma.clone());

                let new_vma = VMArea::inherits_file_from(&containing_vma, protect_range, new_perms);
                VMPerms::apply_perms(&new_vma, new_vma.perms());
                self.add_new_chunk(&current, new_vma);

                let remaining_old_vma = {
                    let range = VMRange::new(protect_range.end(), old_end).unwrap();
                    VMArea::inherits_file_from(&containing_vma, range, old_perms)
                };
                self.add_new_chunk(&current, remaining_old_vma);
            }
            _ => {
                if same_start {
                    // Protect range is at left side of the cotaining vma
                    containing_vma.set_start(protect_range.end());
                } else {
                    // Protect range is at right side of the cotaining vma
                    containing_vma.set_end(protect_range.start());
                }
                self.update_single_vma_chunk(&current, &chunk, containing_vma.clone());

                let new_vma = VMArea::inherits_file_from(&containing_vma, protect_range, new_perms);
                VMPerms::apply_perms(&new_vma, new_vma.perms());
                self.add_new_chunk(&current, new_vma);
            }
        }
        Ok(())
    }

    fn add_new_chunk(&mut self, current_thread: &ThreadRef, new_vma: VMArea) {
        let new_vma_chunk = Arc::new(Chunk::new_chunk_with_vma(new_vma));
        self.chunks.insert(new_vma_chunk.clone());
        current_thread.vm().add_mem_chunk(new_vma_chunk);
    }

    pub fn free_chunk(&mut self, chunk: &ChunkRef) -> Result<()> {
        let range = chunk.range();
        // Remove from chunks
        self.chunks.remove(chunk);

        // Add range back to freespace manager
        self.free_manager.add_range_back_to_free_manager(range);
        Ok(())
    }

    pub fn find_free_gaps(
        &mut self,
        size: usize,
        align: usize,
        addr: VMMapAddr,
    ) -> Result<VMRange> {
        return self
            .free_manager
            .find_free_range_internal(size, align, addr);
    }
}
