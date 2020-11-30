use super::*;

use super::vm_area::VMArea;
use super::vm_perms::VMPerms;
use crate::entry::{DONE, RUNNING};
use crate::process::table::{get_all_processes, get_all_threads};
use crate::process::ThreadStatus;
use crate::time::timespec_t;
use core::ptr;
use crossbeam_queue::ArrayQueue;
use sgx_tstd::sync::SgxThreadSpinlock;
use std::thread;
use std::time::Duration;

#[derive(Clone, Debug)]
pub enum VMInitializer {
    DoNothing(),
    FillZeros(),
    CopyFrom { range: VMRange },
    LoadFromFile { file: FileRef, offset: usize },
}

impl Default for VMInitializer {
    fn default() -> VMInitializer {
        VMInitializer::DoNothing()
    }
}

impl VMInitializer {
    pub fn init_slice(&self, buf: &mut [u8]) -> Result<()> {
        match self {
            VMInitializer::DoNothing() => {
                // Do nothing
            }
            VMInitializer::FillZeros() => {
                // for b in buf {
                //     *b = 0;
                // }
            }
            VMInitializer::CopyFrom { range } => {
                let src_slice = unsafe { range.as_slice() };
                let copy_len = min(buf.len(), src_slice.len());
                buf[..copy_len].copy_from_slice(&src_slice[..copy_len]);
                for b in &mut buf[copy_len..] {
                    *b = 0;
                }
            }
            VMInitializer::LoadFromFile { file, offset } => {
                // TODO: make sure that read_at does not move file cursor
                let len = file
                    .read_at(*offset, buf)
                    .cause_err(|_| errno!(EIO, "failed to init memory from file"))?;
                for b in &mut buf[len..] {
                    *b = 0;
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum VMMapAddr {
    Any,          // Free to choose any address
    Hint(usize),  // Prefer the address, but can use other address
    Need(usize),  // Need to use the address, otherwise report error
    Force(usize), // Force using the address by munmap first
}

impl Default for VMMapAddr {
    fn default() -> VMMapAddr {
        VMMapAddr::Any
    }
}

#[derive(Builder, Debug)]
#[builder(pattern = "owned", build_fn(skip), no_std)]
pub struct VMMapOptions {
    size: usize,
    align: usize,
    perms: VMPerms,
    addr: VMMapAddr,
    initializer: VMInitializer,
    // The content of the VMA can be written back to a given file at a given offset
    writeback_file: Option<(FileRef, usize)>,
}

// VMMapOptionsBuilder is generated automatically, except the build function
impl VMMapOptionsBuilder {
    pub fn build(mut self) -> Result<VMMapOptions> {
        let size = {
            let size = self
                .size
                .ok_or_else(|| errno!(EINVAL, "invalid size for mmap"))?;
            if size == 0 {
                return_errno!(EINVAL, "invalid size for mmap");
            }
            align_up(size, PAGE_SIZE)
        };
        let align = {
            let align = self.align.unwrap_or(PAGE_SIZE);
            if align == 0 || align % PAGE_SIZE != 0 {
                return_errno!(EINVAL, "invalid size for mmap");
            }
            align
        };
        let perms = self
            .perms
            .ok_or_else(|| errno!(EINVAL, "perms must be given"))?;
        let addr = {
            let addr = self.addr.unwrap_or_default();
            match addr {
                // TODO: check addr + size overflow
                VMMapAddr::Any => VMMapAddr::Any,
                VMMapAddr::Hint(addr) => {
                    let addr = align_down(addr, PAGE_SIZE);
                    VMMapAddr::Hint(addr)
                }
                VMMapAddr::Need(addr_) | VMMapAddr::Force(addr_) => {
                    if addr_ % align != 0 {
                        return_errno!(EINVAL, "unaligned addr for fixed mmap");
                    }
                    addr
                }
            }
        };
        let initializer = match self.initializer.as_ref() {
            Some(initializer) => initializer.clone(),
            None => VMInitializer::default(),
        };
        let writeback_file = self.writeback_file.take().unwrap_or_default();
        Ok(VMMapOptions {
            size,
            align,
            perms,
            addr,
            initializer,
            writeback_file,
        })
    }
}

impl VMMapOptions {
    pub fn size(&self) -> &usize {
        &self.size
    }

    pub fn addr(&self) -> &VMMapAddr {
        &self.addr
    }

    pub fn perms(&self) -> &VMPerms {
        &self.perms
    }

    pub fn initializer(&self) -> &VMInitializer {
        &self.initializer
    }

    pub fn writeback_file(&self) -> &Option<(FileRef, usize)> {
        &self.writeback_file
    }
}

#[derive(Debug)]
pub struct VMRemapOptions {
    old_addr: usize,
    old_size: usize,
    new_size: usize,
    flags: MRemapFlags,
}

impl VMRemapOptions {
    pub fn new(
        old_addr: usize,
        old_size: usize,
        new_size: usize,
        flags: MRemapFlags,
    ) -> Result<Self> {
        let old_addr = if old_addr % PAGE_SIZE != 0 {
            return_errno!(EINVAL, "unaligned old address");
        } else {
            old_addr
        };
        let old_size = if old_size == 0 {
            // TODO: support old_size is zero for shareable mapping
            warn!("do not support old_size is zero");
            return_errno!(EINVAL, "invalid old size");
        } else {
            align_up(old_size, PAGE_SIZE)
        };
        if let Some(new_addr) = flags.new_addr() {
            if new_addr % PAGE_SIZE != 0 {
                return_errno!(EINVAL, "unaligned new address");
            }
        }
        let new_size = if new_size == 0 {
            return_errno!(EINVAL, "invalid new size");
        } else {
            align_up(new_size, PAGE_SIZE)
        };
        Ok(Self {
            old_addr,
            old_size,
            new_size,
            flags,
        })
    }

    pub fn old_addr(&self) -> usize {
        self.old_addr
    }

    pub fn old_size(&self) -> usize {
        self.old_size
    }

    pub fn new_size(&self) -> usize {
        self.new_size
    }

    pub fn flags(&self) -> MRemapFlags {
        self.flags
    }
}

/// Memory manager.
///
/// VMManager provides useful memory management APIs such as mmap, munmap, mremap, etc.
///
/// # Invariants
///
/// Behind the scene, VMManager maintains a list of VMArea that have been allocated.
/// (denoted as `self.vmas`). To reason about the correctness of VMManager, we give
/// the set of invariants hold by VMManager.
///
/// 1. The rule of sentry:
/// ```
/// self.range.begin() == self.vmas[0].start() == self.vmas[0].end()
/// ```
/// and
/// ```
/// self.range.end() == self.vmas[N-1].start() == self.vmas[N-1].end()
/// ```
/// where `N = self.vmas.len()`.
///
/// 2. The rule of non-emptyness:
/// ```
/// self.vmas[i].size() > 0, for 1 <= i < self.vmas.len() - 1
/// ```
///
/// 3. The rule of ordering:
/// ```
/// self.vmas[i].end() <= self.vmas[i+1].start() for 0 <= i < self.vmas.len() - 1
/// ```
///
/// 4. The rule of non-mergablility:
/// ```
/// self.vmas[i].end() !=  self.vmas[i+1].start() || self.vmas[i].perms() !=  self.vmas[i+1].perms()
///     for 1 <= i < self.vmas.len() - 2
/// ```
///
#[derive(Debug, Default)]
pub struct VMManager {
    range: VMRange,
    vmas: SgxMutex<Vec<VMArea>>,
    dirty: SgxMutex<VecDeque<VMRange>>,
    free: SgxMutex<Vec<VMRange>>,
    spin_lock: SpinLock,
}

struct SpinLock(SgxThreadSpinlock);

impl Debug for SpinLock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "spin lock")
    }
}

impl Default for SpinLock {
    fn default() -> SpinLock {
        SpinLock(SgxThreadSpinlock::new())
    }
}

// #[derive(Debug)]
// struct DirtyQueue {
//     inner: ArrayQueue<VMRange>
// }

// impl Default for DirtyQueue {
//     fn default() -> DirtyQueue {
//         DirtyQueue {
//             inner: ArrayQueue::<VMRange>::new(100),
//         }
//     }
// }

impl VMManager {
    pub fn from(addr: usize, size: usize) -> Result<VMManager> {
        let range = VMRange::new(addr, addr + size)?;
        let vmas = {
            let start = range.start();
            let end = range.end();
            let start_sentry = {
                let range = VMRange::new_empty(start)?;
                let perms = VMPerms::empty();
                VMArea::new(range, perms, None)
            };
            let end_sentry = {
                let range = VMRange::new_empty(end)?;
                let perms = VMPerms::empty();
                VMArea::new(range, perms, None)
            };
            let mut _vmas = Vec::with_capacity(100);
            _vmas.push(start_sentry);
            _vmas.push(end_sentry);
            SgxMutex::new(_vmas)
        };
        let dirty = SgxMutex::new(VecDeque::with_capacity(100));
        let spin_lock = SpinLock::default();
        let mut _free = Vec::with_capacity(100);
        _free.push(range.clone());
        let free = SgxMutex::new(_free);
        Ok(VMManager {
            range,
            vmas,
            dirty,
            free,
            spin_lock,
        })
    }

    pub fn range(&self) -> &VMRange {
        &self.range
    }

    // Need spin_lock
    pub fn munmap_dirty_range_by_hand(&self, dirty_queue: &mut VecDeque<VMRange>, idx: usize) {
        let dirty_range = dirty_queue.swap_remove_back(idx).unwrap();
        let old_vmas = {
            let mut old_vmas = Vec::new();
            let mut current = self.vmas.lock().unwrap();
            std::mem::swap(&mut *current, &mut old_vmas);
            old_vmas
        };
        let new_vmas = old_vmas
            .into_iter()
            .flat_map(|vma| {
                // Keep the two sentry VMA intact
                if vma.size() == 0 {
                    return vec![vma];
                }

                let intersection_vma = match vma.intersect(&dirty_range) {
                    None => return vec![vma],
                    Some(intersection_vma) => intersection_vma,
                };

                // File-backed VMA needs to be flushed upon munmap
                Self::flush_file_vma(&intersection_vma);

                // Reset memory permissions
                if !&intersection_vma.perms().is_default() {
                    Self::apply_perms(&intersection_vma, VMPerms::default());
                }
                intersection_vma.range().clean();
                vma.subtract(&intersection_vma)
            })
            .collect();
        *self.vmas.lock().unwrap() = new_vmas;
    }

    pub fn mmap(&self, mut options: VMMapOptions) -> Result<usize> {
        // TODO: respect options.align when mmap
        let addr = *options.addr();
        let size = *options.size();

        if let VMMapAddr::Force(addr) = addr {
            let force_vm_range = unsafe { VMRange::from_unchecked(addr, addr + size) };
            let mut dirty_queue = self.dirty.lock().unwrap();
            unsafe {
                self.spin_lock.0.lock();
            }
            //drop(dirty_queue);
            // First check if the range is in dirty queue
            if let Some(idx) = Self::find_dirty_vm_range_idx(&dirty_queue, &force_vm_range) {
                self.munmap_dirty_range_by_hand(&mut dirty_queue, idx);
                unsafe {
                    self.spin_lock.0.unlock();
                }
            } else {
                // The range is not munmapped yet
                unsafe {
                    self.spin_lock.0.unlock();
                }
                self.munmap_sync(addr, size)?;
            }
        }

        if let VMMapAddr::Hint(addr) = addr {
            let hint_vm_range = unsafe { VMRange::from_unchecked(addr, addr + size) };
            let mut dirty_queue = self.dirty.lock().unwrap();
            unsafe {
                self.spin_lock.0.lock();
            }
            //drop(dirty_queue);
            // Check if the range is in dirty queue
            if let Some(idx) = Self::find_dirty_vm_range_idx(&dirty_queue, &hint_vm_range) {
                self.munmap_dirty_range_by_hand(&mut dirty_queue, idx);
            }
            // If not in dirty queue, the range is in use. Do nothing.
            unsafe {
                self.spin_lock.0.unlock();
            }
        }

        // free list and vmas must be updated together
        unsafe {
            self.spin_lock.0.lock();
        }
        // Allocate a new range for this mmap request
        let new_free_range = self.find_free_range(size, addr)?;
        //let new_range = self.alloc_range_from(size, addr, &free_range);
        let new_addr = new_free_range.start();
        let writeback_file = options.writeback_file.take();
        let new_vma = VMArea::new(new_free_range, *options.perms(), writeback_file);

        // Initialize the memory of the new range
        unsafe {
            let buf = new_vma.as_slice_mut();
            options.initializer.init_slice(buf)?;
        }
        // Set memory permissions. Initial permission R/W
        if options.perms.can_execute() {
            Self::apply_perms(&new_vma, new_vma.perms());
        }
        //println!("1 mmap range vma: {:?}", new_vma);

        // After initializing, we can safely insert the new VMA
        //self.insert_new_vma(insert_idx, new_vma);
        self.vmas.lock().unwrap().push(new_vma);
        //println!("1 new vmas: {:?}", self.vmas.lock().unwrap());
        unsafe {
            self.spin_lock.0.unlock();
        }
        Ok(new_addr)
    }

    pub fn munmap(&self, addr: usize, size: usize) -> Result<()> {
        let size = {
            if size == 0 {
                return_errno!(EINVAL, "size of munmap must not be zero");
            }
            align_up(size, PAGE_SIZE)
        };
        let munmap_range = {
            let munmap_range = VMRange::new(addr, addr + size)?;

            let effective_munmap_range_opt = munmap_range.intersect(&self.range);
            if effective_munmap_range_opt.is_none() {
                return Ok(());
            }

            let effective_munmap_range = effective_munmap_range_opt.unwrap();
            if effective_munmap_range.empty() {
                return Ok(());
            }
            effective_munmap_range
        };

        let mut current = self.vmas.lock().unwrap();
        // unsafe {
        //     self.spin_lock.0.lock();
        // }
        let old_vmas = {
            let mut old_vmas = Vec::new();
            // let mut current = self.vmas.lock().unwrap();
            std::mem::swap(&mut *current, &mut old_vmas);
            old_vmas
        };
        let new_vmas = old_vmas
            .into_iter()
            .flat_map(|vma| {
                // Keep the two sentry VMA intact
                if vma.size() == 0 {
                    return vec![vma];
                }

                let intersection_vma = match vma.intersect(&munmap_range) {
                    None => return vec![vma],
                    Some(intersection_vma) => intersection_vma,
                };

                // File-backed VMA needs to be flushed upon munmap
                Self::flush_file_vma(&intersection_vma);

                // Reset memory permissions
                if !&intersection_vma.perms().is_default() {
                    Self::apply_perms(&intersection_vma, VMPerms::default());
                }
                //intersection_vma.range().clean();
                vma.subtract(&intersection_vma)
            })
            .collect();
        *current = new_vmas;
        drop(current);
        // unsafe {
        //     self.spin_lock.0.unlock();
        // }
        //println!("1 munmap range: {:?}", munmap_range);
        self.dirty.lock().unwrap().push_back(munmap_range);

        Ok(())
    }

    pub fn munmap_sync(&self, addr: usize, size: usize) -> Result<()> {
        let size = {
            if size == 0 {
                return_errno!(EINVAL, "size of munmap must not be zero");
            }
            align_up(size, PAGE_SIZE)
        };
        let munmap_range = {
            let munmap_range = VMRange::new(addr, addr + size)?;

            let effective_munmap_range_opt = munmap_range.intersect(&self.range);
            if effective_munmap_range_opt.is_none() {
                return Ok(());
            }

            let effective_munmap_range = effective_munmap_range_opt.unwrap();
            if effective_munmap_range.empty() {
                return Ok(());
            }
            effective_munmap_range
        };

        unsafe {
            self.spin_lock.0.lock();
        }
        let old_vmas = {
            let mut old_vmas = Vec::new();
            let mut current = self.vmas.lock().unwrap();
            std::mem::swap(&mut *current, &mut old_vmas);
            old_vmas
        };
        let new_vmas = old_vmas
            .into_iter()
            .flat_map(|vma| {
                // Keep the two sentry VMA intact
                if vma.size() == 0 {
                    return vec![vma];
                }

                let intersection_vma = match vma.intersect(&munmap_range) {
                    None => return vec![vma],
                    Some(intersection_vma) => intersection_vma,
                };

                // File-backed VMA needs to be flushed upon munmap
                Self::flush_file_vma(&intersection_vma);

                // Reset memory permissions
                if !&intersection_vma.perms().is_default() {
                    Self::apply_perms(&intersection_vma, VMPerms::default());
                }
                //intersection_vma.range().clean();
                vma.subtract(&intersection_vma)
            })
            .collect();
        *self.vmas.lock().unwrap() = new_vmas;
        unsafe {
            self.spin_lock.0.unlock();
        }
        Ok(())
    }

    pub fn update_munmap_range(&self) -> Result<()> {
        let mut working = true;
        while working {
            let mut dirty_queue = self.dirty.lock().unwrap();
            if !dirty_queue.is_empty() {
                if dirty_queue.len() == 1 {
                    working = false;
                }
                let munmap_range = dirty_queue.pop_front().unwrap();
                drop(dirty_queue);
                munmap_range.clean();
                let mut new_free_list = Vec::with_capacity(10);
                // free list and vmas must be updated together
                unsafe {
                    self.spin_lock.0.lock();
                }
                //let free_list = self.free.lock().unwrap();
                self.vmas
                    .lock()
                    .unwrap()
                    .sort_unstable_by(|vma_a, vma_b| vma_a.range().start.cmp(&vma_b.range().start));
                new_free_list = self.get_free_from_vmas(new_free_list);
                *self.free.lock().unwrap() = new_free_list;
                unsafe {
                    self.spin_lock.0.unlock();
                }
            } else {
                return Ok(());
            }
        }
        Ok(())
    }

    fn get_free_from_vmas(&self, mut free_list: Vec<VMRange>) -> Vec<VMRange> {
        let vmas = self.vmas.lock().unwrap();
        for (idx, range_pair) in vmas.windows(2).enumerate() {
            // Since we have two sentry vmas at both ends, we can be sure that the free
            // space only appears between two consecutive vmas.
            let pre_range = &range_pair[0];
            let next_range = &range_pair[1];

            let mut free_range = {
                let free_range_start = pre_range.end();
                let free_range_end = next_range.start();
                unsafe { VMRange::from_unchecked(free_range_start, free_range_end) }
            };
            free_list.push(free_range);
        }
        return free_list;
    }

    pub fn mremap(&self, options: &VMRemapOptions) -> Result<usize> {
        let old_addr = options.old_addr();
        let old_size = options.old_size();
        let old_range = VMRange::new_with_size(old_addr, old_size)?;
        let new_size = options.new_size();
        let flags = options.flags();

        #[derive(Clone, Copy, PartialEq)]
        enum SizeType {
            Same,
            Shrinking,
            Growing,
        };
        let size_type = if new_size == old_size {
            SizeType::Same
        } else if new_size < old_size {
            SizeType::Shrinking
        } else {
            SizeType::Growing
        };

        // Get the memory permissions of the old range
        let perms = {
            // The old range must be contained in one VMA
            let idx = self
                .find_containing_vma_idx(&old_range)
                .ok_or_else(|| errno!(EFAULT, "invalid range"))?;
            let containing_vma = &self.vmas.lock().unwrap()[idx];
            containing_vma.perms()
        };

        // Implement mremap as one optional mmap followed by one optional munmap.
        //
        // The exact arguments for the mmap and munmap are determined by the values of MRemapFlags
        // and SizeType. There is a total of 9 combinations between MRemapFlags and SizeType.
        // As some combinations result in the same mmap and munmap operations, the following code
        // only needs to match four patterns of (MRemapFlags, SizeType) and treat each case
        // accordingly.

        // Determine whether need to do mmap. And when possible, determine the returned address
        // TODO: should fill zeros even when extending a file-backed mapping?
        let (need_mmap, mut ret_addr) = match (flags, size_type) {
            (MRemapFlags::None, SizeType::Growing) => {
                let mmap_opts = VMMapOptionsBuilder::default()
                    .size(new_size - old_size)
                    .addr(VMMapAddr::Need(old_range.end()))
                    .perms(perms)
                    .initializer(VMInitializer::FillZeros())
                    .build()?;
                let ret_addr = Some(old_addr);
                (Some(mmap_opts), ret_addr)
            }
            (MRemapFlags::MayMove, SizeType::Growing) => {
                let prefered_new_range =
                    VMRange::new_with_size(old_addr + old_size, new_size - old_size)?;
                if self.is_free_range(&prefered_new_range) {
                    let mmap_ops = VMMapOptionsBuilder::default()
                        .size(prefered_new_range.size())
                        .addr(VMMapAddr::Need(prefered_new_range.start()))
                        .perms(perms)
                        .initializer(VMInitializer::FillZeros())
                        .build()?;
                    (Some(mmap_ops), Some(old_addr))
                } else {
                    let mmap_ops = VMMapOptionsBuilder::default()
                        .size(new_size)
                        .addr(VMMapAddr::Any)
                        .perms(perms)
                        .initializer(VMInitializer::CopyFrom { range: old_range })
                        .build()?;
                    // Cannot determine the returned address for now, which can only be obtained after calling mmap
                    let ret_addr = None;
                    (Some(mmap_ops), ret_addr)
                }
            }
            (MRemapFlags::FixedAddr(new_addr), _) => {
                let mmap_opts = VMMapOptionsBuilder::default()
                    .size(new_size)
                    .addr(VMMapAddr::Force(new_addr))
                    .perms(perms)
                    .initializer(VMInitializer::CopyFrom { range: old_range })
                    .build()?;
                let ret_addr = Some(new_addr);
                (Some(mmap_opts), ret_addr)
            }
            _ => (None, Some(old_addr)),
        };

        let need_munmap = match (flags, size_type) {
            (MRemapFlags::None, SizeType::Shrinking)
            | (MRemapFlags::MayMove, SizeType::Shrinking) => {
                let unmap_addr = old_addr + new_size;
                let unmap_size = old_size - new_size;
                Some((unmap_addr, unmap_size))
            }
            (MRemapFlags::MayMove, SizeType::Growing) => {
                if ret_addr.is_none() {
                    // We must need to do mmap. Thus unmap the old range
                    Some((old_addr, old_size))
                } else {
                    // We must choose to reuse the old range. Thus, no need to unmap
                    None
                }
            }
            (MRemapFlags::FixedAddr(new_addr), _) => {
                let new_range = VMRange::new_with_size(new_addr, new_size)?;
                if new_range.overlap_with(&old_range) {
                    return_errno!(EINVAL, "new range cannot overlap with the old one");
                }
                Some((old_addr, old_size))
            }
            _ => None,
        };

        // Perform mmap and munmap if needed
        if let Some(mmap_options) = need_mmap {
            let mmap_addr = self.mmap(mmap_options)?;

            if ret_addr.is_none() {
                ret_addr = Some(mmap_addr);
            }
        }
        if let Some((addr, size)) = need_munmap {
            self.munmap(addr, size).expect("never fail");
        }

        debug_assert!(ret_addr.is_some());
        Ok(ret_addr.unwrap())
    }

    pub fn mprotect(&self, addr: usize, size: usize, new_perms: VMPerms) -> Result<()> {
        let protect_range = VMRange::new_with_size(addr, size)?;

        unsafe {
            self.spin_lock.0.lock();
        }
        // FIXME: the current implementation requires the target range to be
        // contained in exact one VMA.
        let containing_idx = self
            .find_containing_vma_idx(&protect_range)
            .ok_or_else(|| {
                let dirty_queue = self.dirty.lock().unwrap();
                let idx = Self::find_dirty_vm_range_idx(&dirty_queue, &protect_range);
                //println!("protect range in dirty queue: {:?}", idx);
                unsafe {
                    self.spin_lock.0.unlock();
                }
                errno!(ENOMEM, "invalid range")
            })?;
        let mut vmas = self.vmas.lock().unwrap();
        let containing_vma = &vmas[containing_idx];

        let old_perms = containing_vma.perms();
        if new_perms == old_perms {
            unsafe {
                self.spin_lock.0.unlock();
            }
            return Ok(());
        }

        let same_start = protect_range.start() == containing_vma.start();
        let same_end = protect_range.end() == containing_vma.end();
        let containing_vma = &mut vmas[containing_idx];
        match (same_start, same_end) {
            (true, true) => {
                containing_vma.set_perms(new_perms);

                Self::apply_perms(containing_vma, containing_vma.perms());
            }
            (false, true) => {
                containing_vma.set_end(protect_range.start());

                let new_vma = VMArea::inherits_file_from(containing_vma, protect_range, new_perms);
                Self::apply_perms(&new_vma, new_vma.perms());
                drop(vmas);
                self.insert_new_vma(containing_idx + 1, new_vma);
            }
            (true, false) => {
                containing_vma.set_start(protect_range.end());

                let new_vma = VMArea::inherits_file_from(containing_vma, protect_range, new_perms);
                Self::apply_perms(&new_vma, new_vma.perms());
                drop(vmas);
                self.insert_new_vma(containing_idx, new_vma);
            }
            (false, false) => {
                // The containing VMA is divided into three VMAs:
                // Shrinked old VMA:    [containing_vma.start,     protect_range.start)
                // New VMA:             [protect_range.start,      protect_range.end)
                // Another new vma:     [protect_range.end,        containing_vma.end)

                let old_end = containing_vma.end();
                let protect_end = protect_range.end();

                // Shrinked old VMA
                containing_vma.set_end(protect_range.start());

                // New VMA
                let new_vma = VMArea::inherits_file_from(containing_vma, protect_range, new_perms);
                Self::apply_perms(&new_vma, new_vma.perms());

                // Another new VMA
                let new_vma2 = {
                    let range = VMRange::new(protect_end, old_end).unwrap();
                    VMArea::inherits_file_from(containing_vma, range, old_perms)
                };

                drop(containing_vma);
                drop(vmas);
                self.insert_new_vma(containing_idx + 1, new_vma);
                self.insert_new_vma(containing_idx + 2, new_vma2);
            }
        }
        unsafe {
            self.spin_lock.0.unlock();
        }

        Ok(())
    }

    /// Sync all shared, file-backed memory mappings in the given range by flushing the
    /// memory content to its underlying file.
    pub fn msync_by_range(&self, sync_range: &VMRange) -> Result<()> {
        if !self.range().is_superset_of(&sync_range) {
            return_errno!(ENOMEM, "invalid range");
        }
        //println!("msync range: {:?}", sync_range);
        unsafe {
            self.spin_lock.0.lock();
        }
        //println!("msync vmas: {:?}", self.vmas.lock().unwrap());
        let vmas = self.vmas.lock().unwrap();
        // FIXME: check if sync_range covers unmapped memory
        for (idx, vma) in vmas.iter().enumerate() {
            //println!("idx = {}", idx);
            let vma = match vma.intersect(sync_range) {
                None => continue,
                Some(vma) => vma,
            };
            Self::flush_file_vma(&vma);
        }
        unsafe {
            self.spin_lock.0.unlock();
        }
        Ok(())
    }

    /// Sync all shared, file-backed memory mappings of the given file by flushing
    /// the memory content to the file.
    pub fn msync_by_file(&self, sync_file: &FileRef) {
        unsafe {
            self.spin_lock.0.lock();
        }
        for vma in self.vmas.lock().unwrap().iter() {
            let is_same_file = |file: &FileRef| -> bool { Arc::ptr_eq(&file, &sync_file) };
            Self::flush_file_vma_with_cond(&vma, is_same_file);
        }
        unsafe {
            self.spin_lock.0.unlock();
        }
    }

    /// Flush a file-backed VMA to its file. This has no effect on anonymous VMA.
    fn flush_file_vma(vma: &VMArea) {
        Self::flush_file_vma_with_cond(vma, |_| true)
    }

    /// Same as flush_vma, except that an extra condition on the file needs to satisfy.
    fn flush_file_vma_with_cond<F: Fn(&FileRef) -> bool>(vma: &VMArea, cond_fn: F) {
        let (file, file_offset) = match vma.writeback_file().as_ref() {
            None => return,
            Some((file_and_offset)) => file_and_offset,
        };
        let file_writable = file
            .get_access_mode()
            .map(|ac| ac.writable())
            .unwrap_or_default();
        if !file_writable {
            return;
        }
        if !cond_fn(file) {
            return;
        }
        file.write_at(*file_offset, unsafe { vma.as_slice() });
    }

    pub fn find_mmap_region(&self, addr: usize) -> Result<VMRange> {
        // here needs spin lock
        let region = self
            .vmas
            .lock()
            .unwrap()
            .iter()
            .map(|vma| vma.range())
            .find(|vma| vma.contains(addr))
            .ok_or_else(|| errno!(ESRCH, "no mmap regions that contains the address"))?
            .clone();
        return Ok(region);
    }

    // Find a VMA that contains the given range, returning the VMA's index
    fn find_containing_vma_idx(&self, target_range: &VMRange) -> Option<usize> {
        self.vmas
            .lock()
            .unwrap()
            .iter()
            .position(|vma| vma.is_superset_of(target_range))
    }

    // Find the dirty vm_range idx in the dirty queue
    // Must be used within spin_lock
    fn find_dirty_vm_range_idx(
        dirty_queue: &VecDeque<VMRange>,
        target_range: &VMRange,
    ) -> Option<usize> {
        dirty_queue
            .iter()
            .position(|range| range.is_superset_of(target_range))
    }

    // Returns whether the requested range is free
    fn is_free_range(&self, request_range: &VMRange) -> bool {
        self.range.is_superset_of(request_range)
            && self
                .vmas
                .lock()
                .unwrap()
                .iter()
                .all(|range| range.overlap_with(request_range) == false)
    }

    // Find the free range that satisfies the constraints of size and address
    fn find_free_range(&self, size: usize, addr: VMMapAddr) -> Result<VMRange> {
        // TODO: reduce the complexity from O(N) to O(log(N)), where N is
        // the number of existing VMAs.

        // Record the minimal free range that satisfies the contraints
        let mut result_free_range: Option<VMRange> = None;
        let mut result_idx: Option<usize> = None;
        let mut free_list = self.free.lock().unwrap();

        for (idx, free_range) in free_list.iter().enumerate() {
            // Since we have two sentry vmas at both ends, we can be sure that the free
            // space only appears between two consecutive vmas.
            // let pre_range = &range_pair[0];
            // let next_range = &range_pair[1];

            // let mut free_range = {
            //     let free_range_start = pre_range.end();
            //     let free_range_end = next_range.start();

            //     let free_range_size = free_range_end - free_range_start;
            //     if free_range_size < size {
            //         continue;
            //     }

            //     unsafe { VMRange::from_unchecked(free_range_start, free_range_end) }
            // };
            let mut free_range = {
                if free_range.size() < size {
                    continue;
                }

                unsafe { VMRange::from_unchecked(free_range.start(), free_range.start() + size) }
            };

            match addr {
                // Want a minimal free_range
                VMMapAddr::Any => {}
                // Prefer to have free_range.start == addr
                VMMapAddr::Hint(addr) => {
                    if free_range.contains(addr) {
                        if free_range.end() - addr >= size {
                            free_range.start = addr;
                            //let insert_idx = idx + 1;
                            Self::free_list_update_range(free_list, idx, free_range);
                            return Ok(free_range);
                        }
                    }
                }
                // Must have free_range.start == addr
                VMMapAddr::Need(addr) | VMMapAddr::Force(addr) => {
                    if free_range.start() > addr {
                        return_errno!(ENOMEM, "not enough memory for fixed mmap");
                    }
                    if !free_range.contains(addr) {
                        continue;
                    }
                    if free_range.end() - addr < size {
                        return_errno!(ENOMEM, "not enough memory for fixed mmap");
                    }
                    free_range.start = addr;
                    //let insert_idx = idx + 1;
                    Self::free_list_update_range(free_list, idx, free_range);
                    return Ok(free_range);
                }
            }

            if result_free_range == None
                || result_free_range.as_ref().unwrap().size() > free_range.size()
            {
                result_free_range = Some(free_range);
                result_idx = Some(idx);
            }
        }

        if result_free_range.is_none() {
            return_errno!(ENOMEM, "not enough memory");
        }

        // let free_range = result_free_range.unwrap();
        // let insert_idx = result_idx.unwrap() + 1;
        // Ok((insert_idx, free_range))
        let index = result_idx.unwrap();
        let result_free_range = result_free_range.unwrap();
        Self::free_list_update_range(free_list, index, result_free_range);
        return Ok(result_free_range);
    }

    fn free_list_update_range(
        mut free_list: SgxMutexGuard<Vec<VMRange>>,
        index: usize,
        range: VMRange,
    ) {
        let ranges_after_subtraction = free_list[index].subtract(&range);
        free_list[index] = ranges_after_subtraction[0];
        if ranges_after_subtraction.len() > 1 {
            free_list.insert(index + 1, ranges_after_subtraction[1]);
        }
    }

    // Find the free range that satisfies the constraints of size and address
    fn find_free_range_by_vmas(&self, size: usize, addr: VMMapAddr) -> Result<(usize, VMRange)> {
        // TODO: reduce the complexity from O(N) to O(log(N)), where N is
        // the number of existing VMAs.

        // Record the minimal free range that satisfies the contraints
        let mut result_free_range: Option<VMRange> = None;
        let mut result_idx: Option<usize> = None;
        let vmas = self.vmas.lock().unwrap();

        for (idx, range_pair) in vmas.windows(2).enumerate() {
            // Since we have two sentry vmas at both ends, we can be sure that the free
            // space only appears between two consecutive vmas.
            let pre_range = &range_pair[0];
            let next_range = &range_pair[1];

            let mut free_range = {
                let free_range_start = pre_range.end();
                let free_range_end = next_range.start();

                let free_range_size = free_range_end - free_range_start;
                if free_range_size < size {
                    continue;
                }

                unsafe { VMRange::from_unchecked(free_range_start, free_range_end) }
            };

            match addr {
                // Want a minimal free_range
                VMMapAddr::Any => {}
                // Prefer to have free_range.start == addr
                VMMapAddr::Hint(addr) => {
                    if free_range.contains(addr) {
                        if free_range.end() - addr >= size {
                            free_range.start = addr;
                            let insert_idx = idx + 1;
                            return Ok((insert_idx, free_range));
                        }
                    }
                }
                // Must have free_range.start == addr
                VMMapAddr::Need(addr) | VMMapAddr::Force(addr) => {
                    if free_range.start() > addr {
                        return_errno!(ENOMEM, "not enough memory for fixed mmap");
                    }
                    if !free_range.contains(addr) {
                        continue;
                    }
                    if free_range.end() - addr < size {
                        return_errno!(ENOMEM, "not enough memory for fixed mmap");
                    }
                    free_range.start = addr;
                    let insert_idx = idx + 1;
                    return Ok((insert_idx, free_range));
                }
            }

            if result_free_range == None
                || result_free_range.as_ref().unwrap().size() > free_range.size()
            {
                result_free_range = Some(free_range);
                result_idx = Some(idx);
            }
        }

        if result_free_range.is_none() {
            return_errno!(ENOMEM, "not enough memory");
        }

        let free_range = result_free_range.unwrap();
        let insert_idx = result_idx.unwrap() + 1;
        Ok((insert_idx, free_range))
    }

    fn alloc_range_from(&self, size: usize, addr: VMMapAddr, free_range: &VMRange) -> VMRange {
        debug_assert!(free_range.size() >= size);

        let mut new_range = *free_range;

        if let VMMapAddr::Need(addr) = addr {
            debug_assert!(addr == new_range.start());
        }
        if let VMMapAddr::Force(addr) = addr {
            debug_assert!(addr == new_range.start());
        }

        new_range.resize(size);
        new_range
    }

    // Insert a new VMA, and when possible, merge it with its neighbors.
    fn insert_new_vma(&self, insert_idx: usize, new_vma: VMArea) {
        let vmas = &mut self.vmas.lock().unwrap();
        // New VMA can only be inserted between the two sentry VMAs
        debug_assert!(0 < insert_idx && insert_idx < vmas.len());

        let left_idx = insert_idx - 1;
        let right_idx = insert_idx;

        let left_vma = &vmas[left_idx];
        let right_vma = &vmas[right_idx];

        // Double check the order
        debug_assert!(left_vma.end() <= new_vma.start());
        debug_assert!(new_vma.end() <= right_vma.start());

        let left_mergable = Self::can_merge_vmas(left_vma, &new_vma);
        let right_mergable = Self::can_merge_vmas(&new_vma, right_vma);

        drop(left_vma);
        drop(right_vma);

        match (left_mergable, right_mergable) {
            (false, false) => {
                vmas.insert(insert_idx, new_vma);
            }
            (true, false) => {
                vmas[left_idx].set_end(new_vma.end);
            }
            (false, true) => {
                vmas[right_idx].set_start(new_vma.start);
            }
            (true, true) => {
                let left_new_end = vmas[right_idx].end();
                vmas[left_idx].set_end(left_new_end);
                vmas.remove(right_idx);
            }
        }
    }

    fn can_merge_vmas(left: &VMArea, right: &VMArea) -> bool {
        debug_assert!(left.end() <= right.start());

        // Both of the two VMAs must not be sentry (whose size == 0)
        if left.size() == 0 || right.size() == 0 {
            return false;
        }
        // The two VMAs must border with each other
        if left.end() != right.start() {
            return false;
        }
        // The two VMAs must have the same memory permissions
        if left.perms() != right.perms() {
            return false;
        }

        // If the two VMAs have write-back files, the files must be the same and
        // the two file regions must be continuous.
        let left_writeback_file = left.writeback_file();
        let right_writeback_file = right.writeback_file();
        match (left_writeback_file, right_writeback_file) {
            (None, None) => true,
            (Some(_), None) => false,
            (None, Some(_)) => false,
            (Some((left_file, left_offset)), Some((right_file, right_offset))) => {
                Arc::ptr_eq(&left_file, &right_file)
                    && right_offset > left_offset
                    && right_offset - left_offset == left.size()
            }
        }
    }

    fn apply_perms(protect_range: &VMRange, perms: VMPerms) {
        extern "C" {
            pub fn occlum_ocall_mprotect(
                retval: *mut i32,
                addr: *const c_void,
                len: usize,
                prot: i32,
            ) -> sgx_status_t;
        };

        unsafe {
            let mut retval = 0;
            let addr = protect_range.start() as *const c_void;
            let len = protect_range.size();
            let prot = perms.bits() as i32;
            let sgx_status = occlum_ocall_mprotect(&mut retval, addr, len, prot);
            assert!(sgx_status == sgx_status_t::SGX_SUCCESS && retval == 0);
        }
    }
}

impl Drop for VMManager {
    fn drop(&mut self) {
        // Ensure that memory permissions are recovered
        for vma in self.vmas.lock().unwrap().iter() {
            if vma.size() == 0 || vma.perms() == VMPerms::default() {
                continue;
            }
            Self::apply_perms(&vma, VMPerms::default());
        }
    }
}

pub extern "C" fn mem_worker_thread_start(main: *mut libc::c_void) -> *mut libc::c_void {
    let mut done = DONE.lock().unwrap();
    while unsafe { RUNNING } {
        //println!("in a custom thread");
        let all_process = get_all_processes();
        for process in all_process.iter() {
            if let Some(thread) = process.main_thread() {
                thread.vm().get_mmap_manager().update_munmap_range();
            }
        }
        // let all_thread = get_all_threads();
        // for thread in all_thread.iter() {
        //     if thread.status() == ThreadStatus::Exited {
        //         continue;
        //     }
        //     thread.vm().get_mmap_manager().update_munmap_range();
        // }
    }
    *done = true;
    drop(done);
    ptr::null_mut()
}
