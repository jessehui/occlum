use std::ops::{Deref, DerefMut};

use super::page_tracker::PageTracker;
use super::vm_perms::VMPerms;
use super::vm_range::VMRange;
use super::vm_util::{FileBacked, PagePolicy, VMInitializer, VMMapOptions};
use super::*;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use super::vm_epc::EPCMemType;
use intrusive_collections::rbtree::{Link, RBTree};
use intrusive_collections::{intrusive_adapter, KeyAdapter};

// Commit memory size when the PF occurs.
// const COMMIT_ONCE_SIZE: usize = 256 * PAGE_SIZE;

const COMMIT_ONCE_SIZE: usize = 4 * PAGE_SIZE;
#[derive(Clone, Debug)]
pub struct VMArea {
    range: VMRange,
    perms: VMPerms,
    file_backed: Option<FileBacked>,
    pid: pid_t,
    pages: Option<PageTracker>, // Track the paging status of this VMA
    epc_type: EPCMemType,       // Track the type of the EPC to use specific APIs
}

impl VMArea {
    pub fn new(
        range: VMRange,
        perms: VMPerms,
        // initializer: Option<VMInitializer>,
        file_backed: Option<FileBacked>,
        pid: pid_t,
        // lazy_extend_perms: Option<VMPerms>,
    ) -> Self {
        let epc_type = EPCMemType::new(&range);
        let pages = {
            let pages = PageTracker::new_vma_tracker(&range, &epc_type).unwrap();
            if pages.is_fully_committed() {
                None
            } else {
                Some(pages)
            }
        };

        let new_vma = Self {
            range,
            perms,
            file_backed,
            // initializer,
            pid,
            pages,
            epc_type,
            // lazy_extend_perms,
        };
        trace!("new vma = {:?}", new_vma);
        new_vma
    }

    // Create the VMA specifically for the gap
    pub fn new_gap(gap_range: VMRange) -> Self {
        let epc_type = EPCMemType::Gap;
        let new_vma = Self {
            range: gap_range,
            perms: VMPerms::default(),
            file_backed: None,
            pid: 0,
            pages: None,
            epc_type,
        };
        new_vma
    }

    fn new_with_page_tracker(
        range: VMRange,
        perms: VMPerms,
        file_backed: Option<FileBacked>,
        pid: pid_t,
        pages: Option<PageTracker>,
    ) -> VMArea {
        let epc_type = EPCMemType::new(&range);
        Self {
            range,
            perms,
            file_backed,
            // initializer,
            pid,
            pages,
            epc_type,
            // lazy_extend_perms,
        }
    }

    /// Create a new VMArea object that inherits the write-back file (if any), but has
    /// a new range and permissions.
    pub fn inherits_file_from(
        vma: &VMArea,
        new_range: VMRange,
        new_perms: VMPerms,
        pid: pid_t,
    ) -> Self {
        trace!("inherits file from vma: {:?}", vma);
        trace!("new range = {:?}", new_range);
        debug_assert!(vma.range.is_superset_of(&new_range));

        let new_backed_file = if let Some(file) = &vma.file_backed {
            let mut new_file = file.clone();
            let file_offset = file.offset();

            debug_assert!(vma.start() <= new_range.start());
            let new_start_offset = new_range.start() - vma.start();
            let new_file_offset = file_offset + new_start_offset;

            trace!("new file offset = {:?}", new_file_offset);
            new_file.set_offset(new_file_offset);
            Some(new_file)
        } else {
            None
        };

        let new_pages = {
            let mut new_pages = vma.pages.clone();

            if let Some(pages) = &mut new_pages {
                pages.split_for_new_range(&new_range);
                if pages.is_fully_committed() {
                    None
                } else {
                    new_pages
                }
            } else {
                None
            }
        };

        let new_vma =
            Self::new_with_page_tracker(new_range, new_perms, new_backed_file, pid, new_pages);

        new_vma
    }

    pub fn perms(&self) -> VMPerms {
        self.perms
    }

    pub fn range(&self) -> &VMRange {
        &self.range
    }

    fn pages(&self) -> &PageTracker {
        debug_assert!(!self.is_fully_committed());
        self.pages.as_ref().unwrap()
    }

    fn pages_mut(&mut self) -> &mut PageTracker {
        debug_assert!(!self.is_fully_committed());
        self.pages.as_mut().unwrap()
    }

    pub fn pid(&self) -> pid_t {
        self.pid
    }

    pub fn is_reserved_only(&self) -> bool {
        if let Some(pages) = &self.pages {
            return pages.is_reserved_only();
        } else {
            false
        }
    }

    pub fn is_fully_committed(&self) -> bool {
        self.pages.is_none()
    }

    pub fn is_partially_committed(&self) -> bool {
        if let Some(pages) = &self.pages {
            return pages.is_partially_committed();
        } else {
            false
        }
    }

    pub fn init_memory(mut self, options: &VMMapOptions) -> Result<Self> {
        trace!("init_memory");
        let mut vm_area = self;
        let page_policy = options.page_policy();

        // Commit pages if needed
        if !vm_area.is_fully_committed() && page_policy == &PagePolicy::CommitNow {
            vm_area.pages_mut().commit_current_vma_whole()?;
            vm_area.pages = None;
        }

        // Initialize committed memory
        if vm_area.is_partially_committed() {
            return vm_area
                .init_committed_memory(options.initializer())
                .map(|_| vm_area);
        } else if vm_area.is_fully_committed() {
            // Initialize the memory of the new range
            unsafe {
                trace!("vma is fully committed");
                let buf = vm_area.range().as_slice_mut();
                options.initializer().init_slice(buf)?;
            }

            // Set memory permissions
            if !options.perms().is_default() {
                vm_area.modify_protection_force(None, vm_area.perms());
            }
            return Ok(vm_area);
        }

        // This vma has no committed memory
        debug_assert!(vm_area.is_reserved_only());
        Ok(vm_area)
    }

    pub fn flush_memory(&self) -> Result<()> {
        if self.is_partially_committed() {
            return self.flush_committed_memory();
        } else if self.is_fully_committed() {
            if !self.perms().is_default() {
                self.modify_protection_force(None, VMPerms::default());
            }

            self.flush_file_vma();

            unsafe {
                let buf = self.as_slice_mut();
                buf.iter_mut().for_each(|b| *b = 0)
            }
        }

        Ok(())
    }

    /// Flush a file-backed VMA to its file. This has no effect on anonymous VMA.
    pub fn flush_file_vma(&self) {
        self.flush_file_vma_with_cond(|_| true)
    }

    /// Same as flush_vma, except that an extra condition on the file needs to satisfy.
    pub fn flush_file_vma_with_cond<F: Fn(&FileRef) -> bool>(&self, cond_fn: F) {
        let (file_handle, file_offset) = match self.writeback_file() {
            None => return,
            Some((file_and_offset)) => file_and_offset,
        };
        let file_writable = file_handle.access_mode().unwrap().writable();
        if !file_writable {
            return;
        }
        if !cond_fn(file_handle) {
            return;
        }
        file_handle.write_at(file_offset, unsafe { self.as_slice() });
    }

    pub fn modify_permissions_for_committed_pages(
        &mut self,
        old_perms: VMPerms,
        new_perms: VMPerms,
        force: bool,
    ) {
        if self.is_fully_committed() {
            self.modify_protection_force(None, new_perms);
        } else if self.is_partially_committed() {
            let committed = true;
            for range in self.pages().get_ranges(committed) {
                self.modify_protection_force(Some(&range), new_perms);
            }
        }
    }

    pub fn handle_page_fault(&mut self, pf_addr: usize, kernel_triggers: bool) -> Result<()> {
        info!("PF vma = {:?}", self);

        if self.is_fully_committed() {
            if self.perms() == VMPerms::NONE {
                return_errno!(
                    EACCES,
                    "Page is set to None permission. This is user-intended"
                );
            } else {
                // This vma has been commited by other threads already. Just return.
                info!("This vma has been committed by other threads already.");
                return Ok(());
            }
        }

        if matches!(self.epc_type, EPCMemType::Reserved) {
            return_errno!(EINVAL, "reserved memory shouldn't trigger PF");
        }

        if kernel_triggers {
            return self.commit_current_vma_whole();
        }

        // The return commit_size can be 0 when other threads already commit the PF-containing range but the vma is not fully committed yet.
        let commit_size = self.commit_once_for_page_fault(pf_addr).unwrap();

        info!("page fault commit memory size = {:?}", commit_size);

        info!("page fault handle success");

        Ok(())
    }

    pub fn init_file(&self) -> Option<(&FileRef, usize)> {
        if let Some(file) = &self.file_backed {
            Some(file.init_file())
        } else {
            None
        }
    }

    pub fn writeback_file(&self) -> Option<(&FileRef, usize)> {
        if let Some(file) = &self.file_backed {
            file.writeback_file()
        } else {
            None
        }
    }

    pub fn set_perms(&mut self, new_perms: VMPerms) {
        self.perms = new_perms;
    }

    pub fn subtract(&self, other: &VMRange) -> Vec<VMArea> {
        self.deref()
            .subtract(other)
            .into_iter()
            .map(|range| Self::inherits_file_from(self, range, self.perms(), self.pid()))
            .collect()
    }

    // Returns an non-empty intersection if where is any
    pub fn intersect(&self, other: &VMRange) -> Option<VMArea> {
        let new_range = {
            let new_range = self.range().intersect(other);
            if new_range.is_none() {
                return None;
            }
            new_range.unwrap()
        };
        let new_vma = VMArea::inherits_file_from(self, new_range, self.perms(), self.pid());
        trace!("intersect new_vma = {:?}", new_vma);
        Some(new_vma)
    }

    pub fn set_start(&mut self, new_start: usize) {
        let old_start = self.start();
        if new_start == old_start {
            return;
        }

        self.range.set_start(new_start);

        if new_start < old_start {
            // Extend this VMA
            let pages = {
                let pages = PageTracker::new_vma_tracker(&self.range, &self.epc_type).unwrap();
                if pages.is_fully_committed() {
                    None
                } else {
                    Some(pages)
                }
            };
            self.pages = pages;
        } else {
            // Split this VMA
            debug_assert!(new_start > old_start);
            if let Some(pages) = &mut self.pages {
                pages.split_for_new_range(&self.range);
                if pages.is_fully_committed() {
                    self.pages = None;
                }
            }
        }

        if let Some(file) = self.file_backed.as_mut() {
            // If the updates to the VMA needs to write back to a file, then the
            // file offset must be adjusted according to the new start address.
            Self::set_file_offset(file, new_start, old_start);
        }

        // if let Some(initializer) = self.initializer.as_mut() {
        //     match initializer {
        //         VMInitializer::FileBacked { file } => {
        //             Self::set_file_offset(file, new_start, old_start);
        //         }
        //         VMInitializer::DoNothing() | VMInitializer::FillZeros() => {}
        //         _ => todo!(),
        //     }
        // }
    }

    fn set_file_offset(file: &mut FileBacked, new_start_offset: usize, old_start_offset: usize) {
        let offset = file.offset();
        if old_start_offset < new_start_offset {
            file.set_offset(offset + (new_start_offset - old_start_offset));
        } else {
            // The caller must guarantee that the new start makes sense
            debug_assert!(offset >= old_start_offset - new_start_offset);
            file.set_offset(offset - (old_start_offset - new_start_offset));
        }
    }

    pub fn is_the_same_to(&self, other: &VMArea) -> bool {
        if self.pid() != other.pid() {
            return false;
        }

        if self.range() != other.range() {
            return false;
        }

        if self.perms() != other.perms() {
            return false;
        }

        let self_init_file = self.init_file();
        let other_init_file = other.init_file();
        match (self_init_file, other_init_file) {
            (None, None) => return true,
            (Some(_), None) => return false,
            (None, Some(_)) => return false,
            (Some((self_file, self_offset)), Some((other_file, other_offset))) => {
                Arc::ptr_eq(&self_file, &other_file) && self_offset == other_offset
            }
        }
    }

    pub fn set_end(&mut self, new_end: usize) {
        self.range.set_end(new_end);
        let pages = if self.range.size() > 0 {
            let pages = PageTracker::new_vma_tracker(&self.range, &self.epc_type).unwrap();
            if pages.is_fully_committed() {
                None
            } else {
                Some(pages)
            }
        } else {
            // self.range.size() == 0
            None
        };
        self.pages = pages;
    }

    pub fn can_merge_vmas(left: &VMArea, right: &VMArea) -> bool {
        debug_assert!(left.end() <= right.start());

        // Both of the two VMAs must not be sentry (whose size == 0)
        if left.size() == 0 || right.size() == 0 {
            return false;
        }
        // The two VMAs must be owned by the same process
        if left.pid() != right.pid() {
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
        let left_init_file = left.init_file();
        let right_init_file = right.init_file();
        match (left_init_file, right_init_file) {
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

    fn modify_protection_force(&self, protect_range: Option<&VMRange>, new_perms: VMPerms) {
        let protect_range = if let Some(range) = protect_range {
            range
        } else {
            self.range()
        };

        self.epc_type
            .modify_protection(protect_range.start(), protect_range.size(), new_perms)
            .unwrap()
    }

    fn init_committed_memory_internal(
        &mut self,
        target_range: &VMRange,
        // force_perm: bool,
        initializer: Option<&VMInitializer>,
    ) -> Result<()> {
        debug_assert!(self.range().is_superset_of(target_range));
        trace!("init range = {:?}", target_range);
        let init_file = self
            .init_file()
            .map(|(file, offset)| (file.clone(), offset));
        if let Some((file, offset)) = init_file {
            let vma_range_start = self.range.start();

            let init_file_offset = offset + (target_range.start() - vma_range_start);

            self.init_file_backed_mem(
                target_range,
                &file,
                init_file_offset,
                self.perms(),
                // force_perm,
            )?;
        } else if let Some(initializer) = initializer {
            match initializer {
                VMInitializer::FileBacked { .. } => unreachable!(), // Should be handled above
                VMInitializer::DoNothing() => {
                    if !self.perms().is_default() {
                        self.modify_protection_force(Some(target_range), self.perms());
                    }
                }
                VMInitializer::FillZeros() => {
                    unsafe {
                        let buf = target_range.as_slice_mut();
                        buf.iter_mut().for_each(|b| *b = 0);
                    }
                    if !self.perms().is_default() {
                        self.modify_protection_force(Some(target_range), self.perms());
                    }
                }
                _ => todo!(),
            }
        } else {
            // PF triggered, no file-backed memory, just modify protection
            if !self.perms().is_default() {
                self.modify_protection_force(Some(target_range), self.perms());
            }
        }

        Ok(())
    }

    fn init_file_backed_mem(
        &mut self,
        target_range: &VMRange,
        file: &FileRef,
        file_offset: usize,
        new_perm: VMPerms,
        // force_perm: bool,
    ) -> Result<()> {
        if !file.access_mode().unwrap().readable() {
            return_errno!(EBADF, "file is not readable");
        }

        let buf = unsafe { target_range.as_slice_mut() };
        let file_size = file.metadata().unwrap().size;

        let len = file
            .read_at(file_offset, buf)
            .map_err(|_| errno!(EACCES, "failed to init memory from file"))?;
        trace!("file offset = {:?}, read len = {:?}", file_offset, len);
        trace!("file total size = {:?}", file_size);

        if !new_perm.is_default() {
            self.modify_protection_force(Some(target_range), new_perm);
        }

        Ok(())
    }

    // Inintialize the VMA memory if the VMA is partially committed
    fn init_committed_memory(&mut self, initializer: &VMInitializer) -> Result<()> {
        debug_assert!(self.is_partially_committed());
        let committed = true;
        let is_handle_pf = false;
        for range in self.pages().get_ranges(committed) {
            trace!("init committed memory: {:?}", range);
            self.init_committed_memory_internal(&range, Some(initializer))?;
        }

        Ok(())
    }

    pub fn flush_committed_memory(&self) -> Result<()> {
        debug_assert!(self.is_partially_committed());
        trace!("flush committed memory");

        let (need_flush, file, file_offset) = match self.writeback_file() {
            None => (false, None, None),
            Some((file_handle, offset)) => {
                if !file_handle.access_mode().unwrap().writable() {
                    (false, None, None)
                } else {
                    (true, Some(file_handle), Some(offset))
                }
            }
        };

        let vm_range_start = self.range.start();
        let committed = true;
        for range in self.pages().get_ranges(committed) {
            info!("flush committed range: {:?}", range);
            let buf = unsafe { range.as_slice_mut() };
            if !self.perms().is_default() {
                self.modify_protection_force(Some(&range), VMPerms::default());
            }

            if need_flush {
                let file_offset = file_offset.unwrap() + (range.start() - vm_range_start);
                file.unwrap().write_at(file_offset, buf);
            }

            // reset zeros
            trace!("reset zeros for range: {:?}", range);
            unsafe {
                buf.iter_mut().for_each(|b| *b = 0);
            }
        }
        Ok(())
    }

    pub fn commit_once_for_page_fault(&mut self, pf_addr: usize) -> Result<usize> {
        debug_assert!(!self.is_fully_committed());
        let mut early_return = false;
        let mut total_commit_size = 0;
        let vma_range_start = self.range.start();
        let permission = self.perms();
        let committed = false;
        let mut uncommitted_ranges = self.pages().get_ranges(committed);

        for range in uncommitted_ranges.iter_mut() {
            info!("uncommitted memory range = {:?}", range);
            if total_commit_size == 0 {
                if !range.contains(pf_addr) {
                    // loop until finding the uncommitted range which contains pf_addr
                    continue;
                } else {
                    info!("pf addr = 0x{:x}, uncommitted range = {:?}", pf_addr, range);
                    // TODO: Support commit memory from the nearest page of the page fault
                    // let old_start = range.start();
                    // let pf_page_addr = align_down(pf_addr, PAGE_SIZE);
                    // range.set_start(pf_page_addr);
                    // debug_assert!(range.start() >= old_start);
                    // if range.start() != old_start {
                    //     debug_assert!(pf_addr != range.start());
                    //     debug_assert!(pf_addr - range.start() < PAGE_SIZE);
                    //     info!("set commit range start from old start address: {:x}, to new start address: {:x}", old_start, range.start());
                    // }
                    info!("target commit range = {:?}", range);
                }
            }

            if range.size() + total_commit_size > COMMIT_ONCE_SIZE {
                info!("before resize, target range = {:?}", range);
                let old_size = range.size();
                range.resize(COMMIT_ONCE_SIZE - total_commit_size);

                // For the first time commit, the range must contain the #PF address
                if total_commit_size == 0 && !range.contains(pf_addr) {
                    // Resize back if the new range doesn't contain #PF address
                    range.resize(old_size);
                }
                info!("after resize, target range = {:?}", range);
            }

            // Commit memory
            self.pages
                .as_mut()
                .unwrap()
                .commit_range_for_current_vma(range)?;
            self.init_committed_memory_internal(&range, None)?;

            total_commit_size += range.size();
            info!("total_commit_size + range size {:?}", range.size());
            if total_commit_size >= COMMIT_ONCE_SIZE {
                break;
            }
        }

        if self.pages().is_fully_committed() {
            self.pages = None;
            // self.initializer = None;
        }

        info!("ret total_commit_size = {:?}", total_commit_size);
        Ok(total_commit_size)
    }

    fn commit_current_vma_whole(&mut self) -> Result<()> {
        debug_assert!(!self.is_fully_committed());

        // Commit EPC
        let commit_mem_length = self.pages_mut().commit_current_vma_whole()?;
        debug_assert!(commit_mem_length > 0);

        self.pages = None;

        // Reset perms if needed
        let need_reset_perms = !self.is_reserved_only() && self.init_file().is_some();
        if need_reset_perms {
            self.modify_protection_force(None, VMPerms::DEFAULT);
        }

        // Init new committed memory
        let range = self.range().clone();
        self.init_committed_memory_internal(&range, None)?;

        Ok(())
    }

    // TODO: We can re-enable this when we support lazy extend permissions.
    #[allow(dead_code)]
    fn page_fault_handler_extend_permission(&mut self, pf_addr: usize) -> Result<()> {
        let permission = self.perms();

        // This is intended by the application.
        if permission == VMPerms::NONE {
            return_errno!(EPERM, "trying to access PROT_NONE memory");
        }

        if self.is_fully_committed() {
            self.modify_protection_force(None, permission);
            return Ok(());
        }

        let committed = true;
        let committed_ranges = self.pages().get_ranges(committed);
        for range in committed_ranges.iter() {
            if !range.contains(pf_addr) {
                continue;
            }

            self.epc_type
                .modify_protection(range.start(), range.size(), permission)?;
        }

        Ok(())
    }

    fn dump_committed_mem(&self) -> Result<()> {
        info!("dump committed memory");
        if !self.is_fully_committed() {
            let committed_ranges = self.pages().get_ranges(true);
            for range in committed_ranges.iter() {
                info!("committed range = {:?}", range);
                let buf = unsafe { range.as_slice() };
                let mut s = DefaultHasher::new();
                buf.hash(&mut s);
                let hash = s.finish();
                eprintln!("committed buf hash = {:?}", hash);
            }
        } else {
            let buf = unsafe { self.as_slice() };
            let mut s = DefaultHasher::new();
            buf.hash(&mut s);
            let hash = s.finish();
            eprintln!("vma fully committed. buf hash = {:?}", hash);
        }

        Ok(())
    }
}

impl Deref for VMArea {
    type Target = VMRange;

    fn deref(&self) -> &Self::Target {
        &self.range
    }
}

#[derive(Clone)]
pub struct VMAObj {
    link: Link,
    vma: VMArea,
}

impl fmt::Debug for VMAObj {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self.vma)
    }
}

// key adapter for RBTree which is sorted by the start of vma ranges
intrusive_adapter!(pub VMAAdapter = Box<VMAObj>: VMAObj { link : Link });
impl<'a> KeyAdapter<'a> for VMAAdapter {
    type Key = usize;
    fn get_key(&self, vma_obj: &'a VMAObj) -> usize {
        vma_obj.vma.range().start()
    }
}

impl VMAObj {
    pub fn new_vma_obj(vma: VMArea) -> Box<Self> {
        Box::new(Self {
            link: Link::new(),
            vma,
        })
    }

    pub fn vma(&self) -> &VMArea {
        &self.vma
    }
}
