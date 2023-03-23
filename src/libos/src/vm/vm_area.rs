use std::ops::{Deref, DerefMut};

use super::page_tracker::PageTracker;
use super::vm_perms::VMPerms;
use super::vm_range::VMRange;
use super::vm_util::{FileBacked, PagePolicy, VMMapOptions};
use super::*;

use super::vm_epc::EPC;
use intrusive_collections::rbtree::{Link, RBTree};
use intrusive_collections::{intrusive_adapter, KeyAdapter};

// Commit memory size when the PF occurs.
const COMMIT_ONCE_SIZE: usize = 1 * PAGE_SIZE;

#[derive(Clone, Debug)]
pub struct VMArea {
    range: VMRange,
    perms: VMPerms,
    initializer: Option<VMInitializer>, // Record the initializer for lazy intialization in PF handler
    file_backed: Option<FileBacked>,
    pid: pid_t,
    pages: Option<PageTracker>, // Track the paging status of this VMA
    epc_type: EPC,              // Track the type of the EPC to use specific APIs
    lazy_extend_perms: Option<VMPerms>, // To know if this VMA is lazyly extending permission by tracking the old permission.
}

impl VMArea {
    pub fn new(
        range: VMRange,
        perms: VMPerms,
        initializer: Option<VMInitializer>,
        file_backed: Option<FileBacked>,
        pid: pid_t,
        lazy_extend_perms: Option<VMPerms>,
    ) -> Self {
        let epc_type = EPC::new(&range);
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
            initializer,
            pid,
            pages,
            epc_type,
            lazy_extend_perms,
        };
        trace!("new vma = {:?}", new_vma);
        new_vma
    }

    // Create the VMA specifically for the gap
    pub fn new_gap(gap_range: VMRange) -> Self {
        let pages = {
            let pages = PageTracker::new_gap_tracker(&gap_range).unwrap();
            if pages.is_fully_committed() {
                None
            } else {
                Some(pages)
            }
        };
        let epc_type = EPC::GapMem;
        let new_vma = Self {
            range: gap_range,
            perms: VMPerms::default(),
            initializer: None,
            file_backed: None,
            pid: 0,
            pages,
            epc_type,
            lazy_extend_perms: None,
        };
        new_vma
    }

    /// Create a new VMArea object that inherits the write-back file (if any), but has
    /// a new range and permissions.
    pub fn inherits_file_from(
        vma: &VMArea,
        new_range: VMRange,
        new_perms: VMPerms,
        pid: pid_t,
    ) -> Self {
        let (new_backed_file, new_initializer) = if let Some(file) = &vma.file_backed {
            let mut new_file = file.clone();
            let file_offset = file.offset();

            let new_file_offset = if vma.start() < new_range.start() {
                let vma_offset = new_range.start() - vma.start();
                file_offset + vma_offset
            } else {
                let vma_offset = vma.start() - new_range.start();
                debug_assert!(file_offset >= vma_offset);
                file_offset - vma_offset
            };

            new_file.set_offset(new_file_offset);
            let new_initializer = Some(VMInitializer::FileBacked {
                file: new_file.clone(),
            });
            (Some(new_file), new_initializer)
        } else {
            (None, vma.initializer().clone())
        };

        Self::new(
            new_range,
            new_perms,
            new_initializer,
            new_backed_file,
            pid,
            vma.lazy_extend_perms,
        )
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

    pub fn initializer(&self) -> &Option<VMInitializer> {
        &self.initializer
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
        let mut first_time_commit = false;
        let mut vm_area = self;
        let page_policy = options.page_policy();

        // Commit pages if needed
        if !vm_area.is_fully_committed() && page_policy == &PagePolicy::CommitNow {
            vm_area.pages_mut().commit_current_vma(true)?;
            first_time_commit = true;
        }

        // Initialize committed memory
        if vm_area.is_partially_committed() {
            vm_area.init_committed_memory()?;
        } else if vm_area.is_fully_committed() {
            // Initialize the memory of the new range
            unsafe {
                let buf = vm_area.range().as_slice_mut();
                options.initializer().init_slice(buf, first_time_commit)?;
            }

            // Set memory permissions
            if !options.perms().is_default() {
                vm_area.modify_protection_lazy(
                    None,
                    VMPerms::DEFAULT,
                    vm_area.perms(),
                    page_policy == &PagePolicy::CommitNow,
                );
            }
        }
        Ok(vm_area)
    }

    pub fn flush_memory(&self) -> Result<()> {
        if self.is_partially_committed() {
            return self.flush_committed_memory();
        }

        if self.is_fully_committed() {
            if !self.perms().is_default() || self.need_reset_perms() {
                self.modify_protection_force(self.range(), VMPerms::default());
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
        let (file, file_offset) = match self.writeback_file() {
            None => return,
            Some((file_and_offset)) => file_and_offset,
        };
        let file_handle = file.as_async_file_handle().unwrap();
        let file_writable = file_handle.access_mode().writable();
        if !file_writable {
            return;
        }
        if !cond_fn(file) {
            return;
        }
        file_handle
            .dentry()
            .inode()
            .as_sync_inode()
            .unwrap()
            .write_at(file_offset, unsafe { self.as_slice() });
    }

    pub fn modify_permissions_for_committed_pages(
        &mut self,
        old_perms: VMPerms,
        new_perms: VMPerms,
        force: bool,
    ) {
        if self.is_fully_committed() {
            self.modify_protection_lazy(None, old_perms, new_perms, force);
        } else if self.is_partially_committed() {
            let committed = true;
            for range in self.pages().get_ranges(committed) {
                self.modify_protection_lazy(Some(&range), old_perms, new_perms, force);
            }
        }
    }

    pub fn handle_page_fault(
        &mut self,
        pf_addr: usize,
        is_protection_violation: bool,
    ) -> Result<()> {
        info!("PF vma = {:?}", self);
        // let (pf_page_start_addr, commit_size, permission) =
        //     (self.start(), self.size(), self.perms());
        // warn!(
        //     "pf_page_start_addr = 0x{:x}, commit_size = 0x{:x}, perms = {:?}",
        //     pf_page_start_addr, commit_size, permission
        // );
        // debug_assert!(pf_page_start_addr % PAGE_SIZE == 0);
        // debug_assert!(commit_size % PAGE_SIZE == 0);

        if matches!(self.epc_type, EPC::ReservedMem(_)) {
            return_errno!(EINVAL, "reserved memory shouldn't trigger PF");
        }
        // TODO: Decide if the PF is triggered by non-committed page or protection violation
        if self.is_reserved_only() {
            let commit_size = self.commit_once_for_page_fault(pf_addr)?;
            debug_assert!(commit_size != 0);
            return Ok(());
        }

        if self.is_fully_committed() {
            info!("committed. Only extend permission");
            return self.page_fault_handler_extend_permission(pf_addr);
        }

        let commit_size = self.commit_once_for_page_fault(pf_addr)?;
        if commit_size == 0 {
            info!("commit_size = 0, try extend permission");
            return self.page_fault_handler_extend_permission(pf_addr);
        }

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
        Some(new_vma)
    }

    pub fn set_start(&mut self, new_start: usize) {
        let old_start = self.start();
        self.range.set_start(new_start);

        let pages = {
            let pages = PageTracker::new_vma_tracker(&self.range, &self.epc_type).unwrap();
            if pages.is_fully_committed() {
                None
            } else {
                Some(pages)
            }
        };
        self.pages = pages;

        if let Some(file) = self.file_backed.as_mut() {
            if !file.need_write_back() {
                return;
            }
            // If the updates to the VMA needs to write back to a file, then the
            // file offset must be adjusted according to the new start address.
            let offset = file.offset();
            if old_start < new_start {
                file.set_offset(offset + (new_start - old_start));
            } else {
                // The caller must guarantee that the new start makes sense
                debug_assert!(offset >= old_start - new_start);
                file.set_offset(offset - (old_start - new_start));
            }
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

        let self_writeback_file = self.writeback_file();
        let other_writeback_file = other.writeback_file();
        match (self_writeback_file, other_writeback_file) {
            (None, None) => return true,
            (Some(_), None) => return false,
            (None, Some(_)) => return false,
            (Some((self_file, self_offset)), Some((other_file, other_offset))) => {
                self_file == other_file && self_offset == other_offset
            }
        }
    }

    pub fn set_end(&mut self, new_end: usize) {
        self.range.set_end(new_end);
        let pages = {
            let pages = PageTracker::new_vma_tracker(&self.range, &self.epc_type).unwrap();
            if pages.is_fully_committed() {
                None
            } else {
                Some(pages)
            }
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
        let left_writeback_file = left.writeback_file();
        let right_writeback_file = right.writeback_file();
        match (left_writeback_file, right_writeback_file) {
            (None, None) => true,
            (Some(_), None) => false,
            (None, Some(_)) => false,
            (Some((left_file, left_offset)), Some((right_file, right_offset))) => {
                left_file == right_file
                    && right_offset > left_offset
                    && right_offset - left_offset == left.size()
            }
        }
    }

    fn need_reset_perms(&self) -> bool {
        if let Some(lazy_perms) = self.lazy_extend_perms {
            // If the lazy_extend_perms(which is the old perm) is less than R/W,
            // then we need to reset the perms for memory cleaning.
            return lazy_perms < VMPerms::DEFAULT;
        } else {
            return false;
        }
    }

    fn modify_protection_lazy(
        &mut self,
        protect_range: Option<&VMRange>,
        old_perms: VMPerms,
        new_perms: VMPerms,
        force: bool,
    ) {
        // Guranteed earlier
        debug_assert!(old_perms != new_perms);
        let protect_range = if let Some(range) = protect_range {
            range
        } else {
            self.range()
        };

        trace!("old perms = {:?}, new_perms = {:?}", old_perms, new_perms);
        match &self.epc_type {
            EPC::UserRegionMem(user_region) => {
                if force {
                    trace!("force apply perms");
                    user_region.modify_protection(
                        protect_range.start(),
                        protect_range.size(),
                        new_perms,
                    );
                } else {
                    if VMPerms::can_lazy_extend(old_perms, new_perms) {
                        trace!("skip apply extending perms");
                        self.lazy_extend_perms = Some(old_perms);
                    } else {
                        trace!("reduce perms");
                        // For protection reduction, do it right now.
                        user_region.modify_protection(
                            protect_range.start(),
                            protect_range.size(),
                            new_perms,
                        );
                    }
                }
            }
            EPC::ReservedMem(reserved_mem) => {
                reserved_mem.modify_protection(
                    protect_range.start(),
                    protect_range.size(),
                    new_perms,
                );
            }
            _ => unreachable!(),
        }
    }

    fn modify_protection_force(
        &self,
        protect_range: &VMRange,
        // old_perms: VMPerms,
        new_perms: VMPerms,
    ) {
        // trace!("old perms = {:?}, new_perms = {:?}", old_perms, new_perms);
        match &self.epc_type {
            EPC::UserRegionMem(user_region) => {
                user_region.modify_protection(
                    protect_range.start(),
                    protect_range.size(),
                    new_perms,
                );
            }
            EPC::ReservedMem(reserved_mem) => {
                reserved_mem.modify_protection(
                    protect_range.start(),
                    protect_range.size(),
                    new_perms,
                );
            }
            _ => unreachable!(),
        }
    }

    fn init_committed_memory_internal(&mut self, range: &VMRange, force_perm: bool) -> Result<()> {
        if let Some(initializer) = self.initializer() {
            match initializer {
                VMInitializer::FileBacked { file } => {
                    let vm_range_start = self.range.start();
                    let file_ref = file.file_ref();
                    if !file_ref.access_mode().readable() {
                        return_errno!(EBADF, "file is not readable");
                    }

                    let file_offset = file.offset() + (range.start() - vm_range_start);
                    let buf = unsafe { range.as_slice_mut() };
                    // make sure that read_at does not move file cursor
                    let len = file_ref
                        .as_async_file_handle()
                        .unwrap()
                        .dentry()
                        .inode()
                        .as_sync_inode()
                        .unwrap()
                        .read_at(file_offset, buf)
                        .map_err(|_| errno!(EACCES, "failed to init memory from file"))?;
                    info!("file offset = {:?}, write len = {:?}", file_offset, len);
                    info!("range offset = {:?}", range.start() - vm_range_start);
                    eprintln!("buf = {:?}", buf);

                    // Set memory permissions for the whole VMA.
                    if !self.perms().is_default() {
                        // warn!("set perms for range: {:?}", range);
                        self.modify_protection_lazy(
                            Some(range),
                            VMPerms::DEFAULT,
                            self.perms(),
                            force_perm,
                        );
                    }
                }
                VMInitializer::DoNothing() | VMInitializer::FillZeros() => {
                    if !self.perms().is_default() {
                        self.modify_protection_lazy(
                            Some(range),
                            VMPerms::DEFAULT,
                            self.perms(),
                            force_perm,
                        );
                    }
                }
                _ => todo!(),
            }
        }

        Ok(())
    }

    // Inintialize the VMA memory if the VMA is partially committed
    fn init_committed_memory(&mut self) -> Result<()> {
        debug_assert!(self.is_partially_committed());
        let committed = true;
        for range in self.pages().get_ranges(committed) {
            self.init_committed_memory_internal(&range, false)?;
        }

        Ok(())
    }

    fn flush_committed_memory(&self) -> Result<()> {
        debug_assert!(self.is_partially_committed());
        let (need_flush, file, file_offset) = match self.writeback_file() {
            None => (false, None, None),
            Some((file, offset)) => {
                let file_handle = file.as_async_file_handle().unwrap();
                if !file_handle.access_mode().writable() {
                    (false, None, None)
                } else {
                    (true, Some(file_handle), Some(offset))
                }
            }
        };

        let vm_range_start = self.range.start();
        let committed = true;
        for range in self.pages().get_ranges(committed) {
            let buf = unsafe { range.as_slice_mut() };
            if !self.perms().is_default() || self.need_reset_perms() {
                self.modify_protection_force(&range, VMPerms::default());
            }

            if need_flush {
                let file_offset = file_offset.unwrap() + (range.start() - vm_range_start);
                file.unwrap()
                    .dentry()
                    .inode()
                    .as_sync_inode()
                    .unwrap()
                    .write_at(file_offset, buf);
            }

            // reset zeros
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
        let force_perm = true;

        for range in uncommitted_ranges.iter_mut() {
            if total_commit_size == 0 {
                if !range.contains(pf_addr) {
                    // loop until finding the uncommitted range which contains pf_addr
                    continue;
                } else {
                    trace!("pf addr = 0x{:x}, uncommitted range = {:?}", pf_addr, range);
                    range.set_start(align_down(pf_addr, PAGE_SIZE));
                    trace!("target commit range = {:?}", range);
                }
            }

            if range.size() + total_commit_size > COMMIT_ONCE_SIZE {
                range.resize(COMMIT_ONCE_SIZE - total_commit_size);
                trace!("after resize, target range = {:?}", range);
            }

            // Commit memory
            self.pages
                .as_mut()
                .unwrap()
                .commit_range_for_current_vma(range)?;

            self.init_committed_memory_internal(&range, force_perm)?;

            total_commit_size += range.size();
            if total_commit_size >= COMMIT_ONCE_SIZE {
                break;
            }
        }

        if self.pages().is_fully_committed() {
            self.pages = None;
        }

        Ok(total_commit_size)
    }

    fn page_fault_handler_extend_permission(&mut self, pf_addr: usize) -> Result<()> {
        let permission = self.perms();

        // This is intended by the application.
        if permission == VMPerms::NONE {
            return_errno!(EPERM, "trying to access PROT_NONE memory");
        }

        if self.is_fully_committed() {
            self.modify_protection_force(self.range(), permission);
            return Ok(());
        }

        let committed = true;
        let committed_ranges = self.pages().get_ranges(committed);
        for range in committed_ranges.iter() {
            if !range.contains(pf_addr) {
                continue;
            }

            self.epc_type
                .modify_protection(range.start(), range.size(), permission);
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
