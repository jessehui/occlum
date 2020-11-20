use std::ops::{Deref, DerefMut};

use super::vm_perms::VMPerms;
use super::vm_range::VMRange;
use super::*;
use std::pin::Pin;

#[derive(Debug, Default)]
pub struct VMArea {
    inner: SgxRwLock<Box<VMArea_inner>>,
}

#[derive(Debug, Default)]
pub struct VMArea_inner {
    range: VMRange,
    perms: VMPerms,
    writeback_file: Option<(FileRef, usize)>,
}

impl VMArea {
    pub fn new(range: VMRange, perms: VMPerms, writeback_file: Option<(FileRef, usize)>) -> Self {
        let inner = Box::new(VMArea_inner {
            range,
            perms,
            writeback_file,
        });
        VMArea{ inner: SgxRwLock::new(inner) }
    }

    /// Create a new VMArea object that inherits the write-back file (if any), but has
    /// a new range and permissions.
    pub fn inherits_file_from(vma: &VMArea, new_range: VMRange, new_perms: VMPerms) -> Self {
        let new_writeback_file = vma.inner.read().unwrap().writeback_file.as_ref().map(|(file, file_offset)| {
            let new_file = file.clone();

            let new_file_offset = if vma.start() < new_range.start() {
                let vma_offset = new_range.start() - vma.start();
                *file_offset + vma_offset
            } else {
                let vma_offset = vma.start() - new_range.start();
                debug_assert!(*file_offset >= vma_offset);
                *file_offset - vma_offset
            };
            (new_file, new_file_offset)
        });
        Self::new(new_range, new_perms, new_writeback_file)
    }

    pub fn inner(&self) -> &SgxRwLock<Box<VMArea_inner>> {
        &self.inner
    }

    pub fn perms(&self) -> VMPerms {
        self.inner.read().unwrap().perms
    }

    pub fn range(&self) -> VMRange {
        self.inner.read().unwrap().range.clone()
    }

    pub fn start(&self) ->usize {
        self.inner.read().unwrap().range.start
    }

    pub fn end(&self) ->usize {
        self.inner.read().unwrap().range.end
    }

    pub fn size(&self) ->usize {
        self.inner.read().unwrap().range.size()
    }

    // pub unsafe fn as_slice(&self) -> &[u8] {
    //     let buf_ptr = self.start() as *const u8;
    //     let buf_size = self.size() as usize;
    //     std::slice::from_raw_parts(buf_ptr, buf_size)
    // }

    pub unsafe fn as_slice_mut(&self) -> &mut [u8] {
        let buf_ptr = self.start() as *mut u8;
        let buf_size = self.size() as usize;
        std::slice::from_raw_parts_mut(buf_ptr, buf_size)
    }

    pub fn writeback_file(&self) -> Option<(FileRef, usize)> {
        self.inner.read().unwrap().writeback_file.clone()
    }

    // pub fn writeback_file_mut(&self) -> &mut Option<(FileRef, usize)> {
    //     &mut self.inner.write().unwrap().writeback_file
    // }

    pub fn set_perms(&self, new_perms: VMPerms) {
        self.inner.write().unwrap().perms = new_perms;
    }

    pub fn subtract(&self, other: &VMRange) -> Vec<Arc<VMArea>> {
        self.range()
            .subtract(other)
            .into_iter()
            .map(|range| Self::inherits_file_from(self, range, self.perms()))
            .map(|vma| Arc::new(vma))
            .collect::<Vec<Arc<VMArea>>>()
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
        let new_vma = VMArea::inherits_file_from(self, new_range, self.perms());
        Some(new_vma)
    }

    pub fn resize(&self, new_size: usize) {
        self.inner.write().unwrap().range.resize(new_size)
    }

    pub fn set_start(&self, new_start: usize) {
        let old_start = self.start();
        self.inner.write().unwrap().range.set_start(new_start);

        // If the updates to the VMA needs to write back to a file, then the
        // file offset must be adjusted according to the new start address.
        if let Some((_, mut offset)) = self.inner.write().unwrap().writeback_file {
            if old_start < new_start {
                offset += new_start - old_start;
            } else {
                // The caller must guarantee that the new start makes sense
                debug_assert!(offset >= old_start - new_start);
                offset -= old_start - new_start;
            }
        }
    }

    pub fn set_end(&self, new_end: usize) {
        self.inner.write().unwrap().range.set_end(new_end);
    }
}

// impl Deref for VMArea {
//     type Target = VMRange;

//     fn deref(&self) -> &Self::Target {
//         self.inner.read().unwrap().range.clone()
//     }
// }
