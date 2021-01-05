use super::*;
use crate::cache::*;
use crate::time::*;
use rcore_fs_sefs::dev::SefsMac;
use std::cmp;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

// lazy_static! {
//     static ref sync_1 :SgxMutex<bool> = SgxMutex::new(false);
//     static ref sync_2 :SgxMutex<bool> = SgxMutex::new(false);
// }
pub struct INodeFile {
    inode: Arc<dyn INode>,
    abs_path: String,
    offset: SgxMutex<usize>,
    access_mode: AccessMode,
    status_flags: RwLock<StatusFlags>,
}

impl File for INodeFile {
    fn do_read_at(&self, offset: usize, buf: &mut [u8]) -> Result<usize> {
        trace!(
            "[do_read_at]fs_type: {:?}, file: {:?}, file offset: {}, buf.len: {}",
            self.inode.get_fs_type(),
            self.inode.get_inode_num(),
            offset,
            buf.len()
        );
        if !self.inode.cache_needed() {
            let len = self.inode.read_at(offset, buf).map_err(|e| errno!(e))?;
            return Ok(len);
        }

        let user_buf_len = buf.len();
        if user_buf_len == 0 {
            return Ok(0);
        }
        let status_flag = self.get_status_flags()?;
        if user_buf_len > MAX_CACHE_LENGTH || status_flag.contains(StatusFlags::O_DIRECT) {
            // don't read to cache
            let len = self.inode.read_at(offset, buf).map_err(|e| errno!(e))?;
            return Ok(len);
        }

        // Ok, we will use cache
        trace!("inode num: {:?}", self.inode.get_inode_num());
        let mut read_len = 0;
        let inode_num = self.inode.get_inode_num()?;
        let global_cache = get_cache(self.inode.get_fs_type()?)?;
        let page_start_id = divide_page_size(offset);
        let page_end_id = divide_page_size(offset + user_buf_len - 1);
        let page_num = page_end_id - page_start_id + 1;

        // page offset
        let mut page_start_offset = offset % PAGE_SIZE;
        let mut data_kernel_cache = page_num * PAGE_SIZE;

        let mut read_len_remained = user_buf_len;

        // user buffer start offset
        let mut ub_start_offset = 0;

        trace!(
            "start_pageid: {}, start_page_offset: {}, page_num: {}, read_len_remained: {}",
            page_start_id,
            page_start_offset,
            page_num,
            read_len_remained
        );
        let mut len = 0;
        // try cache
        // TODO: What if read offset is beyond the length of the page
        for page_id in page_start_id..page_start_id + page_num {
            trace!(
                "page id: {}, page_start_offset: {}, user buffer start_offset: {}",
                page_id,
                page_start_offset,
                ub_start_offset
            );
            READ_COUNTER.fetch_add(1, Ordering::SeqCst);
            let mut cache = global_cache.write().unwrap();
            if let Some(cache_entry) = cache.get((inode_num, page_id)) {
                let entry = cache_entry.lock().unwrap();
                trace!("cache hit. cache entry: {:?}", entry);

                // Just drop global cache lock, although this entry might be dropped by other thread's cache insertion
                drop(cache);
                let kernel_buf = entry.buf;
                let page_data_len = entry.data_len;
                let cache_read_len = if page_start_offset + read_len_remained > PAGE_SIZE {
                    PAGE_SIZE - page_start_offset
                } else {
                    page_data_len - page_start_offset
                };
                // check length, don't overflow user's buffer
                len = cmp::min(read_len_remained, cache_read_len);
                buf[ub_start_offset..ub_start_offset + len]
                    .copy_from_slice(&kernel_buf[page_start_offset..page_start_offset + len]);
                ub_start_offset += len;
                read_len += len;
                read_len_remained -= len;
                // only first time read, the page_start_offset could be not-4K-aligned
                page_start_offset = 0;
                READ_CACHE_HIT_COUNTER.fetch_add(1, Ordering::SeqCst);
            } else {
                // cache miss
                drop(cache);
                let mut kernel_buf = [0; PAGE_SIZE];
                // read a whole page
                let mut data_len = self
                    .inode
                    .read_at(page_id * PAGE_SIZE, &mut kernel_buf)
                    .map_err(|e| errno!(e))?;
                if data_len == 0 {
                    break;
                }

                len = if page_start_offset + read_len_remained > PAGE_SIZE {
                    PAGE_SIZE - page_start_offset
                } else {
                    read_len_remained
                };
                len = cmp::min(len, data_len - page_start_offset);

                let cache_entry =
                    CacheEntry::new(inode_num, self.inode.clone(), page_id, data_len, kernel_buf);
                trace!("cache miss. new cache entry: {:?}", cache_entry);
                let cache_entry = cache_entry.get_arc();
                // get the global cache
                let mut cache = global_cache.write().unwrap();

                // Check the entry again to prevent other thread's write invalidation
                if let Some(entry) = cache.get((inode_num, page_id)) {
                    // If there is an entry existed, other thread could write to this entry
                    // Then we don't insert and just use this entry
                    let cache_buf = &entry.lock().unwrap().buf;
                    buf[ub_start_offset..ub_start_offset + len]
                        .copy_from_slice(&cache_buf[page_start_offset..page_start_offset + len]);
                } else {
                    cache.insert((inode_num, page_id), cache_entry);
                    drop(cache);
                    // copy len of kernel_buf to user buf
                    buf[ub_start_offset..ub_start_offset + len]
                        .copy_from_slice(&kernel_buf[page_start_offset..page_start_offset + len]);
                }

                // // Only Test
                // let mut test_1 = sync_1.lock().unwrap();
                // *test_1 = true;
                // drop(test_1);

                // while true {
                //     let test_1 = sync_1.lock().unwrap();
                //     if *test_1 == false {
                //         break;
                //     } else {
                //         drop(test_1);
                //     }
                // };

                ub_start_offset += len;
                read_len += len;
                read_len_remained -= len;
                // only first time read, the page_start_offset could be not-4K-aligned
                page_start_offset = 0;
            }
            trace!(
                "this time read_len: {}, overall read_len: {}, read_len_remained: {}",
                len,
                read_len,
                read_len_remained
            );
        }

        // TODO: Do pre-read

        // The user buffer could be bigger than the real content.
        // This assertion could fail.
        //debug_assert!(read_len_remained == 0);

        Ok(read_len)
    }

    fn do_write_at(&self, offset: usize, buf: &[u8]) -> Result<usize> {
        trace!(
            "[do_write_at]fs_type: {:?}, file: {:?}, file offset: {}, buf.len: {}",
            self.inode.get_fs_type(),
            self.inode.get_inode_num(),
            offset,
            buf.len()
        );
        if !self.inode.cache_needed() {
            let len = self.inode.write_at(offset, buf).map_err(|e| errno!(e))?;
            return Ok(len);
        }

        let user_buf_len = buf.len();
        if user_buf_len == 0 {
            return Ok(0);
        }
        let status_flag = self.get_status_flags()?;
        if user_buf_len > MAX_CACHE_LENGTH || status_flag.contains(StatusFlags::O_DIRECT) {
            // don't write to cache
            let len = self.inode.write_at(offset, buf).map_err(|e| errno!(e))?;
            return Ok(len);
        }

        // Ok, we will use cache
        let mut write_len = 0;
        let inode_num = self.inode.get_inode_num()?;
        let global_cache = get_cache(self.inode.get_fs_type()?)?;
        let page_start_id = divide_page_size(offset);
        let page_end_id = divide_page_size(offset + user_buf_len - 1);
        let page_num = page_end_id - page_start_id + 1;

        // page offset
        let mut page_start_offset = offset % PAGE_SIZE;
        let mut data_kernel_cache = page_num * PAGE_SIZE;
        let mut write_len_remained = user_buf_len;

        // user buffer start offset
        let mut ub_start_offset = 0;

        trace!(
            "start_pageid: {}, start_page_offset: {}, page_num: {}, write_len_remained: {}",
            page_start_id,
            page_start_offset,
            page_num,
            write_len_remained
        );
        let mut len = 0;
        // try cache
        for page_id in page_start_id..page_start_id + page_num {
            trace!(
                "page id: {}, page_start_offset: {}, user buffer start_offset: {}",
                page_id,
                page_start_offset,
                ub_start_offset
            );
            WRITE_COUNTER.fetch_add(1, Ordering::SeqCst);
            let mut cache = global_cache.write().unwrap();
            if let Some(cache_entry) = cache.get((inode_num, page_id)) {
                // cache hit
                let mut entry = cache_entry.lock().unwrap();
                trace!("cache hit. cache entry: {:?}", entry);
                // Just drop global cache lock, although this entry might be dropped by other thread's cache insertion
                drop(cache);
                len = if page_start_offset + write_len_remained > PAGE_SIZE {
                    PAGE_SIZE - page_start_offset
                } else {
                    write_len_remained
                };
                entry.buf[page_start_offset..page_start_offset + len]
                    .copy_from_slice(&buf[ub_start_offset..ub_start_offset + len]);
                entry.update_data_len(page_start_offset + len);
                entry.set_dirty();
                ub_start_offset += len;
                write_len += len;
                write_len_remained -= len;
                // only first time write, the page_start_offset could be not-4K-aligned
                page_start_offset = 0;
                CACHE_DIRTY_QUEUE
                    .lock()
                    .unwrap()
                    .push(inode_num, cache_entry.clone());
                WRITE_CACHE_HIT_COUNTER.fetch_add(1, Ordering::SeqCst);
            } else {
                // cache miss
                drop(cache);

                // // Only Test
                // while true {
                //     let test_1 = sync_1.lock().unwrap();
                //     if *test_1 == true {
                //         break;
                //     } else {
                //         drop(test_1);
                //     }
                // };

                let mut kernel_buf = [0; PAGE_SIZE];
                len = if page_start_offset + write_len_remained > PAGE_SIZE {
                    PAGE_SIZE - page_start_offset
                } else {
                    write_len_remained
                };
                // copy len of user buf to kernel_buf
                kernel_buf[page_start_offset..page_start_offset + len]
                    .copy_from_slice(&buf[ub_start_offset..ub_start_offset + len]);
                ub_start_offset += len;
                write_len += len;
                write_len_remained -= len;
                let mut cache_entry = CacheEntry::new(
                    inode_num,
                    self.inode.clone(),
                    page_id,
                    page_start_offset + len,
                    kernel_buf,
                );
                cache_entry.set_dirty();
                trace!("cache miss. new cache entry: {:?}", cache_entry);
                let cache_entry = cache_entry.get_arc();
                // only first time write, the page_start_offset could be not-4K-aligned
                page_start_offset = 0;
                global_cache
                    .write()
                    .unwrap()
                    .insert((inode_num, page_id), cache_entry.clone());
                CACHE_DIRTY_QUEUE
                    .lock()
                    .unwrap()
                    .push(inode_num, cache_entry);

                // let mut test_1 = sync_1.lock().unwrap();
                // *test_1 = false;
            }
            trace!(
                "this time write_len: {}, overall write_len: {}, write_len_remained: {}",
                len,
                write_len,
                write_len_remained
            );
        }

        //MetaDataCacheQueue.write().unwrap().update_after_write(&self.inode, write_len);
        debug_assert!(write_len_remained == 0);
        Ok(write_len)
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize> {
        if !self.access_mode.readable() {
            return_errno!(EACCES, "File not readable");
        }
        let mut offset = self.offset.lock().unwrap();
        // let len = self.inode.read_at(*offset, buf).map_err(|e| errno!(e))?;
        let len = self.do_read_at(*offset, buf)?;
        *offset += len;
        Ok(len)
    }

    fn write(&self, buf: &[u8]) -> Result<usize> {
        if !self.access_mode.writable() {
            return_errno!(EACCES, "File not writable");
        }
        let mut offset = self.offset.lock().unwrap();
        if self.status_flags.read().unwrap().always_append() {
            let info = self.inode.metadata()?;
            *offset = info.size;
        }
        let len = self.do_write_at(*offset, buf)?;
        *offset += len;
        Ok(len)
    }

    fn read_at(&self, offset: usize, buf: &mut [u8]) -> Result<usize> {
        if !self.access_mode.readable() {
            return_errno!(EACCES, "File not readable");
        }
        let len = self.do_read_at(offset, buf)?;
        Ok(len)
    }

    fn write_at(&self, offset: usize, buf: &[u8]) -> Result<usize> {
        if !self.access_mode.writable() {
            return_errno!(EACCES, "File not writable");
        }
        let len = self.do_write_at(offset, buf)?;
        Ok(len)
    }

    fn readv(&self, bufs: &mut [&mut [u8]]) -> Result<usize> {
        if !self.access_mode.readable() {
            return_errno!(EACCES, "File not readable");
        }
        let mut offset = self.offset.lock().unwrap();
        let mut total_len = 0;
        for buf in bufs {
            match self.do_read_at(*offset, buf) {
                Ok(len) => {
                    total_len += len;
                    *offset += len;
                }
                Err(_) if total_len != 0 => break,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(total_len)
    }

    fn writev(&self, bufs: &[&[u8]]) -> Result<usize> {
        if !self.access_mode.writable() {
            return_errno!(EACCES, "File not writable");
        }
        let mut offset = self.offset.lock().unwrap();
        if self.status_flags.read().unwrap().always_append() {
            let info = self.inode.metadata()?;
            *offset = info.size;
        }
        let mut total_len = 0;
        for buf in bufs {
            match self.do_write_at(*offset, buf) {
                Ok(len) => {
                    total_len += len;
                    *offset += len;
                }
                Err(_) if total_len != 0 => break,
                Err(e) => return Err(e.into()),
            }
        }
        Ok(total_len)
    }

    fn seek(&self, pos: SeekFrom) -> Result<off_t> {
        let mut offset = self.offset.lock().unwrap();
        let new_offset = match pos {
            SeekFrom::Start(off) => off as i64,
            SeekFrom::End(off) => (self.metadata()?.size as i64)
                .checked_add(off)
                .ok_or_else(|| errno!(EOVERFLOW, "file offset overflow"))?,
            SeekFrom::Current(off) => (*offset as i64)
                .checked_add(off)
                .ok_or_else(|| errno!(EOVERFLOW, "file offset overflow"))?,
        };
        if new_offset < 0 {
            return_errno!(EINVAL, "file offset is negative");
        }
        *offset = new_offset as usize;
        Ok(*offset as i64)
    }

    fn metadata(&self) -> Result<Metadata> {
        CACHE_DIRTY_QUEUE
            .lock()
            .unwrap()
            .flush_file(self.inode.get_inode_num()?)?;
        let metadata = self.inode.metadata()?;
        Ok(metadata)
    }

    fn set_metadata(&self, metadata: &Metadata) -> Result<()> {
        self.inode.set_metadata(metadata)?;
        Ok(())
    }

    fn set_len(&self, len: u64) -> Result<()> {
        if !self.access_mode.writable() {
            return_errno!(EACCES, "File not writable. Can't set len.");
        }
        self.inode.resize(len as usize)?;
        Ok(())
    }

    fn sync_all(&self) -> Result<()> {
        CACHE_DIRTY_QUEUE
            .lock()
            .unwrap()
            .flush_file(self.inode.get_inode_num()?)?;
        self.inode.sync_all()?;
        Ok(())
    }

    fn sync_data(&self) -> Result<()> {
        CACHE_DIRTY_QUEUE
            .lock()
            .unwrap()
            .flush_file(self.inode.get_inode_num()?)?;
        self.inode.sync_data()?;
        Ok(())
    }

    fn read_entry(&self) -> Result<String> {
        if !self.access_mode.readable() {
            return_errno!(EACCES, "File not readable. Can't read entry.");
        }
        let mut offset = self.offset.lock().unwrap();
        let name = self.inode.get_entry(*offset)?;
        *offset += 1;
        Ok(name)
    }

    fn get_access_mode(&self) -> Result<AccessMode> {
        Ok(self.access_mode.clone())
    }

    fn get_status_flags(&self) -> Result<StatusFlags> {
        let status_flags = self.status_flags.read().unwrap();
        Ok(status_flags.clone())
    }

    fn set_status_flags(&self, new_status_flags: StatusFlags) -> Result<()> {
        let mut status_flags = self.status_flags.write().unwrap();
        // Currently, F_SETFL can change only the O_APPEND,
        // O_ASYNC, O_NOATIME, and O_NONBLOCK flags
        let valid_flags_mask = StatusFlags::O_APPEND
            | StatusFlags::O_ASYNC
            | StatusFlags::O_NOATIME
            | StatusFlags::O_NONBLOCK;
        status_flags.remove(valid_flags_mask);
        status_flags.insert(new_status_flags & valid_flags_mask);
        Ok(())
    }

    fn test_advisory_lock(&self, lock: &mut Flock) -> Result<()> {
        // Let the advisory lock could be placed
        // TODO: Implement the real advisory lock
        lock.l_type = FlockType::F_UNLCK;
        Ok(())
    }

    fn set_advisory_lock(&self, lock: &Flock) -> Result<()> {
        match lock.l_type {
            FlockType::F_RDLCK => {
                if !self.access_mode.readable() {
                    return_errno!(EACCES, "File not readable");
                }
            }
            FlockType::F_WRLCK => {
                if !self.access_mode.writable() {
                    return_errno!(EACCES, "File not writable");
                }
            }
            _ => (),
        }
        // Let the advisory lock could be acquired or released
        // TODO: Implement the real advisory lock
        Ok(())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

impl INodeFile {
    pub fn open(inode: Arc<dyn INode>, abs_path: &str, flags: u32) -> Result<Self> {
        let access_mode = AccessMode::from_u32(flags)?;
        if (access_mode.readable() && !inode.allow_read()?) {
            return_errno!(EACCES, "File not readable");
        }
        if (access_mode.writable() && !inode.allow_write()?) {
            return_errno!(EACCES, "File not writable");
        }
        if access_mode.writable() && inode.metadata()?.type_ == FileType::Dir {
            return_errno!(EISDIR, "Directory cannot be open to write");
        }
        let status_flags = StatusFlags::from_bits_truncate(flags);
        Ok(INodeFile {
            inode,
            abs_path: abs_path.to_owned(),
            offset: SgxMutex::new(0),
            access_mode,
            status_flags: RwLock::new(status_flags),
        })
    }

    pub fn get_abs_path(&self) -> &str {
        &self.abs_path
    }
}

impl Debug for INodeFile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "INodeFile {{ inode: ???, abs_path: {}, pos: {}, access_mode: {:?}, status_flags: {:#o} }}",
            self.abs_path,
            *self.offset.lock().unwrap(),
            self.access_mode,
            *self.status_flags.read().unwrap()
        )
    }
}

pub trait INodeExt {
    fn read_as_vec(&self) -> Result<Vec<u8>>;
    fn allow_write(&self) -> Result<bool>;
    fn allow_read(&self) -> Result<bool>;
}

impl INodeExt for dyn INode {
    fn read_as_vec(&self) -> Result<Vec<u8>> {
        let size = self.metadata()?.size;
        let mut buf = Vec::with_capacity(size);
        unsafe {
            buf.set_len(size);
        }
        self.read_at(0, buf.as_mut_slice())?;
        Ok(buf)
    }

    fn allow_write(&self) -> Result<bool> {
        let info = self.metadata()?;
        let file_mode = FileMode::from_bits_truncate(info.mode);
        Ok(file_mode.is_writable())
    }

    fn allow_read(&self) -> Result<bool> {
        let info = self.metadata()?;
        let file_mode = FileMode::from_bits_truncate(info.mode);
        Ok(file_mode.is_readable())
    }
}

pub trait AsINodeFile {
    fn as_inode_file(&self) -> Result<&INodeFile>;
}

impl AsINodeFile for FileRef {
    fn as_inode_file(&self) -> Result<&INodeFile> {
        self.as_any()
            .downcast_ref::<INodeFile>()
            .ok_or_else(|| errno!(EBADF, "not an inode file"))
    }
}
