// What page-cache do in a word:
// (inode, offset) -> cache_entry (a buffer)

// https://crates.io/crates/lru/
//extern crate lru;

use super::*;
use crate::error::*;
use crate::rcore_fs::vfs::{FsType, INode, Metadata};
use lru::LruCache;
use sgx_tstd::sync::{SgxMutex, SgxRwLock};
use std::borrow::Borrow;
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

// We may call it page cache but we are not really
// handling the page but the file block. Both of them
// are 4K bytes.
pub const PAGE_SIZE: usize = 4096;

pub fn divide_page_size(num: usize) -> usize {
    num >> 12
}

// If data size is bigger than 1M, we don't cache it.
pub const MAX_CACHE_LENGTH: usize = 256 * PAGE_SIZE;

// TODO: make it configurable
const CACHE_CAPACITY: usize = 32768; // 32K * 4K = 128M

// Initial capacity for dirty_queue
const DIRTY_QUEUE_INITIAL_SIZE: usize = 100;

const METADATA_QUEUE_INITIAL_SIZE: usize = 100;

// Profile the cache hit ratio
pub static READ_COUNTER: AtomicUsize = AtomicUsize::new(0);
pub static WRITE_COUNTER: AtomicUsize = AtomicUsize::new(0);
pub static READ_CACHE_HIT_COUNTER: AtomicUsize = AtomicUsize::new(0);
pub static WRITE_CACHE_HIT_COUNTER: AtomicUsize = AtomicUsize::new(0);

// Global page-cache. One for each FS.
// TODO: Use macro.
lazy_static! {
    pub static ref HOSTFS_CACHE: SgxRwLock<Cache> = SgxRwLock::new(Cache::new(CACHE_CAPACITY));
    pub static ref SEFS_CACHE: SgxRwLock<Cache> = SgxRwLock::new(Cache::new(CACHE_CAPACITY));
    pub static ref UNIONFS_CACHE: SgxRwLock<Cache> = SgxRwLock::new(Cache::new(CACHE_CAPACITY));
    pub static ref METADATA_QUEUE: SgxRwLock<MetaDataCacheQueue> =
        SgxRwLock::new(MetaDataCacheQueue::new());
    pub static ref CACHE_DIRTY_QUEUE: SgxMutex<DirtyQueue> = SgxMutex::new(DirtyQueue::new());
}

pub fn get_cache(fs: FsType) -> Result<&'static SgxRwLock<Cache>> {
    match fs {
        FsType::HOSTFS => Ok(&HOSTFS_CACHE),

        FsType::SEFS => Ok(&SEFS_CACHE),

        FsType::UNIONFS => Ok(&UNIONFS_CACHE),

        _ => return_errno!(EINVAL, "cache is not implemented for this FS type"),
    }
}

// TODO: Detect pattern and choose different policies.
pub enum PreReadPolicy {
    AGGRESSIVE,   // double the page pre-read, until 32 pages
    CONSERVATIVE, // default, 2 page pre-read
}

struct MetaDataCache {
    metadata: Metadata,
    dirty: bool,
    inode_file: Arc<dyn INode>,
}

impl MetaDataCache {
    pub fn set_dirty(&mut self) {
        self.dirty = true
    }

    pub fn dirty(&self) -> bool {
        self.dirty
    }
}

pub struct MetaDataCacheQueue {
    inner: HashMap<INodeId, MetaDataCache>,
}

impl MetaDataCacheQueue {
    pub fn new() -> Self {
        let inner = HashMap::with_capacity(METADATA_QUEUE_INITIAL_SIZE);
        MetaDataCacheQueue { inner }
    }

    pub fn insert(&mut self, inode: &Arc<dyn INode>) -> Result<()> {
        let inode_id = inode.get_inode_num()?;
        let metadata = inode.metadata()?;
        let metadata_cache = MetaDataCache {
            metadata,
            dirty: false,
            inode_file: inode.clone(),
        };
        self.inner.insert(inode_id, metadata_cache);
        Ok(())
    }

    pub fn get(&mut self, inode: &Arc<dyn INode>) -> Result<Metadata> {
        let inode_num = inode.get_inode_num()?;
        if let Some(metadata_cache) = self.inner.get(&inode_num) {
            // cache hit
            return Ok(metadata_cache.metadata.clone());
        } else {
            let metadata = inode.metadata()?;
            let metadata_cache = MetaDataCache {
                metadata: metadata.clone(),
                dirty: false,
                inode_file: inode.clone(),
            };
            self.inner.insert(inode_num, metadata_cache);
            return Ok(metadata);
        }
    }

    pub fn update(&mut self, inode: &Arc<dyn INode>, new_metadata: &Metadata) -> Result<()> {
        let inode_num = inode.get_inode_num()?;
        if let Some(mut metadata_cache) = self.inner.get_mut(&inode_num) {
            (*metadata_cache).metadata = new_metadata.clone();
            (*metadata_cache).dirty = true;
        } else {
            let metadata = new_metadata.clone();
            let metadata_cache = MetaDataCache {
                metadata,
                dirty: true,
                inode_file: inode.clone(),
            };
            self.inner.insert(inode_num, metadata_cache);
        }
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        for (_, mut metadata_cache) in self.inner.iter_mut() {
            if metadata_cache.dirty() {
                let inode_file = &metadata_cache.inode_file;
                inode_file.set_metadata(&metadata_cache.metadata);
            }
        }
        Ok(())
    }

    // pub fn update_after_write(&mut self, inode: &Arc<dyn INode>, new_len: usize) {
    //     let inode_num = inode.get_inode_num()?;
    //     if let Some(mut metadata_cache) = self.inner.get_mut(&inode_num) {
    //         metadata_cache.metadata.size = new_len;
    //         (*metadata_cache).dirty = true;
    //     } else {
    // }
}

// This struct maintains a fixed-size map and manages the map
// with LRU eviction policy.
// TODO: If we use pairing function to combine InodeID and usize to a unique number, will it faster for hash?
#[derive(Debug)]
pub struct Cache {
    inner: LruCache<(INodeId, usize), CacheEntryRef>, // key: inodeid, page id (offset/page_size)
}

pub struct DirtyQueue {
    inner: HashMap<INodeId, VecDeque<CacheEntryRef>>,
}

impl DirtyQueue {
    fn new() -> Self {
        let inner = HashMap::with_capacity(DIRTY_QUEUE_INITIAL_SIZE);
        DirtyQueue { inner }
    }

    pub fn push(&mut self, inode_num: INodeId, cache_entry: CacheEntryRef) -> Result<()> {
        if let Some(mut file_dirty_queue) = self.inner.get_mut(&inode_num) {
            // This file has a dirty queue already. We just push the dirty entry.
            file_dirty_queue.push_back(cache_entry);
        } else {
            // This file doesn't have a dirty queue yet.
            let mut file_dirty_queue = VecDeque::with_capacity(50);
            file_dirty_queue.push_back(cache_entry);
            self.inner.insert(inode_num, file_dirty_queue);
        }
        Ok(())
    }

    pub fn clean_all(&mut self) -> Result<()> {
        for (_, mut queue) in self.inner.iter_mut() {
            queue.iter_mut().for_each(|cache_entry| {
                let mut entry = cache_entry.lock().unwrap();
                if entry.dirty() {
                    let offset = entry.page_id * PAGE_SIZE;
                    entry
                        .inode_file
                        .write_at(offset, &entry.buf[..entry.data_len]);
                    entry.set_clean();
                    //println!("entry = {:?}", entry);
                }
            });

            // make sure all dirty are flushed
            debug_assert!(queue
                .iter()
                .all(|cache_entry| cache_entry.lock().unwrap().dirty() == false));
            //println!("queue = {:?}", queue);
            queue.clear();
        }
        Ok(())
    }

    pub fn flush_file(&mut self, inode_num: INodeId) -> Result<()> {
        if let Some(mut file_cache_entries) = self.inner.remove(&inode_num) {
            file_cache_entries.iter_mut().for_each(|cache_entry| {
                let mut entry = cache_entry.lock().unwrap();
                if entry.dirty() {
                    trace!("flush file entry = {:?}", entry);
                    let offset = entry.page_id * PAGE_SIZE;
                    entry
                        .inode_file
                        .write_at(offset, &entry.buf[..entry.data_len]);
                    entry.set_clean();
                }
            });
            debug_assert!(file_cache_entries.iter().all(|cache_entry| cache_entry
                .lock()
                .unwrap()
                .dirty()
                == false));
            file_cache_entries.clear();
        }
        Ok(())
    }
}

pub type CacheEntryRef = Arc<SgxMutex<CacheEntry>>;

pub type INodeId = usize;

// The real cached things, corresponds to a page or say block
pub struct CacheEntry {
    inode_id: INodeId,
    inode_file: Arc<dyn INode>,
    page_id: usize,      // page_id * PAGE_SIZE = start offset
    pub data_len: usize, // len with data
    dirty: bool,         // whether this page(/block) is dirty
    pub buf: [u8; PAGE_SIZE], // cached page/block
                         //...
}

impl CacheEntry {
    pub fn new(
        inode_id: INodeId,
        inode_file: Arc<dyn INode>,
        page_id: usize,
        data_len: usize,
        buf: [u8; PAGE_SIZE],
    ) -> Self {
        CacheEntry {
            inode_id,
            inode_file,
            page_id,
            data_len,
            dirty: false,
            buf,
        }
    }

    pub fn get_arc(self) -> CacheEntryRef {
        Arc::new(SgxMutex::new(self))
    }

    pub fn dirty(&self) -> bool {
        self.dirty
    }

    pub fn set_dirty(&mut self) {
        self.dirty = true;
    }

    pub fn set_clean(&mut self) {
        self.dirty = false;
    }

    pub fn update_data_len(&mut self, len: usize) {
        self.data_len = len;
    }

    pub fn clean_buf(&mut self) {
        self.buf.iter_mut().for_each(|e| *e = 0)
    }
}

// This is called when inserting into a full cache and the LRU entry is evicted
// Flush the dirty page when dropped.
impl Drop for CacheEntry {
    fn drop(&mut self) {
        if self.dirty {
            let offset = self.page_id * PAGE_SIZE;
            self.inode_file.write_at(offset, &self.buf[..self.data_len]);
        }
    }
}

impl Cache {
    fn new(capacity: usize) -> Self {
        let inner = LruCache::new(capacity);
        Cache { inner }
    }

    pub fn insert(&mut self, (inode_num, page_id): (INodeId, usize), cache_entry: CacheEntryRef) {
        //let cache_entry = Arc::new(SgxMutex::new(entry));
        self.inner.put((inode_num, page_id), cache_entry);
    }

    pub fn get(&mut self, (inode_num, page_id): (INodeId, usize)) -> Option<CacheEntryRef> {
        if let Some(entry) = self.inner.get(&(inode_num, page_id)) {
            // Operations on cache entry will not need global cache lock
            Some(entry.clone())
        } else {
            None
        }
    }
}

// count cache hit ratio
pub fn display_cache_ratio() {
    let write_hit_times = WRITE_CACHE_HIT_COUNTER.load(Ordering::SeqCst);
    let write_times = WRITE_COUNTER.load(Ordering::SeqCst);
    let read_hit_times = READ_CACHE_HIT_COUNTER.load(Ordering::SeqCst);
    let read_times = READ_COUNTER.load(Ordering::SeqCst);
    let write_hit_ratio: f32 = write_hit_times as f32 / write_times as f32;
    let read_hit_ratio: f32 = read_hit_times as f32 / read_times as f32;
    println!(
        "write times: {:?}, write hit times: {:?}, hit ratio: {:?}",
        write_times, write_hit_times, write_hit_ratio
    );
    println!(
        "read times: {:?}, read hit times: {:?}, hit ratio: {:?}",
        read_times, read_hit_times, read_hit_ratio
    );
}

impl Debug for CacheEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Ok(s) = std::str::from_utf8(&self.buf) {
            write!(
                f,
                "CacheEntry {{ inode_file: ???, inode_id: {}, page_id: {}, data_len: {}, dirty: {} }}",
                self.inode_id,
                self.page_id,
                self.data_len,
                self.dirty,
                //self.buf,
            );
            write!(f, "\nbuf: \n{}", s,)
        } else {
            write!(
                f,
                "CacheEntry {{ inode_file: ???, inode_id: {}, page_id: {}, data_len: {}, dirty: {} }}",
                self.inode_id,
                self.page_id,
                self.data_len,
                self.dirty,
                //self.buf,
            )
        }
    }
}
