use super::*;
use rcore_fs::vfs::FsInfo;

pub fn do_fstatfs(fd: FileDesc) -> Result<Statfs> {
    debug!("fstatfs: fd: {}", fd);

    let file_ref = current!().file(fd)?;
    let statfs = Statfs::from(file_ref.fs()?.info());
    trace!("fstatfs result: {:?}", statfs);
    Ok(statfs)
}

pub fn do_statfs(path: &str) -> Result<Statfs> {
    debug!("statfs: path: {:?}", path);

    let inode = {
        let current = current!();
        let fs = current.fs().lock().unwrap();
        fs.lookup_inode(path)?
    };
    let statfs = Statfs::from(inode.fs().info());
    trace!("statfs result: {:?}", statfs);
    // {
    //     use time::{timespec_t, do_nanosleep};
    //     use std::time::Duration;
    //     let mut u_rem: timespec_t = timespec_t::from(Duration::new(0, 30000));
    //     do_nanosleep(&u_rem, None);
    // }
    Ok(statfs)
}

#[derive(Debug)]
#[repr(C)]
pub struct Statfs {
    /// Type of filesystem
    f_type: usize,
    /// Optimal transfer block size
    f_bsize: usize,
    /// Total data blocks in filesystem
    f_blocks: usize,
    /// Free blocks in filesystem
    f_bfree: usize,
    /// Free blocks available to unprivileged user
    f_bavail: usize,
    /// Total inodes in filesystem
    f_files: usize,
    /// Free inodes in filesystem
    f_ffree: usize,
    /// Filesystem ID
    f_fsid: [i32; 2],
    /// Maximum length of filenames
    f_namelen: usize,
    /// Fragment size
    f_frsize: usize,
    /// Mount flags of filesystem
    f_flags: usize,
    /// Padding bytes reserved for future use
    f_spare: [usize; 4],
}

impl From<FsInfo> for Statfs {
    fn from(info: FsInfo) -> Self {
        let rcore_to_linux_magic = |val: usize| -> usize {
            const EXT4_SUPER_MAGIC: usize = 0xef53;
            const TMPFS_MAGIC: usize = 0x0102_1994;
            const OVERLAYFS_SUPER_MAGIC: usize = 0x794c_7630;
            const SEFS_MAGIC: usize = rcore_fs_sefs::SEFS_MAGIC as usize;
            match val {
                SEFS_MAGIC => EXT4_SUPER_MAGIC,
                rcore_fs_ramfs::RAMFS_MAGIC | rcore_fs_devfs::DEVFS_MAGIC => TMPFS_MAGIC,
                rcore_fs_unionfs::UNIONFS_MAGIC => OVERLAYFS_SUPER_MAGIC,
                val => val,
            }
        };
        Self {
            f_type: rcore_to_linux_magic(info.magic),
            f_bsize: info.bsize,
            f_blocks: info.blocks,
            f_bfree: info.bfree,
            f_bavail: info.bavail,
            f_files: info.files,
            f_ffree: info.ffree,
            f_fsid: [0i32; 2],
            f_namelen: info.namemax,
            f_frsize: info.frsize,
            f_flags: 0,
            f_spare: [0usize; 4],
        }
    }
}
