use super::*;

type __fsword_t = i64;
type fsblkcnt_t = u64;
type fsfilcnt_t = u64;
#[derive(Default)]
struct fsid_t {
    __fsid_val: [i32; 2],
}

const TMPFS_MAGIC: __fsword_t = 0x01021994;

#[derive(Default)]
#[repr(C)]
pub struct Statfs {
    pub f_type: __fsword_t,
    pub f_bsize: __fsword_t,
    pub f_blocks: fsblkcnt_t,
    pub f_bfree: fsblkcnt_t,
    pub f_bavail: fsblkcnt_t,
    pub f_files: fsfilcnt_t,
    pub f_ffree: fsfilcnt_t,
    f_fsid: fsid_t,
    pub f_namelen: __fsword_t,
    pub f_frsize: __fsword_t,

    f_spare: [__fsword_t; 5],
}

// f_blocks=16384, f_bfree=16334, f_bavail=16334, f_files=8153914, f_ffree=8153863, f_fsid={val=[0, 0]}, f_namelen=255, f_frsize=4096,
// pub fn do_statfs(path: String) -> Result<Statfs> {
//     debug!("statfs: path: {:?}", path);

//     let mut statfs= Statfs::default();
//     if &path == "/dev/shm/" {
//         statfs.f_type = TMPFS_MAGIC;
//         statfs.f_bsize = 4096;
//         statfs.f_blocks = 16384;
//         statfs.f_bfree = 16334;
//         statfs.f_files = 8153914;
//         statfs.f_ffree = 8153863;
//         statfs.f_namelen=255;
//         statfs.f_frsize=4096;
//     } else {
//         return_errno!(ENOSYS, "not supported fs type");
//     }

//     Ok(statfs)
// }
