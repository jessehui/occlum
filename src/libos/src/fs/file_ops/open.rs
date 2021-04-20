use super::*;

pub fn do_openat(fs_path: &FsPath, flags: u32, mode: u32) -> Result<FileDesc> {
    warn!(
        "openat: fs_path: {:?}, flags: {:#o}, mode: {:#o}",
        fs_path, flags, mode
    );

    // Note: This is a hack for python multiprocess support only.
    let current_tid = current!().tid();
    if current_tid >= 5 && fs_path.to_abs_path().unwrap() == "/dev/null".to_string() {
        use std::time::Duration;
        use time::{do_nanosleep, timespec_t};
        let mut u_sleep: timespec_t;
        let mut u_rem: timespec_t = timespec_t::from(Duration::new(5, 0));
        warn!("sleep start");
        while u_rem.sec() != 0 {
            u_sleep = u_rem.clone();
            do_nanosleep(&u_sleep, Some(&mut u_rem));
        }
        warn!("sleep done");
    }

    let path = fs_path.to_abs_path()?;
    let current = current!();
    let fs = current.fs().lock().unwrap();

    let file_ref: Arc<dyn File> = fs.open_file(&path, flags, mode)?;

    let fd = {
        let creation_flags = CreationFlags::from_bits_truncate(flags);
        current.add_file(file_ref, creation_flags.must_close_on_spawn())
    };
    Ok(fd)
}
