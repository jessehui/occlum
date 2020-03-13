use super::*;

bitflags! {
    pub struct AccessibilityCheckMode : u32 {
        const X_OK = 1;
        const W_OK = 2;
        const R_OK = 4;
    }
}

impl AccessibilityCheckMode {
    pub fn from_u32(bits: u32) -> Result<AccessibilityCheckMode> {
        AccessibilityCheckMode::from_bits(bits).ok_or_else(|| errno!(EINVAL, "invalid mode"))
    }
}

bitflags! {
    pub struct AccessibilityCheckFlags : u32 {
        const AT_SYMLINK_NOFOLLOW = 0x100;
        const AT_EACCESS          = 0x200;
    }
}

impl AccessibilityCheckFlags {
    pub fn from_u32(bits: u32) -> Result<AccessibilityCheckFlags> {
        AccessibilityCheckFlags::from_bits(bits).ok_or_else(|| errno!(EINVAL, "invalid flags"))
    }
}

pub const AT_FDCWD: i32 = -100;

pub fn do_faccessat(
    dirfd: Option<FileDesc>,
    path: &str,
    mode: AccessibilityCheckMode,
    flags: AccessibilityCheckFlags,
) -> Result<()> {
    info!(
        "faccessat: dirfd: {:?}, path: {:?}, mode: {:?}, flags: {:?}",
        dirfd, path, mode, flags
    );
    match dirfd {
        // TODO: handle dirfd
        Some(dirfd) => return_errno!(ENOSYS, "cannot accept dirfd"),
        None => do_access(path, mode),
    }
}

pub fn do_access(path: &str, mode: AccessibilityCheckMode) -> Result<()> {
    info!("access: path: {:?}, mode: {:?}", path, mode);
    let current_ref = process::get_current();
    let mut current = current_ref.lock().unwrap();
    let inode = current.lookup_inode(path)?;
    //let metadata = inode.get_metadata();
    // TODO: check metadata.mode with mode
    Ok(())
}
