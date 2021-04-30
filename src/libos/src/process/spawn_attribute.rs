use super::*;
use crate::signal::{sigset_t, SigSet};
use crate::util::mem_util::from_user::check_ptr;

// Note: Only support POSIX_SPAWN_SETSIGDEF and POSIX_SPAWN_SETSIGMASK
#[derive(Default, Debug, Copy, Clone)]
pub struct SpawnAttr {
    pub sig_mask: Option<SigSet>,
    pub sig_default: Option<SigSet>,
}

// Glibc and musl use 128 bytes to represent sig_set_t
type SpawnAttrSigSet = [sigset_t; 16];

// Note: The name of the element follows the glibc style. The comments show the
// name in musl.
#[repr(C)]
#[derive(Debug)]
pub struct posix_spawnattr_t {
    flags: SpawnAttributeFlags, // __flags
    pgrp: i32,                  // __pgrp
    sd: SpawnAttrSigSet,        // __def
    ss: SpawnAttrSigSet,        // __mask
    // Below elements are different in musl but we are not using it for now. So just ignore.
    sp: SchedParam,
    policy: i32,
    pad: [i32; 16],
}

#[repr(C)]
#[derive(Debug)]
struct SchedParam {
    sched_priority: i32,
}

bitflags! {
    pub struct SpawnAttributeFlags: u16 {
        const POSIX_SPAWN_RESETIDS = 1; // 0x1
        const POSIX_SPAWN_SETPGROUP = 1 << 1; // 0x2
        const POSIX_SPAWN_SETSIGDEF = 1 << 2; // 0x4
        const POSIX_SPAWN_SETSIGMASK = 1 << 3; // 0x8
        const POSIX_SPAWN_SETSCHEDPARAM = 1 << 4; // 0x10
        const POSIX_SPAWN_SETSCHEDULER = 1 << 5; // 0x20
    }
}

impl SpawnAttributeFlags {
    fn supported(&self) -> bool {
        let unsupported_flags = SpawnAttributeFlags::all()
            - SpawnAttributeFlags::POSIX_SPAWN_SETSIGDEF
            - SpawnAttributeFlags::POSIX_SPAWN_SETSIGMASK;
        if self.intersects(unsupported_flags) {
            false
        } else {
            true
        }
    }
}

// Note: Only support POSIX_SPAWN_SETSIGDEF and POSIX_SPAWN_SETSIGMASK
pub fn clone_spawn_atrributes_safely(
    attr_ptr: *const posix_spawnattr_t,
) -> Result<Option<SpawnAttr>> {
    if attr_ptr != std::ptr::null() {
        check_ptr(attr_ptr)?;
    } else {
        return Ok(None);
    }

    let spawn_attr = unsafe { &*attr_ptr };
    let mut safe_attr = SpawnAttr::default();
    if spawn_attr.flags.is_empty() {
        return Ok(None);
    }

    if !spawn_attr.flags.supported() {
        warn!(
            "Unsupported flags contained. Attribute flags: {:?}",
            spawn_attr.flags
        );
    }

    if spawn_attr
        .flags
        .contains(SpawnAttributeFlags::POSIX_SPAWN_SETSIGDEF)
    {
        safe_attr.sig_default = Some(SigSet::from_c(spawn_attr.sd[0]));
    }
    if spawn_attr
        .flags
        .contains(SpawnAttributeFlags::POSIX_SPAWN_SETSIGMASK)
    {
        safe_attr.sig_mask = Some(SigSet::from_c(spawn_attr.ss[0]));
    }

    Ok(Some(safe_attr))
}
