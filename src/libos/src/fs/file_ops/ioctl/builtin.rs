//! Built-in ioctls.

use super::*;

#[derive(Debug)]
#[repr(C)]
pub struct WinSize {
    pub ws_row: u16,
    pub ws_col: u16,
    pub ws_xpixel: u16,
    pub ws_ypixel: u16,
}

#[derive(Debug)]
#[repr(C)]
pub struct IfConf {
    pub ifc_len: i32,
    pub ifc_buf: *const u8,
}

const IFNAMSIZ: usize = 16;
#[derive(Debug)]
#[repr(C)]
pub struct IfReq {
    pub ifr_name: [u8; IFNAMSIZ],
    pub ifr_union: [u8; 24],
}

type tcflag_t = c_uint;
type cc_t = c_uchar;
type speed_t = c_uint;
#[derive(Debug)]
#[repr(C)]
pub struct termios {
    pub c_iflag: tcflag_t,
    pub c_oflag: tcflag_t,
    pub c_cflag: tcflag_t,
    pub c_lflag: tcflag_t,
    pub c_line: cc_t,
    pub c_cc: [cc_t; 32],
    pub c_ispeed: speed_t,
    pub c_ospeed: speed_t,
}
