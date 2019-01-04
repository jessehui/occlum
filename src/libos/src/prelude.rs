use std;
pub use sgx_types::*;
pub use sgx_trts::libc;

//pub use {elf_helper, errno, file, file_table, fs, mm, process, syscall, vma, };

pub use std::marker::{Sync, Send};
pub use std::sync::{Arc, SgxMutex, SgxMutexGuard, SgxRwLock,
    SgxRwLockReadGuard, SgxRwLockWriteGuard};
pub use std::cell::{Cell, RefCell};
pub use std::result::Result;
//pub use std::borrow::BorrowMut;
pub use std::boxed::Box;
pub use std::vec::Vec;
pub use std::string::{String};
pub use std::collections::{HashMap, VecDeque};
pub use std::fmt::{Debug, Display};
pub use std::io::{Read, Write, Seek, SeekFrom};
pub use std::rc::{Rc};
pub use std::iter::{Iterator};
pub use std::cmp::{Ordering, PartialOrd};
pub use std::borrow::{ToOwned};

pub use errno::Error as Error;
pub use errno::Errno;
pub use errno::Errno::{*};

pub use fs::off_t;

macro_rules! debug_trace {
    () => {
        println!("> Line = {}, File = {}", line!(), file!())
    };
}

macro_rules! errno {
    ($errno: ident, $msg: expr) => {
        {
            println!("ERROR: {} ({}, line {} in file {})", $errno, $msg, line!(), file!());
            Err(Error::new($errno, $msg))
        }
    }
}

pub fn align_up(addr: usize, align: usize) -> usize {
    (addr + (align - 1)) / align * align
}

pub fn align_down(addr: usize, align: usize) -> usize {
    addr & !(align - 1)
}