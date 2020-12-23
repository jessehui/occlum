// A cache layer between the real file IOs and libos IO syscalls.

use super::*;
use std::fmt;
//use crate::Debug;

mod cache;

pub use self::cache::{get_cache, MAX_CACHE_LENGTH, PAGE_SIZE, *};
