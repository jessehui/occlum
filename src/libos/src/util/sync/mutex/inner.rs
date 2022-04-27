/// This implementation makes reference to musl libc's design but only keep the basic
/// functionality. Recursive, error-checking, priority-inheritance or robust-list
/// are not supported yet.
// use super::super::futex::{FutexPtr, FUTEX_BUCKETS};
use super::*;

use crate::process::{futex_wait, futex_wake};
use std::convert::{TryFrom, TryInto};
use std::hint;
use std::sync::atomic::{AtomicI32, Ordering};
// use spin::Mutex;

/// The number of spinning time before sleeping
/// In musl's implmenetation, this is `100`. Considering more overhead in SGX environment,
/// here we make it bigger.
const SPIN_COUNT: usize = 1000;

/// This struct can gurantee there is at most one thread accessing the data.
/// `status` indicates the status of this mutex.
/// `waiters` indicates the number of waiters waiting the mutex.
///
/// There are three states of this mutex:
/// - Free: No one is holding the lock. Init state and can also be set by the thread who release the lock.
/// - Locked: One thread is holding the lock. Set by the thread who acquires the lock.
/// - LockedWithWaiters: One thread is holding the lock and some threads are waiting. Set by the waiting thread.
///
/// The state transition will look like below:
///                Thread 1              |                     Thread 2
///  no lock:        Free                |  no lock:         (do something)
///  try lock:      Locked               |  no lock:         (do something)
///  hold lock:   (do something)         |  try lock:       LockedWithWaiters
///  hold lock:   (do something)         |  wait lock:           (sleep)
///  unlock:         Free                |  wait lock:           (sleep)
///  no lock:    (do something else)     |  wake and try lock:   Locked
///  no lock:    (do something else)     |  hold lock:        (do something)
///  no lock:    (do something else)     |  unlock:               Free
#[derive(Debug)]
pub(super) struct MutexInner {
    status: AtomicLockStatus,
    waiters: AtomicI32,
    // Although WaiterQueue has inner mutex, we still need an exterior mutex to synchronize the WaiterQueue and the status.
    // waiter_queue: Mutex<WaiterQueue>,
}

// This struct is the atomic wrapper for LockStatus.
#[derive(Debug)]
struct AtomicLockStatus(AtomicI32);

// The status code keeps the same as the implementation in musl.
#[derive(Debug, Copy, Clone)]
#[repr(i32)]
enum LockStatus {
    Free = 0,
    Locked = Errno::EBUSY as i32,
    LockedWithWaiters = -2147483632, // 0x8000_0010 = (EBUSY | 0x8000_0000)
}

impl MutexInner {
    pub(super) fn new() -> MutexInner {
        MutexInner {
            status: AtomicLockStatus::init(),
            waiters: AtomicI32::new(0),
            // waiter_queue: Mutex::new(WaiterQueue::new()),
        }
    }

    pub(super) fn try_lock(&self) -> Result<()> {
        if self.status.try_set_lock().is_ok() {
            Ok(())
        } else {
            Err(errno!(EBUSY, "the lock is held by other threads"))
        }
    }

    pub(super) fn lock(&self) -> Result<()> {
        if let Ok(_) = self.try_lock() {
            return Ok(());
        }

        // Spin for a short while if no one is waiting but the lock is held.
        let mut spins = SPIN_COUNT;
        while spins != 0
            && self.status.is_locked()
            // Can't reorder here. `Relaxed` is enough.
            && self.waiters.load(Ordering::Relaxed) == 0
        {
            hint::spin_loop();
            spins -= 1;
        }

        loop {
            if let Ok(_) = self.try_lock() {
                return Ok(());
            }

            if self.status.is_free() {
                continue;
            }

            // In try_set_lock_with_waiters, `AcqRel` will make sure this increment happens before. Thus, `Relaxed` can be used here.
            self.waiters.fetch_add(1, Ordering::Relaxed);

            // Ignore the result here. If the state transition fails, the next wait will not block.
            self.status
                .try_set_lock_with_waiters()
                .map_err(|e| errno!(e.errno(), "failed to set lock status"))
                .ok();

            // let ret = self.wait().await;
            let ret = futex_wait(
                &self.status as *const _ as *const i32,
                LockStatus::LockedWithWaiters as i32,
                &None,
            );

            // Use `Acquire` to make sure `ret` is already set.
            self.waiters.fetch_sub(1, Ordering::Acquire);

            if let Err(error) = &ret {
                match error.errno() {
                    Errno::ECANCELED => return ret,
                    _ => (),
                }
            }
        }
    }

    pub(super) fn unlock(&self) -> Result<()> {
        // `get_current_status_and_set_free` will make sure this happens before. Thus, `Relaxed` can be used here.
        let waiters = self.waiters.load(Ordering::Relaxed);
        let previous_status = self.status.get_current_status_and_set_free();

        // Also check previous status in case the waiter number overflows.
        if waiters > 0 || previous_status.is_locked_with_waiters() {
            // self.wake_one_waiter();
            futex_wake(&self.status as *const _ as *const i32, 1 as usize);
        }

        Ok(())
    }

    // async fn wait(&self) -> Result<()> {
    //     let mut waiter = Waiter::new();

    //     let locked_waiter_queue = self.waiter_queue.lock();
    //     // Check the status value again
    //     if !self.status.is_locked_with_waiters() {
    //         return_errno!(EAGAIN, "the status has changed");
    //     }

    //     locked_waiter_queue.enqueue(&mut waiter);

    //     drop(locked_waiter_queue);
    //     let ret = waiter.wait().await;

    //     let locked_waiter_queue = self.waiter_queue.lock();
    //     locked_waiter_queue.dequeue(&mut waiter);
    //     ret
    // }

    // fn wake_one_waiter(&self) {
    //     self.waiter_queue.lock().wake_one();
    // }
}

// For AtomicLockStatus, global ordering is not needed. `Acquire` and `Release` are enough for the atomic operations.
impl AtomicLockStatus {
    fn init() -> Self {
        Self(AtomicI32::new(LockStatus::init() as i32))
    }

    fn try_set_lock(&self) -> Result<()> {
        if let Err(_) = self.0.compare_exchange(
            LockStatus::Free as i32,
            LockStatus::Locked as i32,
            Ordering::AcqRel,
            Ordering::Relaxed, // We don't care failure thus make it `Relaxed`.
        ) {
            return_errno!(EBUSY, "mutex is locked");
        }
        Ok(())
    }

    fn is_free(&self) -> bool {
        self.0.load(Ordering::Acquire) == LockStatus::Free as i32
    }

    fn is_locked(&self) -> bool {
        self.0.load(Ordering::Acquire) != LockStatus::Free as i32
    }

    fn is_locked_with_waiters(&self) -> bool {
        self.0.load(Ordering::Acquire) == LockStatus::LockedWithWaiters as i32
    }

    fn try_set_lock_with_waiters(&self) -> Result<()> {
        if let Err(_) = self.0.compare_exchange(
            LockStatus::Locked as i32,
            LockStatus::LockedWithWaiters as i32,
            Ordering::AcqRel,
            Ordering::Relaxed, // We don't care failure thus make it `Relaxed`.
        ) {
            return_errno!(EAGAIN, "try set lock with waiters failed");
        }
        Ok(())
    }

    fn get_current_status_and_set_free(&self) -> LockStatus {
        let status = self.0.swap(LockStatus::Free as i32, Ordering::AcqRel);
        LockStatus::try_from(status).unwrap()
    }
}

impl LockStatus {
    fn init() -> Self {
        LockStatus::Free
    }

    fn is_locked_with_waiters(&self) -> bool {
        *self as i32 == LockStatus::LockedWithWaiters as i32
    }
}

impl TryFrom<i32> for LockStatus {
    type Error = Error;

    fn try_from(v: i32) -> Result<Self> {
        match v {
            x if x == LockStatus::Free as i32 => Ok(LockStatus::Free),
            x if x == LockStatus::Locked as i32 => Ok(LockStatus::Locked),
            x if x == LockStatus::LockedWithWaiters as i32 => Ok(LockStatus::LockedWithWaiters),
            _ => return_errno!(EINVAL, "Invalid lock status"),
        }
    }
}
