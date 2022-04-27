use super::*;

mod inner;

use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use core::{fmt, mem, ptr};
use inner::MutexInner;
use std::boxed::Box;

/// An asynchronous mutex type.
///
/// This is simillar to `std::sync::Mutex` but with the following differences:
/// - `lock` method is asynchronous and will not block
/// - the `MutexGuard` can be held across `await` calls
pub struct Mutex<T: ?Sized> {
    inner: Box<MutexInner>,
    data: UnsafeCell<T>,
}

/// Mutex can be used across threads as long as T is `Send`.
unsafe impl<T> Send for Mutex<T> where T: ?Sized + Send {}
unsafe impl<T> Sync for Mutex<T> where T: ?Sized + Send {}

impl<T> Mutex<T> {
    pub fn new(t: T) -> Mutex<T> {
        Mutex {
            inner: Box::new(MutexInner::new()),
            data: UnsafeCell::new(t),
        }
    }
}

impl<T: ?Sized> Mutex<T> {
    /// Async method to lock the mutex
    pub fn lock(&self) -> Result<MutexGuard<'_, T>> {
        self.inner.lock().unwrap();
        Ok(MutexGuard::new(self))
    }

    /// Try acquiring the lock without blocking
    pub fn try_lock(&self) -> Result<MutexGuard<'_, T>> {
        self.inner.try_lock()?;
        Ok(MutexGuard::new(self))
    }

    /// Consume the mutex to get inner T
    pub fn into_inner(self) -> T
    where
        T: Sized,
    {
        let (inner, data) = {
            let Mutex {
                ref inner,
                ref data,
            } = self;
            unsafe { (ptr::read(inner), ptr::read(data)) }
        };
        mem::forget(self);
        drop(inner);

        data.into_inner()
    }

    /// Get a mutable reference to the inner data
    pub fn get_mut(&mut self) -> &mut T {
        unsafe { &mut *self.data.get() }
    }
}

impl<T: core::fmt::Debug> fmt::Debug for Mutex<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mutex lock")
            .field("inner", &self.inner)
            .field("data", unsafe { &(*self.data.get()) })
            .finish()
    }
}

impl<T: ?Sized + Default> Default for Mutex<T> {
    fn default() -> Mutex<T> {
        Mutex::new(Default::default())
    }
}

/// A handle to a held mutex. This can be used across `await` calls because
/// it is `Send`.
pub struct MutexGuard<'a, T: ?Sized + 'a> {
    lock: &'a Mutex<T>,
}

impl<T: ?Sized> !Send for MutexGuard<'_, T> {}
unsafe impl<T: ?Sized + Send + Sync> Sync for MutexGuard<'_, T> {}

impl<'a, T: ?Sized> MutexGuard<'a, T> {
    pub fn new(lock: &'a Mutex<T>) -> MutexGuard<'a, T> {
        MutexGuard { lock }
    }
}

impl<T: ?Sized> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.inner.unlock().unwrap();
    }
}

impl<T: ?Sized> Deref for MutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { &*self.lock.data.get() }
    }
}

impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<T: ?Sized + fmt::Debug> fmt::Debug for MutexGuard<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}
