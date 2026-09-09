// SPDX-License-Identifier: MIT OR Apache-2.0

//! Locking, with the poisoning policy stated once.
//!
//! A poisoned mutex means a thread panicked while holding it. In a release build that cannot
//! happen — a panic aborts the process — so these exist for debug builds and tests, and there
//! they take the inner value rather than propagating: what the node keeps behind a mutex is
//! its own bookkeeping, and refusing to look at it would turn one thread's bug into a hang in
//! every other thread. Every lock in the node goes through here, so that is one decision
//! rather than thirty scattered `unwrap`s.

use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::Duration;

/// Take a mutex.
pub fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Wait to be notified, or for `timeout` to pass. Every wait in the node is bounded, so that
/// a missed notification costs a tick rather than a hang.
pub fn wait<'a, T>(
    condvar: &Condvar,
    guard: MutexGuard<'a, T>,
    timeout: Duration,
) -> MutexGuard<'a, T> {
    match condvar.wait_timeout(guard, timeout) {
        Ok((guard, _)) => guard,
        Err(poisoned) => poisoned.into_inner().0,
    }
}

/// Wait until `predicate` is false.
pub fn wait_while<'a, T, P>(
    condvar: &Condvar,
    guard: MutexGuard<'a, T>,
    predicate: P,
) -> MutexGuard<'a, T>
where
    P: FnMut(&mut T) -> bool,
{
    match condvar.wait_while(guard, predicate) {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Wait until `predicate` is false or `timeout` passes.
pub fn wait_while_timeout<'a, T, P>(
    condvar: &Condvar,
    guard: MutexGuard<'a, T>,
    timeout: Duration,
    predicate: P,
) -> MutexGuard<'a, T>
where
    P: FnMut(&mut T) -> bool,
{
    match condvar.wait_timeout_while(guard, timeout, predicate) {
        Ok((guard, _)) => guard,
        Err(poisoned) => poisoned.into_inner().0,
    }
}
