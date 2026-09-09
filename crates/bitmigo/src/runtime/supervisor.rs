// SPDX-License-Identifier: MIT OR Apache-2.0

//! The thread supervisor: every thread the node will ever run, created at startup from a
//! fixed table, named, given an explicit stack, and accounted for at shutdown.
//!
//! Threads are never spawned on demand. A node that spawns a thread per connection hands an
//! anonymous peer a way to make it allocate; a node whose threads all exist before the first
//! packet arrives has one fewer thing an attacker can push on. The cost is stated up front:
//! the table's stack sizes multiplied by its rows, reserved whether the node has one peer or
//! thirty-two.
//!
//! Exit accounting is separate from `join` because `JoinHandle::join` cannot time out.
//! Each thread marks its slot as it returns, so the supervisor can wait for *most* threads
//! with a deadline and still join the one thread whose work must finish.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{Builder, JoinHandle};
use std::time::{Duration, Instant};

use crate::runtime::sync::{lock, wait};

/// The stack a thread gets unless the table says otherwise. This is what `std` would have
/// given it anyway; it is written down so that the peer threads' smaller stack reads as a
/// decision rather than as a difference from something unstated.
pub const DEFAULT_STACK_BYTES: usize = 2 * 1024 * 1024;

/// How long a thread that is not the node's memory gets to notice the shutdown. It holds
/// nothing that must reach the disk, so past this the node stops waiting for it.
pub const JOIN_DEADLINE: Duration = Duration::from_secs(5);

/// The tick the deadline wait wakes on, so that a thread exiting is noticed promptly and a
/// wait that will never be satisfied is still bounded.
const EXIT_TICK: Duration = Duration::from_millis(50);

/// One running thread. The index is its row in the exit accounting, which stays valid even
/// once a thread has been taken out of the table to be joined on its own.
struct Thread {
    index: usize,
    name: String,
    handle: JoinHandle<()>,
}

/// Which threads have returned. A `Vec<bool>` indexed by spawn order rather than a counter,
/// so that a report can name the threads that did not.
struct Exits {
    returned: Mutex<Vec<bool>>,
    changed: Condvar,
}

impl Exits {
    fn mark(&self, index: usize) {
        let mut returned = lock(&self.returned);
        let slot = returned
            .get_mut(index)
            .expect("every spawned thread has a slot");
        assert!(!*slot, "a thread returns once");
        *slot = true;
        drop(returned);
        self.changed.notify_all();
    }

    fn outstanding(&self) -> Vec<usize> {
        let returned = lock(&self.returned);
        returned
            .iter()
            .enumerate()
            .filter_map(|(index, done)| if *done { None } else { Some(index) })
            .collect()
    }
}

/// What the shutdown wait ended with, for the operator's last line of output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShutdownReport {
    /// Threads that returned and were joined.
    pub joined: usize,
    /// Threads still running when the deadline passed, by name. Empty is the normal case.
    pub outstanding: Vec<String>,
    /// How long the whole wait took.
    pub elapsed: Duration,
}

impl std::fmt::Display for ShutdownReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} threads joined in {:?}", self.joined, self.elapsed)?;
        if !self.outstanding.is_empty() {
            write!(
                f,
                ", {} still running: {}",
                self.outstanding.len(),
                self.outstanding.join(", ")
            )?;
        }
        Ok(())
    }
}

/// The fixed set of threads, and the accounting that lets a shutdown end in bounded time.
pub struct Supervisor {
    threads: Vec<Thread>,
    exits: Arc<Exits>,
    capacity: usize,
    started: AtomicBool,
}

impl Supervisor {
    /// A supervisor that will spawn exactly `capacity` threads. The bound is a hard one:
    /// [`Supervisor::spawn`] past it is a programming error, not a runtime condition.
    pub fn with_capacity(capacity: usize) -> Supervisor {
        assert!(capacity > 0);
        Supervisor {
            threads: Vec::with_capacity(capacity),
            exits: Arc::new(Exits {
                returned: Mutex::new(Vec::with_capacity(capacity)),
                changed: Condvar::new(),
            }),
            capacity,
            started: AtomicBool::new(false),
        }
    }

    /// Start one thread from the table. The name reaches `gdb`, `top` and every panic
    /// message, and the node asserts on it: the queue that peer readers alone may block on
    /// checks the name of the thread trying to block.
    pub fn spawn<B>(&mut self, name: &str, stack_bytes: usize, body: B) -> io::Result<()>
    where
        B: FnOnce() + Send + 'static,
    {
        assert!(!name.is_empty());
        assert!(
            stack_bytes >= 64 * 1024,
            "a thread needs room for its frames"
        );
        assert!(
            self.threads.len() < self.capacity,
            "the thread table is fixed at {} threads",
            self.capacity,
        );

        let index = self.threads.len();
        lock(&self.exits.returned).push(false);
        let exits = Arc::clone(&self.exits);
        let handle = Builder::new()
            .name(name.to_owned())
            .stack_size(stack_bytes)
            .spawn(move || {
                body();
                exits.mark(index);
            })?;
        self.threads.push(Thread {
            index,
            name: name.to_owned(),
            handle,
        });
        self.started.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// How many threads are running.
    pub fn spawned(&self) -> usize {
        self.threads.len()
    }

    /// Join the thread named `unbounded` however long it takes, then give every other thread
    /// `deadline` to return.
    ///
    /// The asymmetry is the point. One thread owns state that must reach the disk before the
    /// process ends, and interrupting its flush is the one thing a clean stop must not do.
    /// The others hold nothing: past the deadline the node reports them and exits, and the
    /// operating system reclaims their stacks.
    pub fn finish(mut self, unbounded: &str, deadline: Duration) -> ShutdownReport {
        assert!(self.started.load(Ordering::SeqCst), "nothing was spawned");
        let started = Instant::now();
        let mut joined: usize = 0;

        // Everyone else first, and concurrently with the flush: the deadline is theirs, and
        // it must not start ticking only once the flush has finished.
        let flushing = self
            .threads
            .iter()
            .position(|thread| thread.name == unbounded);
        let skip = flushing.map(|position| {
            self.threads
                .get(position)
                .map_or(usize::MAX, |thread| thread.index)
        });
        self.wait_for_exits(deadline, skip);

        if let Some(position) = flushing {
            let thread = self.threads.remove(position);
            let name = thread.name.clone();
            if thread.handle.join().is_err() {
                // Unreachable in release, where a panic aborts the process; in a debug build
                // it means a bug in that thread, and the report should say so.
                eprintln!("bitmigo: {name} panicked");
            }
            joined = joined.saturating_add(1);
        }

        let outstanding = self.exits.outstanding();
        let mut names = Vec::with_capacity(outstanding.len());
        for thread in self.threads {
            if outstanding.contains(&thread.index) {
                names.push(thread.name);
                // Deliberately not joined: the handle is dropped and the thread detached.
                continue;
            }
            if thread.handle.join().is_err() {
                eprintln!("bitmigo: {} panicked", thread.name);
            }
            joined = joined.saturating_add(1);
        }

        ShutdownReport {
            joined,
            outstanding: names,
            elapsed: started.elapsed(),
        }
    }

    /// Wait until every thread but `skip` has returned, or `deadline` passes.
    fn wait_for_exits(&self, deadline: Duration, skip: Option<usize>) {
        let until = Instant::now() + deadline;
        let mut returned = lock(&self.exits.returned);
        while returned
            .iter()
            .enumerate()
            .any(|(index, done)| !*done && Some(index) != skip)
        {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return;
            }
            returned = wait(&self.exits.changed, returned, left.min(EXIT_TICK));
        }
    }
}

/// Whether the calling thread's name begins with `prefix`.
///
/// Used for the one invariant that is about *which* thread is running: only a peer reader
/// may block on a full queue. An unnamed thread is never one of the node's own.
pub fn current_thread_is(prefix: &str) -> bool {
    std::thread::current()
        .name()
        .is_some_and(|name| name.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::{DEFAULT_STACK_BYTES, Supervisor, current_thread_is};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn every_thread_is_joined_when_they_all_return() {
        let mut supervisor = Supervisor::with_capacity(4);
        for index in 0..4 {
            supervisor
                .spawn(&format!("worker-{index}"), DEFAULT_STACK_BYTES, || {})
                .unwrap();
        }
        assert_eq!(supervisor.spawned(), 4);
        let report = supervisor.finish("worker-0", Duration::from_secs(5));
        assert_eq!(report.joined, 4);
        assert!(report.outstanding.is_empty());
    }

    #[test]
    fn a_thread_that_does_not_return_is_named_and_left_behind() {
        let stop = Arc::new(AtomicBool::new(false));
        let mut supervisor = Supervisor::with_capacity(2);
        supervisor
            .spawn("prompt", DEFAULT_STACK_BYTES, || {})
            .unwrap();
        let parked = Arc::clone(&stop);
        supervisor
            .spawn("stuck", DEFAULT_STACK_BYTES, move || {
                while !parked.load(Ordering::SeqCst) {
                    thread::sleep(Duration::from_millis(5));
                }
            })
            .unwrap();

        let report = supervisor.finish("prompt", Duration::from_millis(100));
        assert_eq!(report.joined, 1);
        assert_eq!(report.outstanding, vec!["stuck".to_owned()]);
        assert!(report.elapsed >= Duration::from_millis(100));
        stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn the_unbounded_thread_is_waited_for_past_the_deadline() {
        let mut supervisor = Supervisor::with_capacity(1);
        supervisor
            .spawn("validation", DEFAULT_STACK_BYTES, || {
                thread::sleep(Duration::from_millis(150));
            })
            .unwrap();
        let report = supervisor.finish("validation", Duration::from_millis(10));
        assert_eq!(report.joined, 1);
        assert!(report.outstanding.is_empty());
        assert!(report.elapsed >= Duration::from_millis(150));
    }

    #[test]
    fn threads_carry_their_table_name() {
        let mut supervisor = Supervisor::with_capacity(1);
        let named = Arc::new(AtomicBool::new(false));
        let observed = Arc::clone(&named);
        supervisor
            .spawn("peer-reader-07", DEFAULT_STACK_BYTES, move || {
                observed.store(current_thread_is("peer-reader-"), Ordering::SeqCst);
            })
            .unwrap();
        let report = supervisor.finish("peer-reader-07", Duration::from_secs(1));
        assert_eq!(report.joined, 1);
        assert!(named.load(Ordering::SeqCst));
        assert!(!current_thread_is("peer-reader-"));
    }
}
