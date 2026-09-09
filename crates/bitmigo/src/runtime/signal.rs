// SPDX-License-Identifier: MIT OR Apache-2.0

//! Signals, the self-pipe they wake the node through, and the in-process broadcast that a
//! shutdown is under way.
//!
//! This is the only module in the workspace that writes `unsafe`, and the only reason the
//! node links `libc` at all (`docs/decisions/0004-libc.md`). Everything a handler does here
//! is on the short list of what a signal handler may do: an atomic store, a `write` to a
//! pipe, and `_exit`. Nothing allocates, takes a lock, or formats a message.
//!
//! The shape is the standard self-pipe. The handler sets [`signalled`] and writes one byte;
//! the listener thread, which is the one thread that must wait on a file descriptor and on
//! the flag at the same time, sees the byte through [`SignalPipe::wait`] and announces the
//! shutdown on [`Shutdown`], which every other thread is waiting on. A second signal does
//! not queue behind any of that: it exits immediately, which is safe because the storage
//! engine recovers from a crash and the operator asking twice wants out now.

use std::io;
use std::os::fd::RawFd;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::Duration;

use crate::runtime::sync::{lock, wait_while, wait_while_timeout};

/// The status a second signal exits with, distinct from both a clean stop and a failure to
/// start, so that a supervisor's logs say which happened.
pub const EXIT_SECOND_SIGNAL: i32 = 2;

/// The signal that asked for the shutdown, or zero. Written by the handler, which has no
/// other way to carry state, and read by [`signalled`].
static SIGNALLED: AtomicI32 = AtomicI32::new(0);

/// The write end of the self-pipe, or `-1` before [`SignalPipe::install`] runs. The handler
/// needs it and cannot be given an argument.
static PIPE_WRITE: AtomicI32 = AtomicI32::new(-1);

/// Handlers are installed once per process; a second install would leak the first pipe.
static INSTALLED: AtomicBool = AtomicBool::new(false);

/// The signal number that asked for a shutdown, if one has arrived.
pub fn signalled() -> Option<i32> {
    let signum = SIGNALLED.load(Ordering::SeqCst);
    if signum == 0 { None } else { Some(signum) }
}

/// What asked the node to stop.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cause {
    /// `SIGINT` or `SIGTERM`.
    Signal(i32),
    /// The node stopped itself: a thread that cannot continue, or a test.
    Internal(&'static str),
}

impl std::fmt::Display for Cause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Cause::Signal(libc::SIGINT) => write!(f, "SIGINT"),
            Cause::Signal(libc::SIGTERM) => write!(f, "SIGTERM"),
            Cause::Signal(signum) => write!(f, "signal {signum}"),
            Cause::Internal(reason) => write!(f, "{reason}"),
        }
    }
}

/// The one fact every thread polls or waits on: the node is stopping, and why.
///
/// Threads that block on a socket are woken by `shutdown(Both)` on that socket and threads
/// that block on a queue are woken by closing it; this is for the ones that have nothing
/// else to wait on, and for the main thread, which does nothing but wait here.
pub struct Shutdown {
    begun: Mutex<Option<Cause>>,
    changed: Condvar,
}

impl Shutdown {
    /// A node that is running.
    pub fn new() -> Shutdown {
        Shutdown {
            begun: Mutex::new(None),
            changed: Condvar::new(),
        }
    }

    /// Announce a shutdown, returning whether this call was the one that started it. The
    /// first cause wins: a `SIGTERM` arriving during a shutdown a fatal error began does not
    /// rewrite the reason in the log.
    pub fn begin(&self, cause: Cause) -> bool {
        let mut begun = lock(&self.begun);
        let first = begun.is_none();
        if first {
            *begun = Some(cause);
        }
        drop(begun);
        self.changed.notify_all();
        first
    }

    /// Whether a shutdown has been announced. Every unbounded loop in the node checks this.
    pub fn is_begun(&self) -> bool {
        self.cause().is_some()
    }

    /// Why the node is stopping, if it is.
    pub fn cause(&self) -> Option<Cause> {
        *lock(&self.begun)
    }

    /// Block until the shutdown is announced. This is what `main` does with its thread.
    pub fn wait(&self) -> Cause {
        let begun = wait_while(&self.changed, lock(&self.begun), |begun| begun.is_none());
        begun.unwrap_or(Cause::Internal("shutdown"))
    }

    /// Block until the shutdown is announced or `timeout` elapses. Threads with periodic
    /// work of their own use this as their tick.
    pub fn wait_timeout(&self, timeout: Duration) -> Option<Cause> {
        *wait_while_timeout(&self.changed, lock(&self.begun), timeout, |begun| {
            begun.is_none()
        })
    }
}

impl Default for Shutdown {
    fn default() -> Shutdown {
        Shutdown::new()
    }
}

/// The read end of the self-pipe, owned by the listener thread.
///
/// Held by exactly one thread: the byte a handler writes is delivered once, and the thread
/// that reads it is the thread that announces the shutdown.
pub struct SignalPipe {
    read: RawFd,
    /// The write end, owned only by a pipe with no handlers behind it. The installed pipe's
    /// write end belongs to [`PIPE_WRITE`] and is never closed: a handler may run at any
    /// moment, including after this struct has gone.
    write: Option<RawFd>,
}

/// What woke [`SignalPipe::wait`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Woken {
    /// A signal arrived, or the shutdown was announced from inside the process.
    pub signalled: bool,
    /// The socket passed to `wait` has a connection waiting.
    pub socket_ready: bool,
}

impl SignalPipe {
    /// Create the self-pipe and install handlers for `SIGINT` and `SIGTERM`. Called once,
    /// from `main`, before any thread is spawned.
    pub fn install() -> io::Result<SignalPipe> {
        assert!(
            !INSTALLED.swap(true, Ordering::SeqCst),
            "signal handlers are installed once per process",
        );

        let mut fds: [RawFd; 2] = [-1, -1];
        // Non-blocking write end: a handler must never block, and a pipe that already holds
        // a wakeup byte needs no second one. Close-on-exec so no child inherits it.
        let created = unsafe_pipe2(&mut fds, libc::O_CLOEXEC | libc::O_NONBLOCK);
        if created != 0 {
            return Err(io::Error::last_os_error());
        }
        let [read, write] = fds;
        assert!(read >= 0 && write >= 0);
        PIPE_WRITE.store(write, Ordering::SeqCst);

        install_handler(libc::SIGINT)?;
        install_handler(libc::SIGTERM)?;
        Ok(SignalPipe { read, write: None })
    }

    /// A pipe with nothing behind it, for the tests that need a runtime rather than a
    /// process. Handlers are installed once per process and a test binary runs many tests,
    /// so a test that wants a node cannot have the real one.
    #[cfg(test)]
    pub fn detached() -> io::Result<SignalPipe> {
        let mut fds: [RawFd; 2] = [-1, -1];
        if unsafe_pipe2(&mut fds, libc::O_CLOEXEC | libc::O_NONBLOCK) != 0 {
            return Err(io::Error::last_os_error());
        }
        let [read, write] = fds;
        Ok(SignalPipe {
            read,
            write: Some(write),
        })
    }

    /// Wait until `socket` has a connection waiting, a signal arrives, or `timeout` elapses.
    ///
    /// The timeout is a backstop, not the mechanism: it bounds how long the caller can miss
    /// a shutdown announced from inside the process, which writes no byte to the pipe.
    pub fn wait(&self, socket: RawFd, timeout: Duration) -> io::Result<Woken> {
        assert!(socket >= 0);
        let millis = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
        let mut fds = [
            libc::pollfd {
                fd: self.read,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: socket,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let ready = unsafe_poll(&mut fds, millis);
        if ready < 0 {
            let error = io::Error::last_os_error();
            // `poll` is the one call here that a signal can interrupt despite `SA_RESTART`.
            if error.kind() == io::ErrorKind::Interrupted {
                return Ok(Woken {
                    signalled: signalled().is_some(),
                    socket_ready: false,
                });
            }
            return Err(error);
        }
        let woken = Woken {
            signalled: fds[0].revents != 0 || signalled().is_some(),
            socket_ready: fds[1].revents != 0,
        };
        if fds[0].revents != 0 {
            self.drain();
        }
        Ok(woken)
    }

    /// Empty the pipe. One byte per signal, and at most a handful ever arrive, but the read
    /// is bounded regardless: a full buffer is drained by the next wakeup.
    fn drain(&self) {
        let mut buffer = [0u8; 16];
        let _read = unsafe_read(self.read, &mut buffer);
    }
}

impl Drop for SignalPipe {
    fn drop(&mut self) {
        unsafe_close(self.read);
        if let Some(write) = self.write {
            unsafe_close(write);
        }
    }
}

/// The handler. Everything it does is async-signal-safe, and it does as little as possible.
extern "C" fn handle_signal(signum: i32) {
    if SIGNALLED.swap(signum, Ordering::SeqCst) != 0 {
        // Asked twice. The operator wants out of a long flush; storage recovers from this
        // exactly as it recovers from a power cut, so the cost is time, not data.
        unsafe_exit(EXIT_SECOND_SIGNAL);
    }
    let fd = PIPE_WRITE.load(Ordering::SeqCst);
    if fd >= 0 {
        let byte: u8 = 1;
        unsafe_write_byte(fd, &byte);
    }
}

/// Point one signal at [`handle_signal`].
fn install_handler(signum: i32) -> io::Result<()> {
    let mut action: libc::sigaction = zeroed_sigaction();
    action.sa_sigaction = handler_address();
    // Restart the syscalls a signal would otherwise cut short: the wakeup is the pipe, and
    // a peer reader that returns `EINTR` mid-message would have to reassemble it.
    action.sa_flags = libc::SA_RESTART;
    let installed = unsafe_sigaction(signum, &action);
    if installed == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

// The `unsafe` surface, one call per function, so that every use of it is named and can be
// read in one place. Each of these is a syscall with no safe wrapper in `std`.

#[allow(
    unsafe_code,
    reason = "no safe wrapper: `sigaction` is the only way to install a handler"
)]
fn zeroed_sigaction() -> libc::sigaction {
    // All-zero is the documented empty action: no flags, no mask, no handler yet.
    unsafe { std::mem::zeroed() }
}

#[allow(
    unsafe_code,
    reason = "no safe wrapper: `sigaction` is the only way to install a handler"
)]
#[allow(
    clippy::as_conversions,
    reason = "a handler is passed to the kernel as an address; `sighandler_t` is that address"
)]
fn handler_address() -> libc::sighandler_t {
    handle_signal as *const () as libc::sighandler_t
}

#[allow(
    unsafe_code,
    reason = "no safe wrapper: `sigaction` is the only way to install a handler"
)]
fn unsafe_sigaction(signum: i32, action: &libc::sigaction) -> i32 {
    unsafe { libc::sigaction(signum, ptr::from_ref(action), ptr::null_mut()) }
}

#[allow(unsafe_code, reason = "no safe wrapper: `std` has no pipe")]
fn unsafe_pipe2(fds: &mut [RawFd; 2], flags: i32) -> i32 {
    unsafe { libc::pipe2(fds.as_mut_ptr(), flags) }
}

#[allow(
    unsafe_code,
    reason = "no safe wrapper: waiting on two descriptors at once needs poll"
)]
fn unsafe_poll(fds: &mut [libc::pollfd; 2], timeout_millis: i32) -> i32 {
    unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout_millis) }
}

#[allow(
    unsafe_code,
    reason = "reading the self-pipe: the descriptor is this struct's own"
)]
fn unsafe_read(fd: RawFd, buffer: &mut [u8; 16]) -> isize {
    unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) }
}

#[allow(
    unsafe_code,
    reason = "the one write a signal handler is allowed to perform"
)]
fn unsafe_write_byte(fd: RawFd, byte: &u8) {
    // A full pipe means a wakeup is already pending, and `EAGAIN` here is the right answer.
    let _written = unsafe { libc::write(fd, ptr::from_ref(byte).cast(), 1) };
}

#[allow(unsafe_code, reason = "closing a descriptor this struct owns")]
fn unsafe_close(fd: RawFd) {
    let _closed = unsafe { libc::close(fd) };
}

#[allow(unsafe_code, reason = "the immediate exit a second signal performs")]
fn unsafe_exit(status: i32) -> ! {
    // `_exit`, not `exit`: no atexit handler, no flush of a buffer another thread is
    // writing to, no lock taken from a signal handler.
    unsafe { libc::_exit(status) }
}

#[cfg(test)]
mod tests {
    use super::{Cause, Shutdown};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    #[test]
    fn begin_is_announced_once_and_keeps_the_first_cause() {
        let shutdown = Shutdown::new();
        assert!(!shutdown.is_begun());
        assert!(shutdown.begin(Cause::Internal("first")));
        assert!(!shutdown.begin(Cause::Signal(libc::SIGTERM)));
        assert_eq!(shutdown.cause(), Some(Cause::Internal("first")));
    }

    #[test]
    fn wait_returns_once_another_thread_begins() {
        let shutdown = Arc::new(Shutdown::new());
        let announcer = Arc::clone(&shutdown);
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            announcer.begin(Cause::Signal(libc::SIGINT));
        });
        assert_eq!(shutdown.wait(), Cause::Signal(libc::SIGINT));
        handle.join().unwrap();
    }

    #[test]
    fn wait_timeout_returns_none_while_the_node_runs() {
        let shutdown = Shutdown::new();
        let started = Instant::now();
        assert_eq!(shutdown.wait_timeout(Duration::from_millis(20)), None);
        assert!(started.elapsed() >= Duration::from_millis(20));
    }

    #[test]
    fn causes_name_themselves() {
        assert_eq!(Cause::Signal(libc::SIGINT).to_string(), "SIGINT");
        assert_eq!(Cause::Signal(libc::SIGTERM).to_string(), "SIGTERM");
        assert_eq!(
            Cause::Internal("listener failed").to_string(),
            "listener failed"
        );
    }
}
