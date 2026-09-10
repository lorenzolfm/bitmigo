// SPDX-License-Identifier: MIT OR Apache-2.0

//! The data directory, and the lock that makes it this process's.
//!
//! One directory per chain, mainnet included. Core puts mainnet at the datadir root and
//! hangs `signet/` and `regtest/` beneath it, so every path-building call site has to know
//! about the asymmetry; one rule is cheaper than two (BM-D4 decision 9).
//!
//! Four subdirectories rather than one flat directory, because the size split is real:
//! roughly 700 GB of blocks and undo against 9 GB of coins and 134 MB of index at mainnet.
//! An operator can symlink `blocks/` onto a spinning disk today with no flag at all, and
//! what a `-blocksdir` equivalent should look like is the operator surface's question.
//!
//! # The lock
//!
//! Two bitmigo processes on one datadir would corrupt the coin store, so this is not
//! optional for a node other people run. [`std::fs::File::try_lock`] was stabilised in Rust
//! 1.89 and gives `flock` semantics from `std`, which is why `libc` stays scoped to signals
//! and `docs/decisions/0004-libc.md` is unchanged (BM-D4 decision 8).
//!
//! The kernel drops the lock when the process dies, so there is no stale-lockfile case —
//! exactly the case a store designed around `kill -9` would otherwise meet on every restart.

use std::fs::{self, File, TryLockError};
use std::io;
use std::path::{Path, PathBuf};

/// The lock file. Empty: what matters is who holds it, not what it says.
pub const LOCK_FILE: &str = "LOCK";

/// Raw blocks and their undo records.
pub const BLOCKS_DIR: &str = "blocks";

/// The index journal.
pub const INDEX_DIR: &str = "index";

/// The coin store (BM-27).
pub const COINS_DIR: &str = "coins";

/// A data directory this process holds the lock on.
///
/// The lock is released when this is dropped, which for the node is when the process ends.
/// Nothing hands out the [`File`]: holding the `DataDir` is holding the lock.
pub struct DataDir {
    root: PathBuf,
    /// Removed when this is dropped. Tests only: every test needs a data directory of its
    /// own, because the lock is the whole point and two tests sharing one would serialise.
    #[cfg(test)]
    transient: bool,
    #[allow(
        dead_code,
        reason = "the value is the lock: dropping the file releases it, so the field is \
                  read by nothing and must outlive every path built from this directory"
    )]
    lock: File,
}

impl DataDir {
    /// Create the layout below `<data_dir>/<chain>/` and take the lock.
    ///
    /// Every directory is created before the lock is taken, because a lock on a file in a
    /// directory that does not exist cannot be taken at all; every directory but the root
    /// is created after it, so that a second process finds the lock rather than a
    /// half-built layout.
    pub fn open(data_dir: &Path, chain: &str) -> io::Result<DataDir> {
        assert!(!chain.is_empty(), "every chain names its own directory");
        let root = data_dir.join(chain);
        fs::create_dir_all(&root)?;

        let path = root.join(LOCK_FILE);
        let lock = File::options()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&path)?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!("another bitmigo is running on {}", root.display()),
                ));
            }
            Err(TryLockError::Error(error)) => return Err(error),
        }

        for directory in [BLOCKS_DIR, INDEX_DIR, COINS_DIR] {
            fs::create_dir_all(root.join(directory))?;
        }
        Ok(DataDir {
            root,
            #[cfg(test)]
            transient: false,
            lock,
        })
    }

    /// A data directory of this test's own, removed when it is dropped.
    #[cfg(test)]
    pub fn transient() -> io::Result<DataDir> {
        let mut directory = DataDir::open(&unique(), "regtest")?;
        directory.transient = true;
        Ok(directory)
    }

    /// The chain's own directory: the anchors and the control socket sit directly in it.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Where `blk*.dat` and `undo*.dat` go. Both series, because they are the two that an
    /// operator would move to another disk together.
    pub fn blocks(&self) -> PathBuf {
        self.root.join(BLOCKS_DIR)
    }

    /// Where the index journal goes.
    pub fn index(&self) -> PathBuf {
        self.root.join(INDEX_DIR)
    }

    /// Where the coin store goes (BM-27).
    #[allow(dead_code, reason = "the coin store opens this: BM-27")]
    pub fn coins(&self) -> PathBuf {
        self.root.join(COINS_DIR)
    }
}

/// A path no other test is using.
#[cfg(test)]
fn unique() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let name = format!(
        "bitmigo-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst),
    );
    std::env::temp_dir().join(name)
}

/// A data directory a test can close and open again, which is what a restart is.
///
/// [`DataDir::transient`] cannot do it: the lock is released by dropping the `DataDir`,
/// and dropping that one takes the directory with it.
#[cfg(test)]
pub struct Scratch {
    root: PathBuf,
}

#[cfg(test)]
impl Scratch {
    /// An empty directory of this test's own.
    pub fn new() -> Scratch {
        Scratch { root: unique() }
    }

    /// Take the lock on it, as a start does.
    pub fn open(&self) -> io::Result<DataDir> {
        DataDir::open(&self.root, "regtest")
    }
}

#[cfg(test)]
impl Drop for Scratch {
    fn drop(&mut self) {
        if self.root.exists()
            && let Err(error) = fs::remove_dir_all(&self.root)
        {
            eprintln!("bitmigo: test directory {}: {error}", self.root.display());
        }
    }
}

#[cfg(test)]
impl Drop for DataDir {
    fn drop(&mut self) {
        if !self.transient {
            return;
        }
        // The parent, because `transient` made one directory per test and put the chain's
        // below it.
        let whole = self.root.parent().unwrap_or(&self.root);
        if let Err(error) = fs::remove_dir_all(whole) {
            eprintln!("bitmigo: test directory {}: {error}", whole.display());
        }
    }
}

#[cfg(test)]
#[path = "datadir_tests.rs"]
mod tests;
