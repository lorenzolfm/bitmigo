// SPDX-License-Identifier: MIT OR Apache-2.0

//! A bounded table of open files, so that serving blocks costs a fixed number of
//! descriptors however long the chain gets.
//!
//! At mainnet the block series is roughly 5,600 files, and thirty-two peer writers serve
//! `getdata` out of them by `pread` while validation reads the block it is connecting. A
//! handle per file would be 5,600 descriptors for a workload that touches a handful at a
//! time; a handle per read would be an `open` on every served block. So: a fixed table,
//! least-recently-used, preallocated at startup and never grown. btcd's is 25.
//!
//! The lock is held to find a handle and released before the read: a handle is an
//! [`Arc<File>`], and a `pread` needs no cursor, so thirty-two peers reading thirty-two
//! different files wait on each other only for the lookup.

#![allow(
    dead_code,
    reason = "the table is read through the series, whose readers are BM-10's and BM-24's"
)]

use std::fs::File;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::runtime::sync::lock;

/// How many files stay open.
///
/// Above the thirty-three threads that can read at once — thirty-two peer writers and
/// validation — so that two readers on two files never evict each other's handle in a
/// loop, and far below the file count of a mainnet series.
pub const MAX_OPEN_FILES: usize = 40;

const _: () = assert!(MAX_OPEN_FILES > crate::peer::PEER_SLOTS);

/// One open file, and which of the series it is.
struct Entry {
    file: u32,
    handle: Arc<File>,
}

/// The table.
pub struct Handles {
    open: Mutex<Vec<Entry>>,
}

impl Handles {
    /// An empty table at its full capacity: the allocation happens here, at startup, and
    /// never again.
    pub fn new() -> Handles {
        Handles {
            open: Mutex::new(Vec::with_capacity(MAX_OPEN_FILES)),
        }
    }

    /// The handle for one file, opening it if the table does not hold it.
    ///
    /// `path` is a closure so that the common case — a hit — builds no path at all.
    pub fn get<P>(&self, file: u32, path: P) -> io::Result<Arc<File>>
    where
        P: FnOnce() -> PathBuf,
    {
        let mut open = lock(&self.open);
        if let Some(position) = open.iter().position(|entry| entry.file == file) {
            // Most recently used goes to the front, so the eviction below always takes the
            // oldest. The table is forty entries, so the rotation is a memmove of nothing.
            let entry = open.remove(position);
            let handle = Arc::clone(&entry.handle);
            open.insert(0, entry);
            return Ok(handle);
        }

        // Opened while the lock is held. Two threads asking for the same missing file at
        // the same moment would otherwise both open it, and the table would hold one and
        // leak the other for as long as its reader ran.
        let handle = Arc::new(File::open(path())?);
        if open.len() >= MAX_OPEN_FILES {
            // The dropped `Arc` closes the file only once the last reader still holding it
            // has finished, which is what makes evicting a file somebody is reading safe.
            open.pop();
        }
        open.insert(
            0,
            Entry {
                file,
                handle: Arc::clone(&handle),
            },
        );
        assert!(open.len() <= MAX_OPEN_FILES, "the table never grows");
        Ok(handle)
    }

    /// How many files are open. The bound, from the outside.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        lock(&self.open).len()
    }
}
