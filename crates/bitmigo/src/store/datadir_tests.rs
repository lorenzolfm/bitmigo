// SPDX-License-Identifier: MIT OR Apache-2.0

//! The layout, and the lock that is the reason for it.

use super::{BLOCKS_DIR, COINS_DIR, DataDir, INDEX_DIR, LOCK_FILE};

#[test]
fn opening_makes_the_chain_directory_and_its_four_subdirectories() {
    let directory = DataDir::transient().unwrap();
    let root = directory.root().to_path_buf();

    // Every chain gets its own directory, mainnet included: Core's asymmetry is what makes
    // every path-building call site know which chain it is on.
    assert_eq!(
        root.file_name().and_then(|name| name.to_str()),
        Some("regtest")
    );
    assert!(root.join(LOCK_FILE).is_file());
    assert!(root.join(BLOCKS_DIR).is_dir());
    assert!(root.join(INDEX_DIR).is_dir());
    assert!(root.join(COINS_DIR).is_dir());
    assert_eq!(directory.blocks(), root.join(BLOCKS_DIR));
    assert_eq!(directory.index(), root.join(INDEX_DIR));
    assert_eq!(directory.coins(), root.join(COINS_DIR));
}

#[test]
fn a_second_process_on_one_datadir_is_refused() {
    let held = DataDir::transient().unwrap();
    // The same argument the node's own startup passes: the parent of the chain directory.
    let data_dir = held.root().parent().unwrap().to_path_buf();

    let refused = DataDir::open(&data_dir, "regtest");
    let error = refused
        .err()
        .expect("two bitmigos on one datadir is refused");
    assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
    assert!(error.to_string().contains("another bitmigo is running"));

    // A different chain below the same data directory is a different store, and both may
    // run: the lock is per chain, which is what the directory-per-chain rule buys.
    let signet = DataDir::open(&data_dir, "signet");
    assert!(signet.is_ok());
}

#[test]
fn the_lock_goes_when_the_process_that_held_it_does() {
    let data_dir = {
        let held = DataDir::transient().unwrap();
        held.root().parent().unwrap().to_path_buf()
    };
    // `transient` removed the directory with the lock, so this is the ordinary restart:
    // the kernel dropped the lock, and there is no stale lockfile to clear away.
    let again = DataDir::open(&data_dir, "regtest");
    assert!(again.is_ok(), "a released lock is takeable again");
    std::fs::remove_dir_all(&data_dir).ok();
}
