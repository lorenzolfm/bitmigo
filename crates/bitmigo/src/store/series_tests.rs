// SPDX-License-Identifier: MIT OR Apache-2.0

//! The flat-file series: the framing, the roll, and what a location that names the wrong
//! place gets back.

use std::path::PathBuf;

use super::{MAX_FILE_BYTES, SeriesReader, SeriesWriter, open, open_with_bound};
use crate::store::DataDir;
use crate::store::handles::MAX_OPEN_FILES;

/// The magic these tests write.
const MAGIC: [u8; 4] = *b"TSTB";

/// A series in a directory of its own, at a file bound a test can reach.
fn series(bound: u32) -> (DataDir, PathBuf, SeriesWriter, SeriesReader) {
    let directory = DataDir::transient().expect("a test data directory");
    let blocks = directory.blocks();
    let (writer, reader) =
        open_with_bound(&blocks, "tst", MAGIC, 0, 4 * 1024 * 1024, bound).expect("an empty series");
    (directory, blocks, writer, reader)
}

/// A body of a stated length, distinct per length.
fn body(length: usize, seed: u8) -> Vec<u8> {
    (0..length)
        .map(|index| seed.wrapping_add(u8::try_from(index % 251).unwrap_or(0)))
        .collect()
}

#[test]
fn a_record_reads_back_as_the_bytes_that_went_in() {
    let (_directory, _blocks, mut writer, reader) = series(MAX_FILE_BYTES);
    let mut written = Vec::new();
    for length in [0usize, 1, 285, 4096, 100_000] {
        let bytes = body(length, 7);
        let placed = writer.append(&bytes, None).expect("an append");
        // The location names the body, so serving it is one `pread(len)` at the offset.
        assert_eq!(placed.len, u32::try_from(length).unwrap());
        written.push((placed, bytes));
    }
    writer.sync().expect("a sync");
    for (placed, bytes) in written {
        let (back, trailer) = reader.read(placed.file, placed.offset, placed.len).unwrap();
        assert_eq!(back, bytes);
        assert_eq!(trailer, [0u8; 32], "a block series has no trailer");
    }
}

#[test]
fn the_series_rolls_before_a_record_would_take_a_file_past_the_bound() {
    let bound = 4096;
    let (_directory, blocks, mut writer, reader) = series(bound);
    let mut written = Vec::new();
    // Records of a thousand and eight bytes: four to a file, and the fifth rolls.
    for index in 0..14u8 {
        let bytes = body(1000, index);
        written.push((writer.append(&bytes, None).expect("an append"), bytes));
    }
    writer.sync().expect("a sync");

    let (file, offset) = writer.cursor();
    assert_eq!(file, 3, "fourteen records at four to a file");
    assert_eq!(offset, 2 * 1008);
    for (placed, _) in &written {
        assert!(
            placed.offset.saturating_add(placed.len) <= bound,
            "no record straddles the bound",
        );
    }
    assert!(blocks.join("tst00000.dat").is_file());
    assert!(blocks.join("tst00003.dat").is_file());
    for (placed, bytes) in written {
        let (back, _) = reader.read(placed.file, placed.offset, placed.len).unwrap();
        assert_eq!(back, bytes);
    }
}

#[test]
fn a_record_larger_than_the_file_bound_gets_a_file_of_its_own() {
    // Consensus permits an undo record of a quarter of a gigabyte, and aborting on a chain
    // the rules allow is not an option. An empty file takes any record.
    let bound = 4096;
    let (_directory, _blocks, mut writer, reader) = series(bound);
    let small = writer.append(&body(100, 1), None).expect("an append");
    let large = writer
        .append(&body(50_000, 2), None)
        .expect("an oversized append");
    let after = writer.append(&body(100, 3), None).expect("an append");
    writer.sync().expect("a sync");

    assert_eq!(small.file, 0);
    assert_eq!(large.file, 1, "the oversized record moved to a fresh file");
    assert_eq!(large.offset, 8, "and starts at the front of it");
    assert_eq!(after.file, 2, "the file it filled is left behind");
    for placed in [small, large, after] {
        assert!(reader.read(placed.file, placed.offset, placed.len).is_ok());
    }
}

#[test]
fn reopening_finds_the_cursor_at_the_end_of_the_highest_file() {
    let bound = 4096;
    let directory = DataDir::transient().expect("a test data directory");
    let blocks = directory.blocks();
    let mut written = Vec::new();
    {
        let (mut writer, _) =
            open_with_bound(&blocks, "tst", MAGIC, 0, 4 * 1024 * 1024, bound).unwrap();
        for index in 0..9u8 {
            let bytes = body(1000, index);
            written.push((writer.append(&bytes, None).unwrap(), bytes));
        }
        writer.sync().unwrap();
    }
    // The cursor is read off the directory rather than out of a file that would have to be
    // believed: a crash between the bytes and the index leaves dead space, never a lie.
    let (mut writer, reader) =
        open_with_bound(&blocks, "tst", MAGIC, 0, 4 * 1024 * 1024, bound).unwrap();
    assert_eq!(writer.cursor(), (2, 1008));
    let next = writer.append(&body(1000, 99), None).unwrap();
    assert_eq!(next.file, 2);
    writer.sync().unwrap();
    for (placed, bytes) in written {
        let (back, _) = reader.read(placed.file, placed.offset, placed.len).unwrap();
        assert_eq!(back, bytes);
    }
}

#[test]
fn a_location_that_names_the_wrong_place_is_refused() {
    let (_directory, _blocks, mut writer, reader) = series(MAX_FILE_BYTES);
    let placed = writer.append(&body(285, 4), None).expect("an append");
    writer.sync().expect("a sync");

    // The right place, so that the failures below are about the location and nothing else.
    assert!(reader.read(placed.file, placed.offset, placed.len).is_ok());
    // A body that starts inside its own frame is not a body.
    assert!(reader.read(placed.file, 4, placed.len).is_err());
    // A length the record does not agree with.
    assert!(reader.read(placed.file, placed.offset, 284).is_err());
    // A place the magic is not.
    assert!(
        reader
            .read(placed.file, placed.offset + 16, placed.len)
            .is_err()
    );
    // A length past the series' own bound, refused before a buffer is made for it.
    assert!(reader.read(placed.file, placed.offset, u32::MAX).is_err());
    // A file that is not there.
    assert!(reader.read(9, placed.offset, placed.len).is_err());
}

#[test]
fn the_undo_series_carries_its_trailer_through() {
    let directory = DataDir::transient().expect("a test data directory");
    let (mut writer, reader) =
        open(&directory.blocks(), "tsu", MAGIC, 32, 1024 * 1024).expect("an undo series");
    let trailer = [0x5au8; 32];
    let placed = writer
        .append(&body(64, 8), Some(trailer))
        .expect("an append");
    writer.sync().expect("a sync");
    let (body_back, trailer_back) = reader.read(placed.file, placed.offset, placed.len).unwrap();
    assert_eq!(body_back, body(64, 8));
    assert_eq!(
        trailer_back, trailer,
        "the checksum comes back with the body"
    );
}

#[test]
fn the_open_file_table_stays_at_its_bound() {
    // Mainnet is ~5,600 files and thirty-two peers serve blocks out of them; the table is
    // what keeps that a fixed number of descriptors.
    let bound = 1024;
    let (_directory, _blocks, mut writer, reader) = series(bound);
    let mut written = Vec::new();
    for index in 0..(MAX_OPEN_FILES + 20) {
        let bytes = body(600, u8::try_from(index % 251).unwrap_or(0));
        written.push((writer.append(&bytes, None).unwrap(), bytes));
    }
    writer.sync().unwrap();
    assert!(written.len() > MAX_OPEN_FILES, "more files than the table");
    for (placed, bytes) in &written {
        let (back, _) = reader.read(placed.file, placed.offset, placed.len).unwrap();
        assert_eq!(&back, bytes);
    }
    assert_eq!(reader.open_files(), MAX_OPEN_FILES);
    // And reading them again, in the other order, still holds at the bound.
    for (placed, _) in written.iter().rev() {
        assert!(reader.read(placed.file, placed.offset, placed.len).is_ok());
    }
    assert_eq!(reader.open_files(), MAX_OPEN_FILES);
}
