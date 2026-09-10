// SPDX-License-Identifier: MIT OR Apache-2.0

//! The varint, and a reader that cannot be talked past the end of its slice.

use super::{DecodeError, Reader, put_varint};

/// One round trip.
fn round_trip(value: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    put_varint(&mut bytes, value);
    let mut reader = Reader::new(&bytes);
    assert_eq!(reader.varint(), Ok(value), "{value} did not survive");
    reader.finish().expect("nothing follows one varint");
    bytes
}

#[test]
fn cores_varint_encodes_what_core_documents() {
    // `serialize.h`: 0 through 127 in one byte, then the "minus one per continuation"
    // offset, which is what makes 128 two bytes rather than three.
    assert_eq!(round_trip(0), vec![0x00]);
    assert_eq!(round_trip(1), vec![0x01]);
    assert_eq!(round_trip(127), vec![0x7f]);
    assert_eq!(round_trip(128), vec![0x80, 0x00]);
    assert_eq!(round_trip(255), vec![0x80, 0x7f]);
    assert_eq!(round_trip(256), vec![0x81, 0x00]);
    assert_eq!(round_trip(16_511), vec![0xff, 0x7f]);
    assert_eq!(round_trip(16_512), vec![0x80, 0x80, 0x00]);
    assert_eq!(round_trip(65_535), vec![0x82, 0xfe, 0x7f]);
}

#[test]
fn every_power_of_two_and_its_neighbours_survive() {
    for shift in 0..64 {
        let value = 1u64 << shift;
        round_trip(value);
        round_trip(value.saturating_sub(1));
        round_trip(value.saturating_add(1));
    }
    round_trip(u64::MAX);
}

#[test]
fn a_varint_that_runs_past_a_u64_is_refused_rather_than_wrapped() {
    // Eleven continuation bytes is not a number this encoder ever wrote, and the loop that
    // reads one has to end whatever the bytes say.
    let bytes = [0xffu8; 12];
    assert_eq!(Reader::new(&bytes).varint(), Err(DecodeError::BadVarint));
    // And the one that ends exactly at the top.
    let bytes = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
    assert_eq!(Reader::new(&bytes).varint(), Err(DecodeError::BadVarint));
}

#[test]
fn a_truncated_varint_is_an_error_and_not_a_value() {
    let bytes = [0x80u8, 0x80];
    assert!(matches!(
        Reader::new(&bytes).varint(),
        Err(DecodeError::Truncated { .. })
    ));
}

#[test]
fn a_count_is_refused_before_anything_is_reserved_for_it() {
    let mut bytes = Vec::new();
    put_varint(&mut bytes, 1_000_000);
    let refused = Reader::new(&bytes).count(1_000);
    assert_eq!(
        refused,
        Err(DecodeError::TooLong {
            declared: 1_000_000,
            limit: 1_000,
        }),
    );

    let mut bytes = Vec::new();
    put_varint(&mut bytes, 999);
    assert_eq!(Reader::new(&bytes).count(1_000), Ok(999));
}

#[test]
fn nothing_reads_past_the_slice() {
    let bytes = [1u8, 2, 3, 4, 5];
    let mut reader = Reader::new(&bytes);
    assert_eq!(reader.take(4).map(<[u8]>::to_vec), Ok(vec![1, 2, 3, 4]));
    assert_eq!(
        reader.take(4),
        Err(DecodeError::Truncated { wanted: 4, left: 1 }),
    );
    assert_eq!(
        reader.u32_le(),
        Err(DecodeError::Truncated { wanted: 4, left: 1 })
    );
    assert!(matches!(reader.hash(), Err(DecodeError::Truncated { .. })));
    assert_eq!(reader.u8(), Ok(5));
    reader.finish().expect("the slice is spent");
}

#[test]
fn a_record_with_bytes_after_it_is_refused() {
    let bytes = [0u8; 4];
    let mut reader = Reader::new(&bytes);
    assert_eq!(reader.u8(), Ok(0));
    assert_eq!(reader.finish(), Err(DecodeError::Trailing { left: 3 }));
}
