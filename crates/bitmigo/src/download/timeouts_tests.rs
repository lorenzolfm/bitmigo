// SPDX-License-Identifier: MIT OR Apache-2.0

//! The two clocks, at their bounds.

use std::time::Duration;

use super::{STALLING_TIMEOUT_DEFAULT, STALLING_TIMEOUT_MAX, StallTimeout, download_timeout};

/// Regtest's and mainnet's target spacing alike.
const SPACING: Duration = Duration::from_mins(10);

#[test]
fn the_stalling_window_starts_at_two_seconds() {
    assert_eq!(StallTimeout::new().get(), Duration::from_secs(2));
    assert_eq!(STALLING_TIMEOUT_DEFAULT, Duration::from_secs(2));
}

#[test]
fn the_stalling_window_doubles_to_sixty_four_seconds_and_stops() {
    let mut timeout = StallTimeout::new();
    for expected in [4, 8, 16, 32, 64] {
        timeout.doubled();
        assert_eq!(timeout.get(), Duration::from_secs(expected));
    }
    // The cap is the point: a node whose own link is the bottleneck must stop punishing
    // peers for it rather than wait longer and longer forever.
    for _ in 0..8 {
        timeout.doubled();
        assert_eq!(timeout.get(), STALLING_TIMEOUT_MAX);
    }
}

#[test]
fn the_stalling_window_decays_by_fifteen_hundredths_back_to_its_default() {
    let mut timeout = StallTimeout::new();
    for _ in 0..5 {
        timeout.doubled();
    }
    assert_eq!(timeout.get(), STALLING_TIMEOUT_MAX);

    timeout.decay();
    assert_eq!(timeout.get(), Duration::from_millis(64_000 * 85 / 100));
    timeout.decay();
    assert_eq!(timeout.get(), Duration::from_millis(54_400 * 85 / 100));

    // Twenty-two blocks take it from the ceiling back to the floor, and no further.
    for _ in 0..64 {
        timeout.decay();
    }
    assert_eq!(timeout.get(), STALLING_TIMEOUT_DEFAULT);
}

#[test]
fn a_peer_alone_gets_one_target_spacing_to_answer() {
    assert_eq!(download_timeout(SPACING, 0), SPACING);
}

#[test]
fn every_other_peer_downloading_buys_half_a_spacing_more() {
    // Core's `BLOCK_DOWNLOAD_TIMEOUT_BASE + BLOCK_DOWNLOAD_TIMEOUT_PER_PEER * n`, and the
    // reason it grows: thirty-two peers sharing one link are each entitled to less of it.
    assert_eq!(download_timeout(SPACING, 1), Duration::from_mins(15));
    assert_eq!(download_timeout(SPACING, 2), Duration::from_mins(20));
    assert_eq!(download_timeout(SPACING, 31), SPACING + SPACING * 31 / 2);
}

#[test]
fn a_faster_chain_gets_a_proportionally_shorter_timeout() {
    let fast = Duration::from_secs(60);
    assert_eq!(download_timeout(fast, 0), fast);
    assert_eq!(download_timeout(fast, 4), Duration::from_secs(180));
}
