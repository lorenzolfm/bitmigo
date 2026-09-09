// SPDX-License-Identifier: MIT OR Apache-2.0

//! One peer's outbound queue: a megabyte of framed messages, and a disconnect when it fills.
//!
//! This is the writer thread's only blocking point, and the one queue in the node that is
//! bounded by *dropping the peer* rather than by making the producer wait. The reason is
//! the invariant the whole runtime is built on: the only thread allowed to block on a full
//! queue is a peer reader. Everything that queues an outbound message — the chain thread
//! answering a `getdata`, a reader answering a `ping` — is the sole consumer of something
//! else, and a sole consumer that waits here stops draining what it alone drains.
//!
//! Core's `DEFAULT_MAXSENDBUFFER` is the same megabyte, and Core pauses the sender. This
//! node disconnects, because everything in here is a reply nobody is waiting on: a peer
//! that will not read what it asked for has already told us what it is worth.

use std::collections::VecDeque;
use std::sync::{Condvar, Mutex};
use std::time::Duration;

use crate::runtime::sync::{lock, wait};

/// The queue was full, or the connection is over. Either way the caller's message is gone
/// and the connection is finished.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutboxFull;

struct Queued {
    frames: VecDeque<Vec<u8>>,
    bytes: usize,
    closed: bool,
}

/// Framed messages waiting for one peer's writer thread.
pub struct Outbox {
    queued: Mutex<Queued>,
    has_frames: Condvar,
    max_bytes: usize,
}

impl Outbox {
    /// An empty outbox at a stated bound.
    pub fn with_bound(max_bytes: usize) -> Outbox {
        assert!(max_bytes > 0);
        Outbox {
            queued: Mutex::new(Queued {
                frames: VecDeque::new(),
                bytes: 0,
                closed: false,
            }),
            has_frames: Condvar::new(),
            max_bytes,
        }
    }

    /// Queue one framed message, or say the connection is over.
    ///
    /// Never blocks, and never grows past the bound: those are the same property. A frame
    /// larger than the whole outbox is this node's own bug rather than a peer's, so it is
    /// an assertion — nothing it sends is anywhere near a megabyte except a block, and a
    /// block is written from the disk rather than queued.
    pub fn push(&self, frame: Vec<u8>) -> Result<(), OutboxFull> {
        assert!(!frame.is_empty(), "an empty frame is not a message");
        assert!(
            frame.len() <= self.max_bytes,
            "a frame larger than the outbox could never be sent",
        );
        let mut queued = lock(&self.queued);
        if queued.closed {
            return Err(OutboxFull);
        }
        let after = queued.bytes.saturating_add(frame.len());
        if after > self.max_bytes {
            // Closed here, not merely refused: the peer is going, and anything queued
            // behind this frame would be written to a connection that is about to end.
            queued.closed = true;
            drop(queued);
            self.has_frames.notify_all();
            return Err(OutboxFull);
        }
        queued.bytes = after;
        queued.frames.push_back(frame);
        drop(queued);
        self.has_frames.notify_one();
        Ok(())
    }

    /// Take the next frame, waiting up to `timeout` for one. `None` means either nothing
    /// arrived in time or the outbox is closed; [`Outbox::is_closed`] separates them.
    pub fn pop(&self, timeout: Duration) -> Option<Vec<u8>> {
        let mut queued = lock(&self.queued);
        if queued.frames.is_empty() && !queued.closed {
            queued = wait(&self.has_frames, queued, timeout);
        }
        let frame = queued.frames.pop_front()?;
        queued.bytes = queued.bytes.saturating_sub(frame.len());
        Some(frame)
    }

    /// End the outbox: the connection is over, and nothing further will be written.
    pub fn close(&self) {
        lock(&self.queued).closed = true;
        self.has_frames.notify_all();
    }

    /// Whether the outbox has been closed, by a full queue or by the connection ending.
    pub fn is_closed(&self) -> bool {
        lock(&self.queued).closed
    }

    /// Bytes waiting to be written. The number an operator would want when a peer is
    /// being slow, and what the status snapshot will carry once there is anything to send.
    #[allow(
        dead_code,
        reason = "the send-side flow control that reports it is BM-24's"
    )]
    pub fn bytes(&self) -> usize {
        lock(&self.queued).bytes
    }

    /// Frames waiting to be written.
    #[allow(
        dead_code,
        reason = "the send-side flow control that reports it is BM-24's"
    )]
    pub fn len(&self) -> usize {
        lock(&self.queued).frames.len()
    }
}

#[cfg(test)]
#[path = "outbox_tests.rs"]
mod tests;
