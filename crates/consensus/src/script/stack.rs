// SPDX-License-Identifier: MIT OR Apache-2.0

//! [`Stack`]: the interpreter's data stack, with Core's access patterns as methods.
//!
//! Core addresses the stack through `stacktop(-n)`, `popstack`, `swap`, `erase` and
//! `insert`, each an index computed at the call site. Here every one of those is a method
//! that takes Core's depth (`top(1)` is `stacktop(-1)`) and asserts it, so the opcode code
//! does no index arithmetic of its own and a wrong depth is a panic in the method, not a
//! silent read of the wrong element. Items are owned bytes; the 520-byte element limit is
//! asserted on every push, because Core has already rejected a larger push (`PUSH_SIZE`) or
//! witness item before anything reaches the stack, and no opcode can build a larger result.
//! The combined 1,000-element limit is the interpreter's to check after every opcode, so it
//! is a query here, not an assertion.

use super::ScriptError;

/// `MAX_SCRIPT_ELEMENT_SIZE`: the largest stack element, and the largest push.
pub const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;

/// A stack of byte strings, `Vec<Vec<u8>>` behind bounds-checked methods.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Stack {
    items: Vec<Vec<u8>>,
}

impl Stack {
    /// An empty stack.
    #[must_use]
    pub const fn new() -> Stack {
        Stack { items: Vec::new() }
    }

    /// A stack holding `items` bottom to top. Every item must already be within the element
    /// limit; the witness path checks that and reports `PUSH_SIZE` before building one.
    #[must_use]
    pub fn from_items(items: Vec<Vec<u8>>) -> Stack {
        for item in &items {
            assert!(item.len() <= MAX_SCRIPT_ELEMENT_SIZE);
        }
        Stack { items }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// The items, bottom to top.
    #[cfg(test)]
    pub fn items(&self) -> &[Vec<u8>] {
        &self.items
    }

    /// Core's `if (stack.size() < n) return set_error(SCRIPT_ERR_INVALID_STACK_OPERATION)`.
    pub fn require(&self, count: usize) -> Result<(), ScriptError> {
        if self.items.len() < count {
            return Err(ScriptError::InvalidStackOperation);
        }
        Ok(())
    }

    /// Pushes an item within the element limit.
    pub fn push(&mut self, item: Vec<u8>) {
        assert!(item.len() <= MAX_SCRIPT_ELEMENT_SIZE);
        self.items.push(item);
    }

    /// Pushes Core's `vchTrue` (`[0x01]`) or `vchFalse` (empty).
    pub fn push_bool(&mut self, value: bool) {
        self.push(if value { vec![1] } else { Vec::new() });
    }

    /// Core's `popstack`: the caller has checked the depth.
    pub fn pop(&mut self) -> Vec<u8> {
        self.items
            .pop()
            .expect("the caller checked the stack depth")
    }

    /// Core's `stacktop(-depth)`: `top(1)` is the top item.
    #[must_use]
    pub fn top(&self, depth: usize) -> &[u8] {
        let index = self.index_at_depth(depth);
        self.items.get(index).expect("depth is within the stack")
    }

    /// Swaps `stacktop(-a)` and `stacktop(-b)`.
    pub fn swap(&mut self, a: usize, b: usize) {
        let index_a = self.index_at_depth(a);
        let index_b = self.index_at_depth(b);
        self.items.swap(index_a, index_b);
    }

    /// Core's `stack.erase(stack.end() - depth)`: removes and returns `stacktop(-depth)`.
    pub fn remove(&mut self, depth: usize) -> Vec<u8> {
        let index = self.index_at_depth(depth);
        self.items.remove(index)
    }

    /// Core's `stack.insert(stack.end() - depth, item)`: afterwards `item` is
    /// `stacktop(-(depth + 1))`.
    pub fn insert(&mut self, depth: usize, item: Vec<u8>) {
        assert!(item.len() <= MAX_SCRIPT_ELEMENT_SIZE);
        let index = self.index_at_depth(depth);
        self.items.insert(index, item);
    }

    fn index_at_depth(&self, depth: usize) -> usize {
        assert!(depth >= 1);
        assert!(depth <= self.items.len());
        self.items.len() - depth
    }
}

#[cfg(test)]
mod tests {
    use super::super::ScriptError;
    use super::{MAX_SCRIPT_ELEMENT_SIZE, Stack};

    fn stack_of(items: &[u8]) -> Stack {
        Stack::from_items(items.iter().map(|byte| vec![*byte]).collect())
    }

    #[test]
    fn depth_addresses_from_the_top() {
        let stack = stack_of(&[1, 2, 3]);
        assert_eq!(stack.top(1), &[3]);
        assert_eq!(stack.top(3), &[1]);
        assert_eq!(stack.require(3), Ok(()));
        assert_eq!(stack.require(4), Err(ScriptError::InvalidStackOperation));
        assert_eq!(Stack::new().require(0), Ok(()));
    }

    #[test]
    fn swap_remove_insert_follow_core() {
        let mut stack = stack_of(&[1, 2, 3, 4]);
        // OP_2SWAP: (x1 x2 x3 x4 -- x3 x4 x1 x2)
        stack.swap(4, 2);
        stack.swap(3, 1);
        assert_eq!(stack.items(), &[vec![3], vec![4], vec![1], vec![2]]);
        // OP_NIP: (x1 x2 -- x2)
        assert_eq!(stack.remove(2), vec![1]);
        assert_eq!(stack.items(), &[vec![3], vec![4], vec![2]]);
        // OP_TUCK: (x1 x2 -- x2 x1 x2)
        let top = stack.top(1).to_vec();
        stack.insert(2, top);
        assert_eq!(stack.items(), &[vec![3], vec![2], vec![4], vec![2]]);
        assert_eq!(stack.pop(), vec![2]);
        assert_eq!(stack.len(), 3);
    }

    #[test]
    fn push_bool_uses_core_s_encodings() {
        let mut stack = Stack::new();
        stack.push_bool(true);
        stack.push_bool(false);
        assert_eq!(stack.items(), &[vec![1], vec![]]);
    }

    #[test]
    fn largest_element_is_accepted() {
        let mut stack = Stack::new();
        stack.push(vec![0; MAX_SCRIPT_ELEMENT_SIZE]);
        assert_eq!(stack.len(), 1);
    }

    #[test]
    #[should_panic(expected = "MAX_SCRIPT_ELEMENT_SIZE")]
    fn oversized_element_is_a_programmer_error() {
        Stack::new().push(vec![0; MAX_SCRIPT_ELEMENT_SIZE + 1]);
    }

    #[test]
    #[should_panic(expected = "depth <= self.items.len()")]
    fn depth_past_the_bottom_is_a_programmer_error() {
        let stack = stack_of(&[1]);
        let _below_the_bottom = stack.top(2);
    }
}
