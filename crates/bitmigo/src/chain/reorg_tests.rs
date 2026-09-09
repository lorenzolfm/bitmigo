// SPDX-License-Identifier: MIT OR Apache-2.0

//! Reorg selection: the fork point, what comes off, what goes on, and where the plan stops.

use super::REORG_WARNING_DEPTH;
use crate::chain::fixture;
use crate::chain::tree::{HeaderTree, NodeId};
use crate::runtime::queue::JobKind;
use bitcoin::block::Header;
use bitmigo_consensus::params::{ChainParams, Height};

/// A tree, the chain's parameters, and the genesis header every fixture builds on.
fn tree() -> (HeaderTree, ChainParams, Header) {
    let params = fixture::params();
    let tree = HeaderTree::new(&params);
    let genesis = params.genesis().header;
    (tree, params, genesis)
}

#[test]
fn a_node_on_its_own_best_chain_has_nothing_to_do() {
    let (mut tree, params, genesis) = tree();
    let headers = fixture::chain(&genesis, 5, 1, &params);
    let nodes = fixture::accept_all(&mut tree, &headers, &params);
    fixture::connect_through(&mut tree, *nodes.last().expect("five"));

    let plan = tree.reorg(&params, 64);
    assert!(plan.is_empty());
    assert_eq!(plan.depth(), 0);
    assert_eq!(plan.fork(), tree.tip());
    assert_eq!(plan.missing(), None);
}

#[test]
fn a_sync_is_a_reorg_with_nothing_to_disconnect() {
    let (mut tree, params, genesis) = tree();
    let headers = fixture::chain(&genesis, 5, 1, &params);
    let nodes = fixture::accept_all(&mut tree, &headers, &params);
    for node in &nodes {
        fixture::check(&mut tree, *node);
    }

    let plan = tree.reorg(&params, 64);
    assert_eq!(plan.depth(), 0);
    assert_eq!(plan.fork(), NodeId::GENESIS);
    assert_eq!(plan.jobs().len(), 5);
    for (step, job) in plan.jobs().iter().enumerate() {
        let height = u32::try_from(step).expect("bounded") + 1;
        assert_eq!(job.kind, JobKind::Connect);
        assert_eq!(job.height(), Height::new(height));
        // The context travels with the job, so the validation thread needs no lock on this
        // tree to know what rules the block is judged under (BM-D5 decision 5).
        assert_eq!(job.context.height(), Height::new(height));
    }
}

#[test]
fn the_plan_stops_where_the_downloaded_blocks_do() {
    let (mut tree, params, genesis) = tree();
    let headers = fixture::chain(&genesis, 8, 1, &params);
    let nodes = fixture::accept_all(&mut tree, &headers, &params);
    for node in nodes.iter().take(3) {
        fixture::check(&mut tree, *node);
    }

    let plan = tree.reorg(&params, 64);
    assert_eq!(plan.jobs().len(), 3);
    // The connectable prefix ends at the fourth block, which is the download schedule's cue.
    assert_eq!(
        plan.missing(),
        Some(tree.entry(*nodes.get(3).expect("eight")).hash())
    );
}

#[test]
fn the_plan_never_exceeds_the_room_it_was_given() {
    let (mut tree, params, genesis) = tree();
    let headers = fixture::chain(&genesis, 100, 1, &params);
    let nodes = fixture::accept_all(&mut tree, &headers, &params);
    for node in &nodes {
        fixture::check(&mut tree, *node);
    }

    // A reorg of any depth is worked through a batch at a time, so the chain thread never
    // builds a list it cannot hand over.
    let plan = tree.reorg(&params, 7);
    assert_eq!(plan.jobs().len(), 7);
    assert_eq!(
        plan.missing(),
        None,
        "it stopped on room, not on a missing block"
    );
}

#[test]
fn a_fork_with_more_work_takes_the_active_chain_off_down_to_the_fork_point() {
    let (mut tree, params, genesis) = tree();
    let trunk = fixture::chain(&genesis, 5, 1, &params);
    let trunk_nodes = fixture::accept_all(&mut tree, &trunk, &params);
    fixture::connect_through(&mut tree, *trunk_nodes.last().expect("five"));

    // A branch off block two that reaches height seven: two blocks come off, five go on.
    let fork_at = *trunk.get(1).expect("five");
    let branch = fixture::chain(&fork_at, 5, 2, &params);
    let branch_nodes = fixture::accept_all(&mut tree, &branch, &params);
    for node in &branch_nodes {
        fixture::check(&mut tree, *node);
    }

    let plan = tree.reorg(&params, 64);
    assert_eq!(tree.entry(plan.fork()).height(), Height::new(2));
    assert_eq!(plan.depth(), 3);
    assert_eq!(plan.jobs().len(), 8);

    // Disconnects first, tip downward, so the chainstate is only ever one block from a
    // state it could stop at.
    let heights: Vec<(JobKind, u32)> = plan
        .jobs()
        .iter()
        .map(|job| (job.kind, job.height().get()))
        .collect();
    assert_eq!(
        heights,
        vec![
            (JobKind::Disconnect, 5),
            (JobKind::Disconnect, 4),
            (JobKind::Disconnect, 3),
            (JobKind::Connect, 3),
            (JobKind::Connect, 4),
            (JobKind::Connect, 5),
            (JobKind::Connect, 6),
            (JobKind::Connect, 7),
        ],
    );
    // Every disconnect names bytes that are still on the disk: the store never deletes.
    for job in plan.jobs().iter().take(3) {
        assert_eq!(job.location.len, fixture::location(job.height().get()).len);
    }
}

#[test]
fn a_deep_reorg_is_followed_and_the_operator_is_told() {
    let (mut tree, params, genesis) = tree();
    let trunk = fixture::chain(&genesis, 9, 1, &params);
    let trunk_nodes = fixture::accept_all(&mut tree, &trunk, &params);
    fixture::connect_through(&mut tree, *trunk_nodes.last().expect("nine"));

    // BM-D1 decision 4: most work wins, with no refusal depth — a cap would be a consensus
    // rule Core does not have. Six blocks or more is news, not a veto.
    let branch = fixture::chain(&genesis, 12, 2, &params);
    let branch_nodes = fixture::accept_all(&mut tree, &branch, &params);
    for node in &branch_nodes {
        fixture::check(&mut tree, *node);
    }

    let plan = tree.reorg(&params, 64);
    assert_eq!(plan.fork(), NodeId::GENESIS);
    assert_eq!(plan.depth(), 9);
    assert!(plan.is_deep());
    assert!(plan.depth() >= REORG_WARNING_DEPTH);
    assert_eq!(plan.jobs().len(), 21);
}

#[test]
fn a_shallow_reorg_is_not_worth_an_operators_attention() {
    let (mut tree, params, genesis) = tree();
    let trunk = fixture::chain(&genesis, 4, 1, &params);
    let trunk_nodes = fixture::accept_all(&mut tree, &trunk, &params);
    fixture::connect_through(&mut tree, *trunk_nodes.last().expect("four"));

    let fork_at = *trunk.get(2).expect("four");
    let branch = fixture::chain(&fork_at, 3, 2, &params);
    let branch_nodes = fixture::accept_all(&mut tree, &branch, &params);
    for node in &branch_nodes {
        fixture::check(&mut tree, *node);
    }

    let plan = tree.reorg(&params, 64);
    assert_eq!(plan.depth(), 1);
    assert!(!plan.is_deep());
}

#[test]
fn the_disconnects_alone_can_fill_a_batch() {
    let (mut tree, params, genesis) = tree();
    let trunk = fixture::chain(&genesis, 10, 1, &params);
    let trunk_nodes = fixture::accept_all(&mut tree, &trunk, &params);
    fixture::connect_through(&mut tree, *trunk_nodes.last().expect("ten"));

    let branch = fixture::chain(&genesis, 12, 2, &params);
    let branch_nodes = fixture::accept_all(&mut tree, &branch, &params);
    for node in &branch_nodes {
        fixture::check(&mut tree, *node);
    }

    let plan = tree.reorg(&params, 4);
    assert_eq!(plan.jobs().len(), 4);
    assert!(
        plan.jobs()
            .iter()
            .all(|job| job.kind == JobKind::Disconnect)
    );
    // The depth is the whole reorg's, not this batch's: an operator hears about the reorg
    // that is happening, not about the four blocks that happen to fit.
    assert_eq!(plan.depth(), 10);
    assert!(plan.is_deep());
}

#[test]
fn a_branch_whose_blocks_have_not_arrived_leaves_the_active_chain_alone() {
    let (mut tree, params, genesis) = tree();
    let trunk = fixture::chain(&genesis, 5, 1, &params);
    let trunk_nodes = fixture::accept_all(&mut tree, &trunk, &params);
    fixture::connect_through(&mut tree, *trunk_nodes.last().expect("five"));

    // Headers with more work, and not one of their blocks here yet. A node that started
    // disconnecting on the strength of headers alone would take itself off a chain it can
    // reach and onto one it cannot.
    let branch = fixture::chain(&genesis, 9, 2, &params);
    let branch_nodes = fixture::accept_all(&mut tree, &branch, &params);

    let plan = tree.reorg(&params, 64);
    assert_eq!(plan.depth(), 5);
    assert_eq!(plan.jobs().len(), 5);
    assert!(
        plan.jobs()
            .iter()
            .all(|job| job.kind == JobKind::Disconnect)
    );
    assert_eq!(
        plan.missing(),
        Some(tree.entry(*branch_nodes.first().expect("nine")).hash())
    );
}
