use core::poseidon::poseidon_hash_span;
use zkapi_cairo::constants::{MERKLE_DEPTH, XMSS_TREE_HEIGHT};
use zkapi_cairo::domains::{
    DOMAIN_CLEAR, DOMAIN_LEAF, DOMAIN_NODE, DOMAIN_REG, DOMAIN_STATE, DOMAIN_XMSS_MSG,
    DOMAIN_XMSS_NODE,
};
use zkapi_cairo::pedersen_balance::compute_commitment;
use zkapi_cairo::request::program::run_request_program;
use zkapi_cairo::withdrawal::program::run_withdrawal_program;
use zkapi_cairo::xmss::wots::{wots_pk_to_leaf, wots_verify};

fn zero_path_for_leaf(leaf: felt252) -> (Array<felt252>, Array<felt252>, felt252) {
    let mut index_bits = array![];
    let mut siblings = array![];
    let mut zero = 0;
    let mut current = leaf;
    let mut i: u32 = 0;
    while i < MERKLE_DEPTH {
        index_bits.append(0);
        siblings.append(zero);
        current = poseidon_hash_span(array![DOMAIN_NODE, current, zero].span());
        zero = poseidon_hash_span(array![DOMAIN_NODE, zero, zero].span());
        i += 1;
    }
    (index_bits, siblings, current)
}

fn fake_wots_sig(offset: felt252) -> Array<felt252> {
    let mut sig = array![];
    let mut i: u32 = 0;
    while i < 65 {
        let value: felt252 = (i + 1).into();
        sig.append(value + offset);
        i += 1;
    }
    sig
}

fn zero_xmss_auth_path() -> Array<felt252> {
    let mut auth_path = array![];
    let mut i: u32 = 0;
    while i < XMSS_TREE_HEIGHT {
        auth_path.append(0);
        i += 1;
    }
    auth_path
}

fn xmss_root_for_fixture(
    message: felt252, leaf_index: u32, wots_sig: Span<felt252>, auth_path: Span<felt252>,
) -> felt252 {
    let digest = poseidon_hash_span(array![DOMAIN_XMSS_MSG, message].span());
    let pk_values = wots_verify(wots_sig, digest);
    let mut current = wots_pk_to_leaf(pk_values.span());
    let mut idx = leaf_index;
    let mut i: u32 = 0;
    while i < XMSS_TREE_HEIGHT {
        let sibling = *auth_path.at(i);
        if idx % 2 == 0 {
            current = poseidon_hash_span(array![DOMAIN_XMSS_NODE, current, sibling].span());
        } else {
            current = poseidon_hash_span(array![DOMAIN_XMSS_NODE, sibling, current].span());
        }
        idx = idx / 2;
        i += 1;
    }
    current
}

fn read_felt(args: Span<felt252>, index: u32) -> felt252 {
    *args.at(index)
}

fn read_u32(args: Span<felt252>, index: u32) -> u32 {
    read_felt(args, index).try_into().expect('arg must fit u32')
}

fn copy_felts(args: Span<felt252>, start: u32, len: u32) -> Array<felt252> {
    let mut out = array![];
    let mut i: u32 = 0;
    while i < len {
        out.append(read_felt(args, start + i));
        i += 1;
    }
    out
}

#[executable]
pub fn request_from_args(args: Array<felt252>) -> Array<felt252> {
    let args_span = args.span();
    assert(args_span.len() == 167, 'bad request arg count');
    let merkle_index_bits = copy_felts(args_span, 9, MERKLE_DEPTH);
    let merkle_siblings = copy_felts(args_span, 9 + MERKLE_DEPTH, MERKLE_DEPTH);
    let wots_start = 81;
    let auth_len_index = wots_start + 65;
    let auth_start = auth_len_index + 1;
    let auth_len = read_u32(args_span, auth_len_index);
    assert(auth_len <= XMSS_TREE_HEIGHT, 'auth path too long');
    let wots_sig = copy_felts(args_span, wots_start, 65);
    let auth_path = copy_felts(args_span, auth_start, auth_len);

    run_request_program(
        read_felt(args_span, 0),
        read_felt(args_span, 1),
        read_felt(args_span, 2),
        read_felt(args_span, 3),
        read_felt(args_span, 4),
        read_felt(args_span, 5),
        read_felt(args_span, 6),
        read_felt(args_span, 7),
        read_felt(args_span, 8),
        merkle_index_bits.span(),
        merkle_siblings.span(),
        read_felt(args_span, 73),
        read_felt(args_span, 74),
        read_felt(args_span, 75),
        read_felt(args_span, 76),
        read_felt(args_span, 77),
        read_felt(args_span, 78),
        read_u32(args_span, 79),
        read_u32(args_span, 80),
        wots_sig.span(),
        auth_path.span(),
    )
}

#[executable]
pub fn withdrawal_from_args(args: Array<felt252>) -> Array<felt252> {
    let args_span = args.span();
    assert(args_span.len() == 256, 'bad withdrawal arg count');
    let merkle_index_bits = copy_felts(args_span, 9, MERKLE_DEPTH);
    let merkle_siblings = copy_felts(args_span, 9 + MERKLE_DEPTH, MERKLE_DEPTH);
    let state_wots_start = 80;
    let state_auth_len_index = state_wots_start + 65;
    let state_auth_start = state_auth_len_index + 1;
    let clear_wots_start = 170;
    let clear_auth_len_index = clear_wots_start + 65;
    let clear_auth_start = clear_auth_len_index + 1;
    let state_auth_len = read_u32(args_span, state_auth_len_index);
    let clear_auth_len = read_u32(args_span, clear_auth_len_index);
    assert(state_auth_len <= XMSS_TREE_HEIGHT, 'state path too long');
    assert(clear_auth_len <= XMSS_TREE_HEIGHT, 'clear path too long');
    let state_wots_sig = copy_felts(args_span, state_wots_start, 65);
    let state_auth_path = copy_felts(args_span, state_auth_start, state_auth_len);
    let clear_wots_sig = copy_felts(args_span, clear_wots_start, 65);
    let clear_auth_path = copy_felts(args_span, clear_auth_start, clear_auth_len);

    run_withdrawal_program(
        read_felt(args_span, 0),
        read_felt(args_span, 1),
        read_felt(args_span, 2),
        read_felt(args_span, 3),
        read_felt(args_span, 4),
        read_felt(args_span, 5),
        read_felt(args_span, 6),
        read_felt(args_span, 7),
        read_felt(args_span, 8),
        merkle_index_bits.span(),
        merkle_siblings.span(),
        read_felt(args_span, 73),
        read_felt(args_span, 74),
        read_felt(args_span, 75),
        read_felt(args_span, 76),
        read_felt(args_span, 77),
        read_u32(args_span, 78),
        read_u32(args_span, 79),
        state_wots_sig.span(),
        state_auth_path.span(),
        read_felt(args_span, 166),
        read_felt(args_span, 167),
        read_u32(args_span, 168),
        read_u32(args_span, 169),
        clear_wots_sig.span(),
        clear_auth_path.span(),
    )
}

#[executable]
pub fn request_genesis() -> Array<felt252> {
    let secret_s = 42;
    let note_id = 0;
    let deposit_amount = 1000;
    let expiry_ts = 1700000000;
    let commitment = poseidon_hash_span(array![DOMAIN_REG, secret_s, 0].span());
    let leaf = poseidon_hash_span(
        array![DOMAIN_LEAF, note_id, commitment, deposit_amount, expiry_ts].span(),
    );
    let (index_bits, siblings, active_root) = zero_path_for_leaf(leaf);

    run_request_program(
        1,
        1,
        0xdead,
        active_root,
        100,
        secret_s,
        note_id,
        deposit_amount,
        expiry_ts,
        index_bits.span(),
        siblings.span(),
        deposit_amount,
        0,
        7,
        1,
        1,
        0,
        0,
        0,
        array![].span(),
        array![].span(),
    )
}

#[executable]
pub fn request_non_genesis() -> Array<felt252> {
    let secret_s = 42;
    let note_id = 0;
    let deposit_amount = 1000;
    let expiry_ts = 1700000000;
    let current_balance = 900;
    let current_blinding = 13;
    let current_anchor = 77;
    let user_rerandomization = 7;
    let commitment = poseidon_hash_span(array![DOMAIN_REG, secret_s, 0].span());
    let leaf = poseidon_hash_span(
        array![DOMAIN_LEAF, note_id, commitment, deposit_amount, expiry_ts].span(),
    );
    let (index_bits, siblings, active_root) = zero_path_for_leaf(leaf);
    let (e_x, e_y) = compute_commitment(current_balance, current_blinding);
    let state_msg = poseidon_hash_span(
        array![DOMAIN_STATE, 1, 1, 0xdead, e_x, e_y, current_anchor].span(),
    );
    let state_wots_sig = fake_wots_sig(10);
    let state_auth_path = zero_xmss_auth_path();
    let state_sig_root = xmss_root_for_fixture(
        state_msg, 0, state_wots_sig.span(), state_auth_path.span(),
    );

    run_request_program(
        1,
        1,
        0xdead,
        active_root,
        100,
        secret_s,
        note_id,
        deposit_amount,
        expiry_ts,
        index_bits.span(),
        siblings.span(),
        current_balance,
        current_blinding,
        user_rerandomization,
        current_anchor,
        0,
        state_sig_root,
        1,
        0,
        state_wots_sig.span(),
        state_auth_path.span(),
    )
}

#[executable]
pub fn withdrawal_genesis_escape() -> Array<felt252> {
    let secret_s = 42;
    let note_id = 0;
    let deposit_amount = 1000;
    let expiry_ts = 1700000000;
    let commitment = poseidon_hash_span(array![DOMAIN_REG, secret_s, 0].span());
    let leaf = poseidon_hash_span(
        array![DOMAIN_LEAF, note_id, commitment, deposit_amount, expiry_ts].span(),
    );
    let (index_bits, siblings, active_root) = zero_path_for_leaf(leaf);

    run_withdrawal_program(
        1,
        1,
        0xdead,
        active_root,
        0x1234,
        secret_s,
        note_id,
        deposit_amount,
        expiry_ts,
        index_bits.span(),
        siblings.span(),
        deposit_amount,
        0,
        1,
        1,
        0,
        0,
        0,
        array![].span(),
        array![].span(),
        0,
        0,
        0,
        0,
        array![].span(),
        array![].span(),
    )
}

#[executable]
pub fn withdrawal_non_genesis_escape() -> Array<felt252> {
    let secret_s = 42;
    let note_id = 0;
    let deposit_amount = 1000;
    let expiry_ts = 1700000000;
    let final_balance = 750;
    let final_blinding = 21;
    let current_anchor = 88;
    let commitment = poseidon_hash_span(array![DOMAIN_REG, secret_s, 0].span());
    let leaf = poseidon_hash_span(
        array![DOMAIN_LEAF, note_id, commitment, deposit_amount, expiry_ts].span(),
    );
    let (index_bits, siblings, active_root) = zero_path_for_leaf(leaf);
    let (e_x, e_y) = compute_commitment(final_balance, final_blinding);
    let state_msg = poseidon_hash_span(
        array![DOMAIN_STATE, 1, 1, 0xdead, e_x, e_y, current_anchor].span(),
    );
    let state_wots_sig = fake_wots_sig(20);
    let state_auth_path = zero_xmss_auth_path();
    let state_sig_root = xmss_root_for_fixture(
        state_msg, 0, state_wots_sig.span(), state_auth_path.span(),
    );

    run_withdrawal_program(
        1,
        1,
        0xdead,
        active_root,
        0x1234,
        secret_s,
        note_id,
        deposit_amount,
        expiry_ts,
        index_bits.span(),
        siblings.span(),
        final_balance,
        final_blinding,
        current_anchor,
        0,
        state_sig_root,
        1,
        0,
        state_wots_sig.span(),
        state_auth_path.span(),
        0,
        0,
        0,
        0,
        array![].span(),
        array![].span(),
    )
}

#[executable]
pub fn withdrawal_mutual_close() -> Array<felt252> {
    let secret_s = 42;
    let note_id = 0;
    let deposit_amount = 1000;
    let expiry_ts = 1700000000;
    let final_balance = 750;
    let final_blinding = 21;
    let current_anchor = 88;
    let destination = 0x1234;
    let commitment = poseidon_hash_span(array![DOMAIN_REG, secret_s, 0].span());
    let leaf = poseidon_hash_span(
        array![DOMAIN_LEAF, note_id, commitment, deposit_amount, expiry_ts].span(),
    );
    let (index_bits, siblings, active_root) = zero_path_for_leaf(leaf);
    let (e_x, e_y) = compute_commitment(final_balance, final_blinding);
    let state_msg = poseidon_hash_span(
        array![DOMAIN_STATE, 1, 1, 0xdead, e_x, e_y, current_anchor].span(),
    );
    let state_wots_sig = fake_wots_sig(30);
    let state_auth_path = zero_xmss_auth_path();
    let state_sig_root = xmss_root_for_fixture(
        state_msg, 0, state_wots_sig.span(), state_auth_path.span(),
    );
    let withdrawal_nullifier = poseidon_hash_span(
        array![zkapi_cairo::domains::DOMAIN_NULL, secret_s, current_anchor].span(),
    );
    let clear_msg = poseidon_hash_span(
        array![DOMAIN_CLEAR, 1, 1, 0xdead, withdrawal_nullifier].span(),
    );
    let clear_wots_sig = fake_wots_sig(40);
    let clear_auth_path = zero_xmss_auth_path();
    let clear_sig_root = xmss_root_for_fixture(
        clear_msg, 0, clear_wots_sig.span(), clear_auth_path.span(),
    );

    run_withdrawal_program(
        1,
        1,
        0xdead,
        active_root,
        destination,
        secret_s,
        note_id,
        deposit_amount,
        expiry_ts,
        index_bits.span(),
        siblings.span(),
        final_balance,
        final_blinding,
        current_anchor,
        0,
        state_sig_root,
        1,
        0,
        state_wots_sig.span(),
        state_auth_path.span(),
        1,
        clear_sig_root,
        1,
        0,
        clear_wots_sig.span(),
        clear_auth_path.span(),
    )
}
