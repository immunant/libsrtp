#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
extern "C" {
    fn bitvector_alloc(v: *mut bitvector_t, length: libc::c_ulong) -> libc::c_int;
    fn bitvector_dealloc(v: *mut bitvector_t);
    fn bitvector_set_to_zero(x: *mut bitvector_t);
    fn bitvector_left_shift(x: *mut bitvector_t, index: libc::c_int);
}
pub type __uint16_t = libc::c_ushort;
pub type __int32_t = libc::c_int;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type int32_t = __int32_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bitvector_t {
    pub length: uint32_t,
    pub word: *mut uint32_t,
}
pub type srtp_err_status_t = libc::c_uint;
pub const srtp_err_status_pkt_idx_adv: srtp_err_status_t = 27;
pub const srtp_err_status_pkt_idx_old: srtp_err_status_t = 26;
pub const srtp_err_status_bad_mki: srtp_err_status_t = 25;
pub const srtp_err_status_pfkey_err: srtp_err_status_t = 24;
pub const srtp_err_status_semaphore_err: srtp_err_status_t = 23;
pub const srtp_err_status_encode_err: srtp_err_status_t = 22;
pub const srtp_err_status_parse_err: srtp_err_status_t = 21;
pub const srtp_err_status_write_fail: srtp_err_status_t = 20;
pub const srtp_err_status_read_fail: srtp_err_status_t = 19;
pub const srtp_err_status_nonce_bad: srtp_err_status_t = 18;
pub const srtp_err_status_signal_err: srtp_err_status_t = 17;
pub const srtp_err_status_socket_err: srtp_err_status_t = 16;
pub const srtp_err_status_key_expired: srtp_err_status_t = 15;
pub const srtp_err_status_cant_check: srtp_err_status_t = 14;
pub const srtp_err_status_no_ctx: srtp_err_status_t = 13;
pub const srtp_err_status_no_such_op: srtp_err_status_t = 12;
pub const srtp_err_status_algo_fail: srtp_err_status_t = 11;
pub const srtp_err_status_replay_old: srtp_err_status_t = 10;
pub const srtp_err_status_replay_fail: srtp_err_status_t = 9;
pub const srtp_err_status_cipher_fail: srtp_err_status_t = 8;
pub const srtp_err_status_auth_fail: srtp_err_status_t = 7;
pub const srtp_err_status_terminus: srtp_err_status_t = 6;
pub const srtp_err_status_init_fail: srtp_err_status_t = 5;
pub const srtp_err_status_dealloc_fail: srtp_err_status_t = 4;
pub const srtp_err_status_alloc_fail: srtp_err_status_t = 3;
pub const srtp_err_status_bad_param: srtp_err_status_t = 2;
pub const srtp_err_status_fail: srtp_err_status_t = 1;
pub const srtp_err_status_ok: srtp_err_status_t = 0;
pub type srtp_sequence_number_t = uint16_t;
pub type srtp_xtd_seq_num_t = uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct srtp_rdbx_t {
    pub index: srtp_xtd_seq_num_t,
    pub bitmask: bitvector_t,
}
#[no_mangle]
pub unsafe extern "C" fn srtp_index_init(mut pi: *mut srtp_xtd_seq_num_t) {
    *pi = 0 as libc::c_int as srtp_xtd_seq_num_t;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_index_advance(
    mut pi: *mut srtp_xtd_seq_num_t,
    mut s: srtp_sequence_number_t,
) {
    *pi = (*pi as libc::c_ulong).wrapping_add(s as libc::c_ulong) as srtp_xtd_seq_num_t
        as srtp_xtd_seq_num_t;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_index_guess(
    mut local: *const srtp_xtd_seq_num_t,
    mut guess: *mut srtp_xtd_seq_num_t,
    mut s: srtp_sequence_number_t,
) -> int32_t {
    let mut local_roc: uint32_t = (*local >> 16 as libc::c_int) as uint32_t;
    let mut local_seq: uint16_t = *local as uint16_t;
    let mut guess_roc: uint32_t = 0;
    let mut guess_seq: uint16_t = 0;
    let mut difference: int32_t = 0;
    if (local_seq as libc::c_int)
        < (1 as libc::c_int)
            << (8 as libc::c_int as libc::c_ulong)
                .wrapping_mul(
                    ::core::mem::size_of::<srtp_sequence_number_t>() as libc::c_ulong,
                )
                .wrapping_sub(1 as libc::c_int as libc::c_ulong)
    {
        if s as libc::c_int - local_seq as libc::c_int
            > (1 as libc::c_int)
                << (8 as libc::c_int as libc::c_ulong)
                    .wrapping_mul(
                        ::core::mem::size_of::<srtp_sequence_number_t>() as libc::c_ulong,
                    )
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong)
        {
            guess_roc = local_roc.wrapping_sub(1 as libc::c_int as libc::c_uint);
            difference = s as libc::c_int - local_seq as libc::c_int
                - ((1 as libc::c_int)
                    << (8 as libc::c_int as libc::c_ulong)
                        .wrapping_mul(
                            ::core::mem::size_of::<srtp_sequence_number_t>()
                                as libc::c_ulong,
                        ));
        } else {
            guess_roc = local_roc;
            difference = s as libc::c_int - local_seq as libc::c_int;
        }
    } else if local_seq as libc::c_int
            - ((1 as libc::c_int)
                << (8 as libc::c_int as libc::c_ulong)
                    .wrapping_mul(
                        ::core::mem::size_of::<srtp_sequence_number_t>() as libc::c_ulong,
                    )
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong)) > s as libc::c_int
        {
        guess_roc = local_roc.wrapping_add(1 as libc::c_int as libc::c_uint);
        difference = s as libc::c_int - local_seq as libc::c_int
            + ((1 as libc::c_int)
                << (8 as libc::c_int as libc::c_ulong)
                    .wrapping_mul(
                        ::core::mem::size_of::<srtp_sequence_number_t>() as libc::c_ulong,
                    ));
    } else {
        guess_roc = local_roc;
        difference = s as libc::c_int - local_seq as libc::c_int;
    }
    guess_seq = s;
    *guess = (guess_roc as uint64_t) << 16 as libc::c_int | guess_seq as libc::c_ulong;
    return difference;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_rdbx_init(
    mut rdbx: *mut srtp_rdbx_t,
    mut ws: libc::c_ulong,
) -> srtp_err_status_t {
    if ws == 0 as libc::c_int as libc::c_ulong {
        return srtp_err_status_bad_param;
    }
    if bitvector_alloc(&mut (*rdbx).bitmask, ws) != 0 as libc::c_int {
        return srtp_err_status_alloc_fail;
    }
    srtp_index_init(&mut (*rdbx).index);
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_rdbx_dealloc(
    mut rdbx: *mut srtp_rdbx_t,
) -> srtp_err_status_t {
    bitvector_dealloc(&mut (*rdbx).bitmask);
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_rdbx_set_roc(
    mut rdbx: *mut srtp_rdbx_t,
    mut roc: uint32_t,
) -> srtp_err_status_t {
    bitvector_set_to_zero(&mut (*rdbx).bitmask);
    if (roc as libc::c_ulong) < (*rdbx).index >> 16 as libc::c_int {
        return srtp_err_status_replay_old;
    }
    (*rdbx).index &= 0xffff as libc::c_int as libc::c_ulong;
    (*rdbx).index |= (roc as uint64_t) << 16 as libc::c_int;
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_rdbx_get_packet_index(
    mut rdbx: *const srtp_rdbx_t,
) -> srtp_xtd_seq_num_t {
    return (*rdbx).index;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_rdbx_get_window_size(
    mut rdbx: *const srtp_rdbx_t,
) -> libc::c_ulong {
    return (*rdbx).bitmask.length as libc::c_ulong;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_rdbx_check(
    mut rdbx: *const srtp_rdbx_t,
    mut delta: libc::c_int,
) -> srtp_err_status_t {
    if delta > 0 as libc::c_int {
        return srtp_err_status_ok
    } else {
        if ((*rdbx).bitmask.length).wrapping_sub(1 as libc::c_int as libc::c_uint)
            as libc::c_int + delta < 0 as libc::c_int
        {
            return srtp_err_status_replay_old
        } else {
            if *((*rdbx).bitmask.word)
                .offset(
                    (((*rdbx).bitmask.length)
                        .wrapping_sub(1 as libc::c_int as libc::c_uint) as libc::c_int
                        + delta >> 5 as libc::c_int) as isize,
                )
                >> (((*rdbx).bitmask.length)
                    .wrapping_sub(1 as libc::c_int as libc::c_uint) as libc::c_int
                    + delta & 31 as libc::c_int) & 1 as libc::c_int as libc::c_uint
                == 1 as libc::c_int as libc::c_uint
            {
                return srtp_err_status_replay_fail;
            }
        }
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_rdbx_add_index(
    mut rdbx: *mut srtp_rdbx_t,
    mut delta: libc::c_int,
) -> srtp_err_status_t {
    if delta > 0 as libc::c_int {
        srtp_index_advance(&mut (*rdbx).index, delta as srtp_sequence_number_t);
        bitvector_left_shift(&mut (*rdbx).bitmask, delta);
        let ref mut fresh0 = *((*rdbx).bitmask.word)
            .offset(
                (((*rdbx).bitmask.length).wrapping_sub(1 as libc::c_int as libc::c_uint)
                    >> 5 as libc::c_int) as isize,
            );
        *fresh0
            |= (1 as libc::c_int as uint32_t)
                << (((*rdbx).bitmask.length)
                    .wrapping_sub(1 as libc::c_int as libc::c_uint)
                    & 31 as libc::c_int as libc::c_uint);
    } else {
        let ref mut fresh1 = *((*rdbx).bitmask.word)
            .offset(
                (((*rdbx).bitmask.length)
                    .wrapping_sub(1 as libc::c_int as libc::c_uint)
                    .wrapping_add(delta as libc::c_uint) >> 5 as libc::c_int) as isize,
            );
        *fresh1
            |= (1 as libc::c_int as uint32_t)
                << (((*rdbx).bitmask.length)
                    .wrapping_sub(1 as libc::c_int as libc::c_uint)
                    .wrapping_add(delta as libc::c_uint)
                    & 31 as libc::c_int as libc::c_uint);
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_rdbx_estimate_index(
    mut rdbx: *const srtp_rdbx_t,
    mut guess: *mut srtp_xtd_seq_num_t,
    mut s: srtp_sequence_number_t,
) -> int32_t {
    if (*rdbx).index
        > ((1 as libc::c_int)
            << (8 as libc::c_int as libc::c_ulong)
                .wrapping_mul(
                    ::core::mem::size_of::<srtp_sequence_number_t>() as libc::c_ulong,
                )
                .wrapping_sub(1 as libc::c_int as libc::c_ulong)) as libc::c_ulong
    {
        return srtp_index_guess(&(*rdbx).index, guess, s);
    }
    *guess = s as srtp_xtd_seq_num_t;
    return s as libc::c_int - (*rdbx).index as uint16_t as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_rdbx_get_roc(mut rdbx: *const srtp_rdbx_t) -> uint32_t {
    let mut roc: uint32_t = 0;
    roc = ((*rdbx).index >> 16 as libc::c_int) as uint32_t;
    return roc;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_rdbx_set_roc_seq(
    mut rdbx: *mut srtp_rdbx_t,
    mut roc: uint32_t,
    mut seq: uint16_t,
) -> srtp_err_status_t {
    if (roc as libc::c_ulong) < (*rdbx).index >> 16 as libc::c_int {
        return srtp_err_status_replay_old;
    }
    (*rdbx).index = seq as srtp_xtd_seq_num_t;
    (*rdbx).index |= (roc as uint64_t) << 16 as libc::c_int;
    bitvector_set_to_zero(&mut (*rdbx).bitmask);
    return srtp_err_status_ok;
}
