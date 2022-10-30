#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
use crate::v128_t;
extern "C" {
    fn v128_left_shift(x: *mut v128_t, shift_index: libc::c_int);
}
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct srtp_rdb_t {
    pub window_start: uint32_t,
    pub bitmask: v128_t,
}
#[no_mangle]
pub unsafe extern "C" fn srtp_rdb_init(mut rdb: *mut srtp_rdb_t) -> srtp_err_status_t {
    (*rdb).bitmask.v32[0 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    (*rdb).bitmask.v32[1 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    (*rdb).bitmask.v32[2 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    (*rdb).bitmask.v32[3 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    (*rdb).window_start = 0 as libc::c_int as uint32_t;
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_rdb_check(
    mut rdb: *const srtp_rdb_t,
    mut p_index: uint32_t,
) -> srtp_err_status_t {
    if p_index as libc::c_ulong
        >= ((*rdb).window_start as libc::c_ulong)
            .wrapping_add(
                (8 as libc::c_int as libc::c_ulong)
                    .wrapping_mul(::core::mem::size_of::<v128_t>() as libc::c_ulong),
            )
    {
        return srtp_err_status_ok;
    }
    if p_index < (*rdb).window_start {
        return srtp_err_status_replay_old;
    }
    if (*rdb)
        .bitmask
        .v32[(p_index.wrapping_sub((*rdb).window_start) >> 5 as libc::c_int) as usize]
        >> (p_index.wrapping_sub((*rdb).window_start)
            & 31 as libc::c_int as libc::c_uint) & 1 as libc::c_int as libc::c_uint
        == 1 as libc::c_int as libc::c_uint
    {
        return srtp_err_status_replay_fail;
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_rdb_add_index(
    mut rdb: *mut srtp_rdb_t,
    mut p_index: uint32_t,
) -> srtp_err_status_t {
    let mut delta: libc::c_uint = 0;
    if p_index < (*rdb).window_start {
        return srtp_err_status_replay_fail;
    }
    delta = p_index.wrapping_sub((*rdb).window_start);
    if (delta as libc::c_ulong)
        < (8 as libc::c_int as libc::c_ulong)
            .wrapping_mul(::core::mem::size_of::<v128_t>() as libc::c_ulong)
    {
        (*rdb).bitmask.v32[(delta >> 5 as libc::c_int) as usize]
            |= (1 as libc::c_int as uint32_t)
                << (delta & 31 as libc::c_int as libc::c_uint);
    } else {
        delta = (delta as libc::c_ulong)
            .wrapping_sub(
                (8 as libc::c_int as libc::c_ulong)
                    .wrapping_mul(::core::mem::size_of::<v128_t>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong),
            ) as libc::c_uint as libc::c_uint;
        v128_left_shift(&mut (*rdb).bitmask, delta as libc::c_int);
        (*rdb)
            .bitmask
            .v32[((8 as libc::c_int as libc::c_ulong)
            .wrapping_mul(::core::mem::size_of::<v128_t>() as libc::c_ulong)
            .wrapping_sub(1 as libc::c_int as libc::c_ulong) >> 5 as libc::c_int)
            as usize]
            |= (1 as libc::c_int as uint32_t)
                << ((8 as libc::c_int as libc::c_ulong)
                    .wrapping_mul(::core::mem::size_of::<v128_t>() as libc::c_ulong)
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong)
                    & 31 as libc::c_int as libc::c_ulong);
        (*rdb)
            .window_start = ((*rdb).window_start as libc::c_uint).wrapping_add(delta)
            as uint32_t as uint32_t;
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_rdb_increment(
    mut rdb: *mut srtp_rdb_t,
) -> srtp_err_status_t {
    if (*rdb).window_start >= 0x7fffffff as libc::c_int as libc::c_uint {
        return srtp_err_status_key_expired;
    }
    (*rdb).window_start = ((*rdb).window_start).wrapping_add(1);
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_rdb_get_value(mut rdb: *const srtp_rdb_t) -> uint32_t {
    return (*rdb).window_start;
}
