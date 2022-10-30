#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
pub type __uint64_t = libc::c_ulong;
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
pub type srtp_xtd_seq_num_t = uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct srtp_key_limit_ctx_t {
    pub num_left: srtp_xtd_seq_num_t,
    pub state: srtp_key_state_t,
}
pub type srtp_key_state_t = libc::c_uint;
pub const srtp_key_state_expired: srtp_key_state_t = 2;
pub const srtp_key_state_past_soft_limit: srtp_key_state_t = 1;
pub const srtp_key_state_normal: srtp_key_state_t = 0;
pub type srtp_key_limit_t = *mut srtp_key_limit_ctx_t;
pub type srtp_key_event_t = libc::c_uint;
pub const srtp_key_event_hard_limit: srtp_key_event_t = 2;
pub const srtp_key_event_soft_limit: srtp_key_event_t = 1;
pub const srtp_key_event_normal: srtp_key_event_t = 0;
#[no_mangle]
pub unsafe extern "C" fn srtp_key_limit_set(
    mut key: srtp_key_limit_t,
    s: srtp_xtd_seq_num_t,
) -> srtp_err_status_t {
    if s < 0x10000 as libc::c_int as libc::c_ulong {
        return srtp_err_status_bad_param;
    }
    (*key).num_left = s;
    (*key).state = srtp_key_state_normal;
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_key_limit_clone(
    mut original: srtp_key_limit_t,
    mut new_key: *mut srtp_key_limit_t,
) -> srtp_err_status_t {
    if original.is_null() {
        return srtp_err_status_bad_param;
    }
    *new_key = original;
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_key_limit_update(
    mut key: srtp_key_limit_t,
) -> srtp_key_event_t {
    (*key).num_left = ((*key).num_left).wrapping_sub(1);
    if (*key).num_left >= 0x10000 as libc::c_int as libc::c_ulong {
        return srtp_key_event_normal;
    }
    if (*key).state as libc::c_uint
        == srtp_key_state_normal as libc::c_int as libc::c_uint
    {
        (*key).state = srtp_key_state_past_soft_limit;
    }
    if (*key).num_left < 1 as libc::c_int as libc::c_ulong {
        (*key).state = srtp_key_state_expired;
        return srtp_key_event_hard_limit;
    }
    return srtp_key_event_soft_limit;
}
