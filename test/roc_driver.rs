#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
extern "C" {
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    fn exit(_: libc::c_int) -> !;
    fn srtp_index_guess(
        local: *const srtp_xtd_seq_num_t,
        guess: *mut srtp_xtd_seq_num_t,
        s: srtp_sequence_number_t,
    ) -> int32_t;
    fn srtp_index_advance(pi: *mut srtp_xtd_seq_num_t, s: srtp_sequence_number_t);
    fn srtp_index_init(pi: *mut srtp_xtd_seq_num_t);
    fn ut_init(utc: *mut ut_connection);
    fn ut_next_index(utc: *mut ut_connection) -> uint32_t;
}
pub type __uint16_t = libc::c_ushort;
pub type __int32_t = libc::c_int;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type int32_t = __int32_t;
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
pub type srtp_sequence_number_t = uint16_t;
pub type srtp_xtd_seq_num_t = uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ut_connection {
    pub index: uint32_t,
    pub buffer: [uint32_t; 160],
}
unsafe fn main_0() -> libc::c_int {
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    printf(
        b"rollover counter test driver\nDavid A. McGrew\nCisco Systems, Inc.\n\0"
            as *const u8 as *const libc::c_char,
    );
    printf(b"testing index functions...\0" as *const u8 as *const libc::c_char);
    status = roc_test((1 as libc::c_int) << 18 as libc::c_int);
    if status as u64 != 0 {
        printf(b"failed\n\0" as *const u8 as *const libc::c_char);
        exit(status as libc::c_int);
    }
    printf(b"passed\n\0" as *const u8 as *const libc::c_char);
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn roc_test(mut num_trials: libc::c_int) -> srtp_err_status_t {
    let mut local: srtp_xtd_seq_num_t = 0;
    let mut est: srtp_xtd_seq_num_t = 0;
    let mut ref_0: srtp_xtd_seq_num_t = 0;
    let mut utc: ut_connection = ut_connection {
        index: 0,
        buffer: [0; 160],
    };
    let mut i: libc::c_int = 0;
    let mut num_bad_est: libc::c_int = 0 as libc::c_int;
    let mut delta: libc::c_int = 0;
    let mut ircvd: uint32_t = 0;
    let mut failure_rate: libc::c_double = 0.;
    srtp_index_init(&mut local);
    srtp_index_init(&mut ref_0);
    srtp_index_init(&mut est);
    printf(b"\n\ttesting sequential insertion...\0" as *const u8 as *const libc::c_char);
    i = 0 as libc::c_int;
    while i < 2048 as libc::c_int {
        srtp_index_guess(&mut local, &mut est, ref_0 as uint16_t);
        if ref_0 != est {
            num_bad_est += 1;
        }
        srtp_index_advance(&mut ref_0, 1 as libc::c_int as srtp_sequence_number_t);
        i += 1;
    }
    failure_rate = num_bad_est as libc::c_double / num_trials as libc::c_double;
    if failure_rate > 0.01f64 {
        printf(
            b"error: failure rate too high (%d bad estimates in %d trials)\n\0"
                as *const u8 as *const libc::c_char,
            num_bad_est,
            num_trials,
        );
        return srtp_err_status_algo_fail;
    }
    printf(b"done\n\0" as *const u8 as *const libc::c_char);
    printf(
        b"\ttesting non-sequential insertion...\0" as *const u8 as *const libc::c_char,
    );
    srtp_index_init(&mut local);
    srtp_index_init(&mut ref_0);
    srtp_index_init(&mut est);
    ut_init(&mut utc);
    i = 0 as libc::c_int;
    while i < num_trials {
        ircvd = ut_next_index(&mut utc);
        ref_0 = ircvd as srtp_xtd_seq_num_t;
        delta = srtp_index_guess(&mut local, &mut est, ref_0 as uint16_t);
        if local.wrapping_add(delta as libc::c_ulong) != est {
            printf(
                b" *bad delta*: local %llu + delta %d != est %llu\n\0" as *const u8
                    as *const libc::c_char,
                local as libc::c_ulonglong,
                delta,
                est as libc::c_ulonglong,
            );
            return srtp_err_status_algo_fail;
        }
        if delta > 0 as libc::c_int {
            srtp_index_advance(&mut local, delta as srtp_sequence_number_t);
        }
        if ref_0 != est {
            num_bad_est += 1;
            local = ref_0;
        }
        i += 1;
    }
    failure_rate = num_bad_est as libc::c_double / num_trials as libc::c_double;
    if failure_rate > 0.01f64 {
        printf(
            b"error: failure rate too high (%d bad estimates in %d trials)\n\0"
                as *const u8 as *const libc::c_char,
            num_bad_est,
            num_trials,
        );
        return srtp_err_status_algo_fail;
    }
    printf(b"done\n\0" as *const u8 as *const libc::c_char);
    return srtp_err_status_ok;
}
pub fn main() {
    unsafe { ::std::process::exit(main_0() as i32) }
}
