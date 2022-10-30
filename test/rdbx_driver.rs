#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
extern "C" {
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    fn getopt_s(
        argc: libc::c_int,
        argv: *const *mut libc::c_char,
        optstring: *const libc::c_char,
    ) -> libc::c_int;
    fn exit(_: libc::c_int) -> !;
    fn clock() -> clock_t;
    fn srtp_rdbx_init(rdbx: *mut srtp_rdbx_t, ws: libc::c_ulong) -> srtp_err_status_t;
    fn srtp_rdbx_dealloc(rdbx: *mut srtp_rdbx_t) -> srtp_err_status_t;
    fn srtp_rdbx_check(
        rdbx: *const srtp_rdbx_t,
        difference: libc::c_int,
    ) -> srtp_err_status_t;
    fn srtp_rdbx_add_index(
        rdbx: *mut srtp_rdbx_t,
        delta: libc::c_int,
    ) -> srtp_err_status_t;
    fn srtp_index_guess(
        local: *const srtp_xtd_seq_num_t,
        guess: *mut srtp_xtd_seq_num_t,
        s: srtp_sequence_number_t,
    ) -> int32_t;
    fn srtp_cipher_rand_u32_for_tests() -> uint32_t;
    fn ut_init(utc: *mut ut_connection);
    fn ut_next_index(utc: *mut ut_connection) -> uint32_t;
}
pub type __uint16_t = libc::c_ushort;
pub type __int32_t = libc::c_int;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __clock_t = libc::c_long;
pub type clock_t = __clock_t;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ut_connection {
    pub index: uint32_t,
    pub buffer: [uint32_t; 160],
}
#[no_mangle]
pub unsafe extern "C" fn usage(mut prog_name: *mut libc::c_char) {
    printf(b"usage: %s [ -t | -v ]\n\0" as *const u8 as *const libc::c_char, prog_name);
    exit(255 as libc::c_int);
}
unsafe fn main_0(
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut rate: libc::c_double = 0.;
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut q: libc::c_int = 0;
    let mut do_timing_test: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut do_validation: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    loop {
        q = getopt_s(
            argc,
            argv as *const *mut libc::c_char,
            b"tv\0" as *const u8 as *const libc::c_char,
        );
        if q == -(1 as libc::c_int) {
            break;
        }
        match q {
            116 => {
                do_timing_test = 1 as libc::c_int as libc::c_uint;
            }
            118 => {
                do_validation = 1 as libc::c_int as libc::c_uint;
            }
            _ => {
                usage(*argv.offset(0 as libc::c_int as isize));
            }
        }
    }
    printf(
        b"rdbx (replay database w/ extended range) test driver\nDavid A. McGrew\nCisco Systems, Inc.\n\0"
            as *const u8 as *const libc::c_char,
    );
    if do_validation == 0 && do_timing_test == 0 {
        usage(*argv.offset(0 as libc::c_int as isize));
    }
    if do_validation != 0 {
        printf(
            b"testing srtp_rdbx_t (ws=128)...\n\0" as *const u8 as *const libc::c_char,
        );
        status = test_replay_dbx(
            (1 as libc::c_int) << 12 as libc::c_int,
            128 as libc::c_int as libc::c_ulong,
        );
        if status as u64 != 0 {
            printf(b"failed\n\0" as *const u8 as *const libc::c_char);
            exit(1 as libc::c_int);
        }
        printf(b"passed\n\0" as *const u8 as *const libc::c_char);
        printf(
            b"testing srtp_rdbx_t (ws=1024)...\n\0" as *const u8 as *const libc::c_char,
        );
        status = test_replay_dbx(
            (1 as libc::c_int) << 12 as libc::c_int,
            1024 as libc::c_int as libc::c_ulong,
        );
        if status as u64 != 0 {
            printf(b"failed\n\0" as *const u8 as *const libc::c_char);
            exit(1 as libc::c_int);
        }
        printf(b"passed\n\0" as *const u8 as *const libc::c_char);
    }
    if do_timing_test != 0 {
        rate = rdbx_check_adds_per_second(
            (1 as libc::c_int) << 18 as libc::c_int,
            128 as libc::c_int as libc::c_ulong,
        );
        printf(
            b"rdbx_check/replay_adds per second (ws=128): %e\n\0" as *const u8
                as *const libc::c_char,
            rate,
        );
        rate = rdbx_check_adds_per_second(
            (1 as libc::c_int) << 18 as libc::c_int,
            1024 as libc::c_int as libc::c_ulong,
        );
        printf(
            b"rdbx_check/replay_adds per second (ws=1024): %e\n\0" as *const u8
                as *const libc::c_char,
            rate,
        );
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn rdbx_check_add(
    mut rdbx: *mut srtp_rdbx_t,
    mut idx: uint32_t,
) -> srtp_err_status_t {
    let mut delta: libc::c_int = 0;
    let mut est: srtp_xtd_seq_num_t = 0;
    delta = srtp_index_guess(
        &mut (*rdbx).index,
        &mut est,
        idx as srtp_sequence_number_t,
    );
    if srtp_rdbx_check(rdbx, delta) as libc::c_uint
        != srtp_err_status_ok as libc::c_int as libc::c_uint
    {
        printf(
            b"replay_check failed at index %u\n\0" as *const u8 as *const libc::c_char,
            idx,
        );
        return srtp_err_status_algo_fail;
    }
    if srtp_rdbx_add_index(rdbx, delta) as libc::c_uint
        != srtp_err_status_ok as libc::c_int as libc::c_uint
    {
        printf(
            b"rdbx_add_index failed at index %u\n\0" as *const u8 as *const libc::c_char,
            idx,
        );
        return srtp_err_status_algo_fail;
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn rdbx_check_expect_failure(
    mut rdbx: *mut srtp_rdbx_t,
    mut idx: uint32_t,
) -> srtp_err_status_t {
    let mut delta: libc::c_int = 0;
    let mut est: srtp_xtd_seq_num_t = 0;
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    delta = srtp_index_guess(
        &mut (*rdbx).index,
        &mut est,
        idx as srtp_sequence_number_t,
    );
    status = srtp_rdbx_check(rdbx, delta);
    if status as libc::c_uint == srtp_err_status_ok as libc::c_int as libc::c_uint {
        printf(b"delta: %d \0" as *const u8 as *const libc::c_char, delta);
        printf(
            b"replay_check failed at index %u (false positive)\n\0" as *const u8
                as *const libc::c_char,
            idx,
        );
        return srtp_err_status_algo_fail;
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn rdbx_check_add_unordered(
    mut rdbx: *mut srtp_rdbx_t,
    mut idx: uint32_t,
) -> srtp_err_status_t {
    let mut delta: libc::c_int = 0;
    let mut est: srtp_xtd_seq_num_t = 0;
    let mut rstat: srtp_err_status_t = srtp_err_status_ok;
    delta = srtp_index_guess(
        &mut (*rdbx).index,
        &mut est,
        idx as srtp_sequence_number_t,
    );
    rstat = srtp_rdbx_check(rdbx, delta);
    if rstat as libc::c_uint != srtp_err_status_ok as libc::c_int as libc::c_uint
        && rstat as libc::c_uint
            != srtp_err_status_replay_old as libc::c_int as libc::c_uint
    {
        printf(
            b"replay_check_add_unordered failed at index %u\n\0" as *const u8
                as *const libc::c_char,
            idx,
        );
        return srtp_err_status_algo_fail;
    }
    if rstat as libc::c_uint == srtp_err_status_replay_old as libc::c_int as libc::c_uint
    {
        return srtp_err_status_ok;
    }
    if srtp_rdbx_add_index(rdbx, delta) as libc::c_uint
        != srtp_err_status_ok as libc::c_int as libc::c_uint
    {
        printf(
            b"rdbx_add_index failed at index %u\n\0" as *const u8 as *const libc::c_char,
            idx,
        );
        return srtp_err_status_algo_fail;
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn test_replay_dbx(
    mut num_trials: libc::c_int,
    mut ws: libc::c_ulong,
) -> srtp_err_status_t {
    let mut rdbx: srtp_rdbx_t = srtp_rdbx_t {
        index: 0,
        bitmask: bitvector_t {
            length: 0,
            word: 0 as *mut uint32_t,
        },
    };
    let mut idx: uint32_t = 0;
    let mut ircvd: uint32_t = 0;
    let mut utc: ut_connection = ut_connection {
        index: 0,
        buffer: [0; 160],
    };
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut num_fp_trials: libc::c_int = 0;
    status = srtp_rdbx_init(&mut rdbx, ws);
    if status as u64 != 0 {
        printf(
            b"replay_init failed with error code %d\n\0" as *const u8
                as *const libc::c_char,
            status as libc::c_uint,
        );
        exit(1 as libc::c_int);
    }
    printf(b"\ttesting sequential insertion...\0" as *const u8 as *const libc::c_char);
    idx = 0 as libc::c_int as uint32_t;
    while (idx as libc::c_int) < num_trials {
        status = rdbx_check_add(&mut rdbx, idx);
        if status as u64 != 0 {
            return status;
        }
        idx = idx.wrapping_add(1);
    }
    printf(b"passed\n\0" as *const u8 as *const libc::c_char);
    num_fp_trials = num_trials % 0x10000 as libc::c_int;
    if num_fp_trials == 0 as libc::c_int {
        printf(
            b"warning: no false positive tests performed\n\0" as *const u8
                as *const libc::c_char,
        );
    }
    printf(b"\ttesting for false positives...\0" as *const u8 as *const libc::c_char);
    idx = 0 as libc::c_int as uint32_t;
    while (idx as libc::c_int) < num_fp_trials {
        status = rdbx_check_expect_failure(&mut rdbx, idx);
        if status as u64 != 0 {
            return status;
        }
        idx = idx.wrapping_add(1);
    }
    printf(b"passed\n\0" as *const u8 as *const libc::c_char);
    srtp_rdbx_dealloc(&mut rdbx);
    if srtp_rdbx_init(&mut rdbx, ws) as libc::c_uint
        != srtp_err_status_ok as libc::c_int as libc::c_uint
    {
        printf(b"replay_init failed\n\0" as *const u8 as *const libc::c_char);
        return srtp_err_status_init_fail;
    }
    ut_init(&mut utc);
    printf(
        b"\ttesting non-sequential insertion...\0" as *const u8 as *const libc::c_char,
    );
    idx = 0 as libc::c_int as uint32_t;
    while (idx as libc::c_int) < num_trials {
        ircvd = ut_next_index(&mut utc);
        status = rdbx_check_add_unordered(&mut rdbx, ircvd);
        if status as u64 != 0 {
            return status;
        }
        status = rdbx_check_expect_failure(&mut rdbx, ircvd);
        if status as u64 != 0 {
            return status;
        }
        idx = idx.wrapping_add(1);
    }
    printf(b"passed\n\0" as *const u8 as *const libc::c_char);
    srtp_rdbx_dealloc(&mut rdbx);
    if srtp_rdbx_init(&mut rdbx, ws) as libc::c_uint
        != srtp_err_status_ok as libc::c_int as libc::c_uint
    {
        printf(b"replay_init failed\n\0" as *const u8 as *const libc::c_char);
        return srtp_err_status_init_fail;
    }
    printf(
        b"\ttesting insertion with large gaps...\0" as *const u8 as *const libc::c_char,
    );
    idx = 0 as libc::c_int as uint32_t;
    ircvd = 0 as libc::c_int as uint32_t;
    while (idx as libc::c_int) < num_trials {
        status = rdbx_check_add(&mut rdbx, ircvd);
        if status as u64 != 0 {
            return status;
        }
        status = rdbx_check_expect_failure(&mut rdbx, ircvd);
        if status as u64 != 0 {
            return status;
        }
        idx = idx.wrapping_add(1);
        ircvd = (ircvd as libc::c_uint)
            .wrapping_add(
                ((1 as libc::c_int)
                    << (srtp_cipher_rand_u32_for_tests())
                        .wrapping_rem(12 as libc::c_int as libc::c_uint)) as libc::c_uint,
            ) as uint32_t as uint32_t;
    }
    printf(b"passed\n\0" as *const u8 as *const libc::c_char);
    srtp_rdbx_dealloc(&mut rdbx);
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn rdbx_check_adds_per_second(
    mut num_trials: libc::c_int,
    mut ws: libc::c_ulong,
) -> libc::c_double {
    let mut i: uint32_t = 0;
    let mut delta: libc::c_int = 0;
    let mut rdbx: srtp_rdbx_t = srtp_rdbx_t {
        index: 0,
        bitmask: bitvector_t {
            length: 0,
            word: 0 as *mut uint32_t,
        },
    };
    let mut est: srtp_xtd_seq_num_t = 0;
    let mut timer: clock_t = 0;
    let mut failures: libc::c_int = 0;
    if srtp_rdbx_init(&mut rdbx, ws) as libc::c_uint
        != srtp_err_status_ok as libc::c_int as libc::c_uint
    {
        printf(b"replay_init failed\n\0" as *const u8 as *const libc::c_char);
        exit(1 as libc::c_int);
    }
    failures = 0 as libc::c_int;
    timer = clock();
    i = 0 as libc::c_int as uint32_t;
    while (i as libc::c_int) < num_trials {
        delta = srtp_index_guess(&mut rdbx.index, &mut est, i as srtp_sequence_number_t);
        if srtp_rdbx_check(&mut rdbx, delta) as libc::c_uint
            != srtp_err_status_ok as libc::c_int as libc::c_uint
        {
            failures += 1;
        } else if srtp_rdbx_add_index(&mut rdbx, delta) as libc::c_uint
                != srtp_err_status_ok as libc::c_int as libc::c_uint
            {
            failures += 1;
        }
        i = i.wrapping_add(1);
    }
    timer = clock() - timer;
    if timer < 1 as libc::c_int as libc::c_long {
        timer = 1 as libc::c_int as clock_t;
    }
    printf(b"number of failures: %d \n\0" as *const u8 as *const libc::c_char, failures);
    srtp_rdbx_dealloc(&mut rdbx);
    return 1000000 as libc::c_int as __clock_t as libc::c_double
        * num_trials as libc::c_double / timer as libc::c_double;
}
pub fn main() {
    let mut args: Vec::<*mut libc::c_char> = Vec::new();
    for arg in ::std::env::args() {
        args.push(
            (::std::ffi::CString::new(arg))
                .expect("Failed to convert argument into CString.")
                .into_raw(),
        );
    }
    args.push(::core::ptr::null_mut());
    unsafe {
        ::std::process::exit(
            main_0(
                (args.len() - 1) as libc::c_int,
                args.as_mut_ptr() as *mut *mut libc::c_char,
            ) as i32,
        )
    }
}
