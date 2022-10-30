#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
extern "C" {
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    fn exit(_: libc::c_int) -> !;
    fn clock() -> clock_t;
    fn srtp_rdb_get_value(rdb: *const srtp_rdb_t) -> uint32_t;
    fn srtp_rdb_increment(rdb: *mut srtp_rdb_t) -> srtp_err_status_t;
    fn srtp_rdb_add_index(
        rdb: *mut srtp_rdb_t,
        rdb_index: uint32_t,
    ) -> srtp_err_status_t;
    fn srtp_rdb_check(rdb: *const srtp_rdb_t, rdb_index: uint32_t) -> srtp_err_status_t;
    fn srtp_rdb_init(rdb: *mut srtp_rdb_t) -> srtp_err_status_t;
    fn ut_init(utc: *mut ut_connection);
    fn ut_next_index(utc: *mut ut_connection) -> uint32_t;
    fn srtp_cipher_rand_u32_for_tests() -> uint32_t;
}
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __clock_t = libc::c_long;
pub type clock_t = __clock_t;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub union v128_t {
    pub v8: [uint8_t; 16],
    pub v16: [uint16_t; 8],
    pub v32: [uint32_t; 4],
    pub v64: [uint64_t; 2],
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct srtp_rdb_t {
    pub window_start: uint32_t,
    pub bitmask: v128_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ut_connection {
    pub index: uint32_t,
    pub buffer: [uint32_t; 160],
}
#[no_mangle]
pub static mut num_trials: libc::c_uint = ((1 as libc::c_int) << 16 as libc::c_int)
    as libc::c_uint;
unsafe fn main_0() -> libc::c_int {
    let mut err: srtp_err_status_t = srtp_err_status_ok;
    printf(
        b"testing anti-replay database (srtp_rdb_t)...\n\0" as *const u8
            as *const libc::c_char,
    );
    err = test_rdb_db();
    if err as u64 != 0 {
        printf(b"failed\n\0" as *const u8 as *const libc::c_char);
        exit(1 as libc::c_int);
    }
    printf(b"done\n\0" as *const u8 as *const libc::c_char);
    printf(
        b"rdb_check/rdb_adds per second: %e\n\0" as *const u8 as *const libc::c_char,
        rdb_check_adds_per_second(),
    );
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn rdb_check_add(
    mut rdb: *mut srtp_rdb_t,
    mut idx: uint32_t,
) -> srtp_err_status_t {
    if srtp_rdb_check(rdb, idx) as libc::c_uint
        != srtp_err_status_ok as libc::c_int as libc::c_uint
    {
        printf(
            b"rdb_check failed at index %u\n\0" as *const u8 as *const libc::c_char,
            idx,
        );
        return srtp_err_status_fail;
    }
    if srtp_rdb_add_index(rdb, idx) as libc::c_uint
        != srtp_err_status_ok as libc::c_int as libc::c_uint
    {
        printf(
            b"rdb_add_index failed at index %u\n\0" as *const u8 as *const libc::c_char,
            idx,
        );
        return srtp_err_status_fail;
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn rdb_check_expect_failure(
    mut rdb: *mut srtp_rdb_t,
    mut idx: uint32_t,
) -> srtp_err_status_t {
    let mut err: srtp_err_status_t = srtp_err_status_ok;
    err = srtp_rdb_check(rdb, idx);
    if err as libc::c_uint != srtp_err_status_replay_old as libc::c_int as libc::c_uint
        && err as libc::c_uint
            != srtp_err_status_replay_fail as libc::c_int as libc::c_uint
    {
        printf(
            b"rdb_check failed at index %u (false positive)\n\0" as *const u8
                as *const libc::c_char,
            idx,
        );
        return srtp_err_status_fail;
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn rdb_check_add_unordered(
    mut rdb: *mut srtp_rdb_t,
    mut idx: uint32_t,
) -> srtp_err_status_t {
    let mut rstat: srtp_err_status_t = srtp_err_status_ok;
    rstat = srtp_rdb_check(rdb, idx);
    if rstat as libc::c_uint != srtp_err_status_ok as libc::c_int as libc::c_uint
        && rstat as libc::c_uint
            != srtp_err_status_replay_old as libc::c_int as libc::c_uint
    {
        printf(
            b"rdb_check_add_unordered failed at index %u\n\0" as *const u8
                as *const libc::c_char,
            idx,
        );
        return rstat;
    }
    if rstat as libc::c_uint == srtp_err_status_replay_old as libc::c_int as libc::c_uint
    {
        return srtp_err_status_ok;
    }
    if srtp_rdb_add_index(rdb, idx) as libc::c_uint
        != srtp_err_status_ok as libc::c_int as libc::c_uint
    {
        printf(
            b"rdb_add_index failed at index %u\n\0" as *const u8 as *const libc::c_char,
            idx,
        );
        return srtp_err_status_fail;
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn test_rdb_db() -> srtp_err_status_t {
    let mut rdb: srtp_rdb_t = srtp_rdb_t {
        window_start: 0,
        bitmask: v128_t { v8: [0; 16] },
    };
    let mut idx: uint32_t = 0;
    let mut ircvd: uint32_t = 0;
    let mut utc: ut_connection = ut_connection {
        index: 0,
        buffer: [0; 160],
    };
    let mut err: srtp_err_status_t = srtp_err_status_ok;
    if srtp_rdb_init(&mut rdb) as libc::c_uint
        != srtp_err_status_ok as libc::c_int as libc::c_uint
    {
        printf(b"rdb_init failed\n\0" as *const u8 as *const libc::c_char);
        return srtp_err_status_init_fail;
    }
    idx = 0 as libc::c_int as uint32_t;
    while idx < num_trials {
        err = rdb_check_add(&mut rdb, idx);
        if err as u64 != 0 {
            return err;
        }
        idx = idx.wrapping_add(1);
    }
    idx = 0 as libc::c_int as uint32_t;
    while idx < num_trials {
        err = rdb_check_expect_failure(&mut rdb, idx);
        if err as u64 != 0 {
            return err;
        }
        idx = idx.wrapping_add(1);
    }
    if srtp_rdb_init(&mut rdb) as libc::c_uint
        != srtp_err_status_ok as libc::c_int as libc::c_uint
    {
        printf(b"rdb_init failed\n\0" as *const u8 as *const libc::c_char);
        return srtp_err_status_fail;
    }
    ut_init(&mut utc);
    idx = 0 as libc::c_int as uint32_t;
    while idx < num_trials {
        ircvd = ut_next_index(&mut utc);
        err = rdb_check_add_unordered(&mut rdb, ircvd);
        if err as u64 != 0 {
            return err;
        }
        err = rdb_check_expect_failure(&mut rdb, ircvd);
        if err as u64 != 0 {
            return err;
        }
        idx = idx.wrapping_add(1);
    }
    if srtp_rdb_init(&mut rdb) as libc::c_uint
        != srtp_err_status_ok as libc::c_int as libc::c_uint
    {
        printf(b"rdb_init failed\n\0" as *const u8 as *const libc::c_char);
        return srtp_err_status_fail;
    }
    idx = 0 as libc::c_int as uint32_t;
    ircvd = 0 as libc::c_int as uint32_t;
    while idx < num_trials {
        err = rdb_check_add(&mut rdb, ircvd);
        if err as u64 != 0 {
            return err;
        }
        err = rdb_check_expect_failure(&mut rdb, ircvd);
        if err as u64 != 0 {
            return err;
        }
        idx = idx.wrapping_add(1);
        ircvd = (ircvd as libc::c_uint)
            .wrapping_add(
                ((1 as libc::c_int)
                    << (srtp_cipher_rand_u32_for_tests())
                        .wrapping_rem(10 as libc::c_int as libc::c_uint)) as libc::c_uint,
            ) as uint32_t as uint32_t;
    }
    if srtp_rdb_init(&mut rdb) as libc::c_uint
        != srtp_err_status_ok as libc::c_int as libc::c_uint
    {
        printf(b"rdb_init failed\n\0" as *const u8 as *const libc::c_char);
        return srtp_err_status_fail;
    }
    idx = 0 as libc::c_int as uint32_t;
    while idx < num_trials {
        err = rdb_check_add(
            &mut rdb,
            idx.wrapping_add(513 as libc::c_int as libc::c_uint),
        );
        if err as u64 != 0 {
            return err;
        }
        idx = idx.wrapping_add(1);
    }
    idx = 0 as libc::c_int as uint32_t;
    while idx < num_trials.wrapping_add(513 as libc::c_int as libc::c_uint) {
        err = rdb_check_expect_failure(&mut rdb, idx);
        if err as u64 != 0 {
            return err;
        }
        idx = idx.wrapping_add(1);
    }
    if srtp_rdb_init(&mut rdb) as libc::c_uint
        != srtp_err_status_ok as libc::c_int as libc::c_uint
    {
        printf(b"rdb_init failed\n\0" as *const u8 as *const libc::c_char);
        return srtp_err_status_fail;
    }
    rdb.window_start = 0x7ffffffe as libc::c_int as uint32_t;
    if srtp_rdb_increment(&mut rdb) as libc::c_uint
        != srtp_err_status_ok as libc::c_int as libc::c_uint
    {
        printf(
            b"srtp_rdb_increment of 0x7ffffffe failed\n\0" as *const u8
                as *const libc::c_char,
        );
        return srtp_err_status_fail;
    }
    if srtp_rdb_get_value(&mut rdb) != 0x7fffffff as libc::c_int as libc::c_uint {
        printf(b"rdb valiue was not 0x7fffffff\n\0" as *const u8 as *const libc::c_char);
        return srtp_err_status_fail;
    }
    if srtp_rdb_increment(&mut rdb) as libc::c_uint
        != srtp_err_status_key_expired as libc::c_int as libc::c_uint
    {
        printf(
            b"srtp_rdb_increment of 0x7fffffff did not return srtp_err_status_key_expired\n\0"
                as *const u8 as *const libc::c_char,
        );
        return srtp_err_status_fail;
    }
    if srtp_rdb_get_value(&mut rdb) != 0x7fffffff as libc::c_int as libc::c_uint {
        printf(b"rdb valiue was not 0x7fffffff\n\0" as *const u8 as *const libc::c_char);
        return srtp_err_status_fail;
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn rdb_check_adds_per_second() -> libc::c_double {
    let mut i: uint32_t = 0;
    let mut rdb: srtp_rdb_t = srtp_rdb_t {
        window_start: 0,
        bitmask: v128_t { v8: [0; 16] },
    };
    let mut timer: clock_t = 0;
    let mut failures: libc::c_int = 0 as libc::c_int;
    if srtp_rdb_init(&mut rdb) as libc::c_uint
        != srtp_err_status_ok as libc::c_int as libc::c_uint
    {
        printf(b"rdb_init failed\n\0" as *const u8 as *const libc::c_char);
        exit(1 as libc::c_int);
    }
    timer = clock();
    i = 0 as libc::c_int as uint32_t;
    while i < 10000000 as libc::c_int as libc::c_uint {
        if srtp_rdb_check(&mut rdb, i.wrapping_add(2 as libc::c_int as libc::c_uint))
            as libc::c_uint != srtp_err_status_ok as libc::c_int as libc::c_uint
        {
            failures += 1;
        }
        if srtp_rdb_add_index(&mut rdb, i.wrapping_add(2 as libc::c_int as libc::c_uint))
            as libc::c_uint != srtp_err_status_ok as libc::c_int as libc::c_uint
        {
            failures += 1;
        }
        if srtp_rdb_check(&mut rdb, i.wrapping_add(1 as libc::c_int as libc::c_uint))
            as libc::c_uint != srtp_err_status_ok as libc::c_int as libc::c_uint
        {
            failures += 1;
        }
        if srtp_rdb_add_index(&mut rdb, i.wrapping_add(1 as libc::c_int as libc::c_uint))
            as libc::c_uint != srtp_err_status_ok as libc::c_int as libc::c_uint
        {
            failures += 1;
        }
        if srtp_rdb_check(&mut rdb, i) as libc::c_uint
            != srtp_err_status_ok as libc::c_int as libc::c_uint
        {
            failures += 1;
        }
        if srtp_rdb_add_index(&mut rdb, i) as libc::c_uint
            != srtp_err_status_ok as libc::c_int as libc::c_uint
        {
            failures += 1;
        }
        i = (i as libc::c_uint).wrapping_add(3 as libc::c_int as libc::c_uint)
            as uint32_t as uint32_t;
    }
    timer = clock() - timer;
    return 1000000 as libc::c_int as __clock_t as libc::c_double
        * 10000000 as libc::c_int as libc::c_double / timer as libc::c_double;
}
pub fn main() {
    unsafe { ::std::process::exit(main_0() as i32) }
}
