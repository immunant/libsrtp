#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
#![feature(extern_types)]
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    static mut stdout: *mut FILE;
    static mut stderr: *mut FILE;
    fn fflush(__stream: *mut FILE) -> libc::c_int;
    fn fprintf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    fn getopt_s(
        argc: libc::c_int,
        argv: *const *mut libc::c_char,
        optstring: *const libc::c_char,
    ) -> libc::c_int;
    fn srtp_cipher_encrypt(
        c: *mut srtp_cipher_t,
        buffer: *mut uint8_t,
        num_octets_to_output: *mut uint32_t,
    ) -> srtp_err_status_t;
    fn srtp_cipher_set_iv(
        c: *mut srtp_cipher_t,
        iv: *mut uint8_t,
        direction: libc::c_int,
    ) -> srtp_err_status_t;
    fn srtp_cipher_init(c: *mut srtp_cipher_t, key: *const uint8_t) -> srtp_err_status_t;
    fn srtp_cipher_dealloc(c: *mut srtp_cipher_t) -> srtp_err_status_t;
    fn srtp_cipher_type_alloc(
        ct: *const srtp_cipher_type_t,
        c: *mut *mut srtp_cipher_t,
        key_len: libc::c_int,
        tlen: libc::c_int,
    ) -> srtp_err_status_t;
    fn srtp_cipher_bits_per_second(
        c: *mut srtp_cipher_t,
        octets_in_buffer: libc::c_int,
        num_trials: libc::c_int,
    ) -> uint64_t;
    fn srtp_cipher_type_self_test(ct: *const srtp_cipher_type_t) -> srtp_err_status_t;
    fn srtp_cipher_rand_for_tests(dest: *mut libc::c_void, len: uint32_t);
    fn srtp_cipher_rand_u32_for_tests() -> uint32_t;
    fn exit(_: libc::c_int) -> !;
    fn srtp_crypto_alloc(size: size_t) -> *mut libc::c_void;
    fn srtp_crypto_free(ptr: *mut libc::c_void);
    fn clock() -> clock_t;
    static mut srtp_null_cipher: srtp_cipher_type_t;
    static mut srtp_aes_icm_128: srtp_cipher_type_t;
    static mut srtp_aes_icm_256: srtp_cipher_type_t;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __clock_t = libc::c_long;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct _IO_FILE {
    pub _flags: libc::c_int,
    pub _IO_read_ptr: *mut libc::c_char,
    pub _IO_read_end: *mut libc::c_char,
    pub _IO_read_base: *mut libc::c_char,
    pub _IO_write_base: *mut libc::c_char,
    pub _IO_write_ptr: *mut libc::c_char,
    pub _IO_write_end: *mut libc::c_char,
    pub _IO_buf_base: *mut libc::c_char,
    pub _IO_buf_end: *mut libc::c_char,
    pub _IO_save_base: *mut libc::c_char,
    pub _IO_backup_base: *mut libc::c_char,
    pub _IO_save_end: *mut libc::c_char,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: libc::c_int,
    pub _flags2: libc::c_int,
    pub _old_offset: __off_t,
    pub _cur_column: libc::c_ushort,
    pub _vtable_offset: libc::c_schar,
    pub _shortbuf: [libc::c_char; 1],
    pub _lock: *mut libc::c_void,
    pub _offset: __off64_t,
    pub _codecvt: *mut _IO_codecvt,
    pub _wide_data: *mut _IO_wide_data,
    pub _freeres_list: *mut _IO_FILE,
    pub _freeres_buf: *mut libc::c_void,
    pub __pad5: size_t,
    pub _mode: libc::c_int,
    pub _unused2: [libc::c_char; 20],
}
pub type _IO_lock_t = ();
pub type FILE = _IO_FILE;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type srtp_cipher_type_id_t = uint32_t;
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
pub type srtp_cipher_direction_t = libc::c_uint;
pub const srtp_direction_any: srtp_cipher_direction_t = 2;
pub const srtp_direction_decrypt: srtp_cipher_direction_t = 1;
pub const srtp_direction_encrypt: srtp_cipher_direction_t = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct srtp_cipher_t {
    pub type_0: *const srtp_cipher_type_t,
    pub state: *mut libc::c_void,
    pub key_len: libc::c_int,
    pub algorithm: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct srtp_cipher_type_t {
    pub alloc: srtp_cipher_alloc_func_t,
    pub dealloc: srtp_cipher_dealloc_func_t,
    pub init: srtp_cipher_init_func_t,
    pub set_aad: srtp_cipher_set_aad_func_t,
    pub encrypt: srtp_cipher_encrypt_func_t,
    pub decrypt: srtp_cipher_encrypt_func_t,
    pub set_iv: srtp_cipher_set_iv_func_t,
    pub get_tag: srtp_cipher_get_tag_func_t,
    pub description: *const libc::c_char,
    pub test_data: *const srtp_cipher_test_case_t,
    pub id: srtp_cipher_type_id_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct srtp_cipher_test_case_t {
    pub key_length_octets: libc::c_int,
    pub key: *const uint8_t,
    pub idx: *mut uint8_t,
    pub plaintext_length_octets: libc::c_uint,
    pub plaintext: *const uint8_t,
    pub ciphertext_length_octets: libc::c_uint,
    pub ciphertext: *const uint8_t,
    pub aad_length_octets: libc::c_int,
    pub aad: *const uint8_t,
    pub tag_length_octets: libc::c_int,
    pub next_test_case: *const srtp_cipher_test_case_t,
}
pub type srtp_cipher_get_tag_func_t = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *mut uint8_t,
        *mut uint32_t,
    ) -> srtp_err_status_t,
>;
pub type srtp_cipher_set_iv_func_t = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *mut uint8_t,
        srtp_cipher_direction_t,
    ) -> srtp_err_status_t,
>;
pub type srtp_cipher_encrypt_func_t = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *mut uint8_t,
        *mut libc::c_uint,
    ) -> srtp_err_status_t,
>;
pub type srtp_cipher_set_aad_func_t = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const uint8_t,
        uint32_t,
    ) -> srtp_err_status_t,
>;
pub type srtp_cipher_init_func_t = Option::<
    unsafe extern "C" fn(*mut libc::c_void, *const uint8_t) -> srtp_err_status_t,
>;
pub type srtp_cipher_dealloc_func_t = Option::<
    unsafe extern "C" fn(srtp_cipher_pointer_t) -> srtp_err_status_t,
>;
pub type srtp_cipher_pointer_t = *mut srtp_cipher_t;
pub type srtp_cipher_alloc_func_t = Option::<
    unsafe extern "C" fn(
        *mut srtp_cipher_pointer_t,
        libc::c_int,
        libc::c_int,
    ) -> srtp_err_status_t,
>;
pub type clock_t = __clock_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub union v128_t {
    pub v8: [uint8_t; 16],
    pub v16: [uint16_t; 8],
    pub v32: [uint32_t; 4],
    pub v64: [uint64_t; 2],
}
#[no_mangle]
pub unsafe extern "C" fn usage(mut prog_name: *mut libc::c_char) {
    printf(
        b"usage: %s [ -t | -v | -a ]\n\0" as *const u8 as *const libc::c_char,
        prog_name,
    );
    exit(255 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn check_status(mut s: srtp_err_status_t) {
    if s as u64 != 0 {
        printf(
            b"error (code %d)\n\0" as *const u8 as *const libc::c_char,
            s as libc::c_uint,
        );
        exit(s as libc::c_int);
    }
}
unsafe fn main_0(
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut c: *mut srtp_cipher_t = 0 as *mut srtp_cipher_t;
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut test_key: [libc::c_uchar; 48] = [
        0 as libc::c_int as libc::c_uchar,
        0x1 as libc::c_int as libc::c_uchar,
        0x2 as libc::c_int as libc::c_uchar,
        0x3 as libc::c_int as libc::c_uchar,
        0x4 as libc::c_int as libc::c_uchar,
        0x5 as libc::c_int as libc::c_uchar,
        0x6 as libc::c_int as libc::c_uchar,
        0x7 as libc::c_int as libc::c_uchar,
        0x8 as libc::c_int as libc::c_uchar,
        0x9 as libc::c_int as libc::c_uchar,
        0xa as libc::c_int as libc::c_uchar,
        0xb as libc::c_int as libc::c_uchar,
        0xc as libc::c_int as libc::c_uchar,
        0xd as libc::c_int as libc::c_uchar,
        0xe as libc::c_int as libc::c_uchar,
        0xf as libc::c_int as libc::c_uchar,
        0x10 as libc::c_int as libc::c_uchar,
        0x11 as libc::c_int as libc::c_uchar,
        0x12 as libc::c_int as libc::c_uchar,
        0x13 as libc::c_int as libc::c_uchar,
        0x14 as libc::c_int as libc::c_uchar,
        0x15 as libc::c_int as libc::c_uchar,
        0x16 as libc::c_int as libc::c_uchar,
        0x17 as libc::c_int as libc::c_uchar,
        0x18 as libc::c_int as libc::c_uchar,
        0x19 as libc::c_int as libc::c_uchar,
        0x1a as libc::c_int as libc::c_uchar,
        0x1b as libc::c_int as libc::c_uchar,
        0x1c as libc::c_int as libc::c_uchar,
        0x1d as libc::c_int as libc::c_uchar,
        0x1e as libc::c_int as libc::c_uchar,
        0x1f as libc::c_int as libc::c_uchar,
        0x20 as libc::c_int as libc::c_uchar,
        0x21 as libc::c_int as libc::c_uchar,
        0x22 as libc::c_int as libc::c_uchar,
        0x23 as libc::c_int as libc::c_uchar,
        0x24 as libc::c_int as libc::c_uchar,
        0x25 as libc::c_int as libc::c_uchar,
        0x26 as libc::c_int as libc::c_uchar,
        0x27 as libc::c_int as libc::c_uchar,
        0x28 as libc::c_int as libc::c_uchar,
        0x29 as libc::c_int as libc::c_uchar,
        0x2a as libc::c_int as libc::c_uchar,
        0x2b as libc::c_int as libc::c_uchar,
        0x2c as libc::c_int as libc::c_uchar,
        0x2d as libc::c_int as libc::c_uchar,
        0x2e as libc::c_int as libc::c_uchar,
        0x2f as libc::c_int as libc::c_uchar,
    ];
    let mut q: libc::c_int = 0;
    let mut do_timing_test: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut do_validation: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut do_array_timing_test: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    loop {
        q = getopt_s(
            argc,
            argv as *const *mut libc::c_char,
            b"tva\0" as *const u8 as *const libc::c_char,
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
            97 => {
                do_array_timing_test = 1 as libc::c_int as libc::c_uint;
            }
            _ => {
                usage(*argv.offset(0 as libc::c_int as isize));
            }
        }
    }
    printf(
        b"cipher test driver\nDavid A. McGrew\nCisco Systems, Inc.\n\0" as *const u8
            as *const libc::c_char,
    );
    if do_validation == 0 && do_timing_test == 0 && do_array_timing_test == 0 {
        usage(*argv.offset(0 as libc::c_int as isize));
    }
    if do_array_timing_test != 0 {
        let mut max_num_cipher: libc::c_int = (1 as libc::c_int) << 16 as libc::c_int;
        let mut num_cipher: libc::c_int = 0;
        num_cipher = 1 as libc::c_int;
        while num_cipher < max_num_cipher {
            cipher_driver_test_array_throughput(
                &mut srtp_null_cipher,
                0 as libc::c_int,
                num_cipher,
            );
            num_cipher *= 8 as libc::c_int;
        }
        num_cipher = 1 as libc::c_int;
        while num_cipher < max_num_cipher {
            cipher_driver_test_array_throughput(
                &mut srtp_aes_icm_128,
                14 as libc::c_int + 16 as libc::c_int,
                num_cipher,
            );
            num_cipher *= 8 as libc::c_int;
        }
        num_cipher = 1 as libc::c_int;
        while num_cipher < max_num_cipher {
            cipher_driver_test_array_throughput(
                &mut srtp_aes_icm_256,
                14 as libc::c_int + 32 as libc::c_int,
                num_cipher,
            );
            num_cipher *= 8 as libc::c_int;
        }
    }
    if do_validation != 0 {
        cipher_driver_self_test(&mut srtp_null_cipher);
        cipher_driver_self_test(&mut srtp_aes_icm_128);
        cipher_driver_self_test(&mut srtp_aes_icm_256);
    }
    status = srtp_cipher_type_alloc(
        &mut srtp_null_cipher,
        &mut c,
        0 as libc::c_int,
        0 as libc::c_int,
    );
    check_status(status);
    status = srtp_cipher_init(c, 0 as *const uint8_t);
    check_status(status);
    if do_timing_test != 0 {
        cipher_driver_test_throughput(c);
    }
    if do_validation != 0 {
        status = cipher_driver_test_buffering(c);
        check_status(status);
    }
    status = srtp_cipher_dealloc(c);
    check_status(status);
    status = srtp_cipher_type_alloc(
        &mut srtp_aes_icm_128,
        &mut c,
        14 as libc::c_int + 16 as libc::c_int,
        0 as libc::c_int,
    );
    if status as u64 != 0 {
        fprintf(
            stderr,
            b"error: can't allocate cipher\n\0" as *const u8 as *const libc::c_char,
        );
        exit(status as libc::c_int);
    }
    status = srtp_cipher_init(c, test_key.as_mut_ptr());
    check_status(status);
    if do_timing_test != 0 {
        cipher_driver_test_throughput(c);
    }
    if do_validation != 0 {
        status = cipher_driver_test_buffering(c);
        check_status(status);
    }
    status = srtp_cipher_dealloc(c);
    check_status(status);
    status = srtp_cipher_type_alloc(
        &mut srtp_aes_icm_256,
        &mut c,
        14 as libc::c_int + 32 as libc::c_int,
        0 as libc::c_int,
    );
    if status as u64 != 0 {
        fprintf(
            stderr,
            b"error: can't allocate cipher\n\0" as *const u8 as *const libc::c_char,
        );
        exit(status as libc::c_int);
    }
    status = srtp_cipher_init(c, test_key.as_mut_ptr());
    check_status(status);
    if do_timing_test != 0 {
        cipher_driver_test_throughput(c);
    }
    if do_validation != 0 {
        status = cipher_driver_test_buffering(c);
        check_status(status);
    }
    status = srtp_cipher_dealloc(c);
    check_status(status);
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn cipher_driver_test_throughput(mut c: *mut srtp_cipher_t) {
    let mut i: libc::c_int = 0;
    let mut min_enc_len: libc::c_int = 32 as libc::c_int;
    let mut max_enc_len: libc::c_int = 2048 as libc::c_int;
    let mut num_trials: libc::c_int = 1000000 as libc::c_int;
    printf(
        b"timing %s throughput, key length %d:\n\0" as *const u8 as *const libc::c_char,
        (*(*c).type_0).description,
        (*c).key_len,
    );
    fflush(stdout);
    i = min_enc_len;
    while i <= max_enc_len {
        printf(
            b"msg len: %d\tgigabits per second: %f\n\0" as *const u8
                as *const libc::c_char,
            i,
            srtp_cipher_bits_per_second(c, i, num_trials) as libc::c_double / 1e9f64,
        );
        i = i * 2 as libc::c_int;
    }
}
#[no_mangle]
pub unsafe extern "C" fn cipher_driver_self_test(
    mut ct: *mut srtp_cipher_type_t,
) -> srtp_err_status_t {
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    printf(
        b"running cipher self-test for %s...\0" as *const u8 as *const libc::c_char,
        (*ct).description,
    );
    status = srtp_cipher_type_self_test(ct);
    if status as u64 != 0 {
        printf(
            b"failed with error code %d\n\0" as *const u8 as *const libc::c_char,
            status as libc::c_uint,
        );
        exit(status as libc::c_int);
    }
    printf(b"passed\n\0" as *const u8 as *const libc::c_char);
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn cipher_driver_test_buffering(
    mut c: *mut srtp_cipher_t,
) -> srtp_err_status_t {
    let mut i: libc::c_int = 0;
    let mut j: libc::c_int = 0;
    let mut num_trials: libc::c_int = 1000 as libc::c_int;
    let mut len: libc::c_uint = 0;
    let mut buflen: libc::c_uint = 1024 as libc::c_int as libc::c_uint;
    let mut buffer0: [uint8_t; 1024] = [0; 1024];
    let mut buffer1: [uint8_t; 1024] = [0; 1024];
    let mut current: *mut uint8_t = 0 as *mut uint8_t;
    let mut end: *mut uint8_t = 0 as *mut uint8_t;
    let mut idx: [uint8_t; 16] = [
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0x12 as libc::c_int as uint8_t,
        0x34 as libc::c_int as uint8_t,
    ];
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    printf(
        b"testing output buffering for cipher %s...\0" as *const u8
            as *const libc::c_char,
        (*(*c).type_0).description,
    );
    i = 0 as libc::c_int;
    while i < num_trials {
        j = 0 as libc::c_int;
        while j < buflen as libc::c_int {
            buffer1[j as usize] = 0 as libc::c_int as uint8_t;
            buffer0[j as usize] = buffer1[j as usize];
            j += 1;
        }
        status = srtp_cipher_set_iv(
            c,
            idx.as_mut_ptr(),
            srtp_direction_encrypt as libc::c_int,
        );
        if status as u64 != 0 {
            return status;
        }
        status = srtp_cipher_encrypt(c, buffer0.as_mut_ptr(), &mut buflen);
        if status as u64 != 0 {
            return status;
        }
        status = srtp_cipher_set_iv(
            c,
            idx.as_mut_ptr(),
            srtp_direction_encrypt as libc::c_int,
        );
        if status as u64 != 0 {
            return status;
        }
        current = buffer1.as_mut_ptr();
        end = buffer1.as_mut_ptr().offset(buflen as isize);
        while current < end {
            len = srtp_cipher_rand_u32_for_tests() & 0x1f as libc::c_int as libc::c_uint;
            if current.offset(len as isize) > end {
                len = end.offset_from(current) as libc::c_long as libc::c_uint;
            }
            status = srtp_cipher_encrypt(c, current, &mut len);
            if status as u64 != 0 {
                return status;
            }
            current = current.offset(len as isize);
            if current == end {
                break;
            }
        }
        j = 0 as libc::c_int;
        while j < buflen as libc::c_int {
            if buffer0[j as usize] as libc::c_int != buffer1[j as usize] as libc::c_int {
                return srtp_err_status_algo_fail;
            }
            j += 1;
        }
        i += 1;
    }
    printf(b"passed\n\0" as *const u8 as *const libc::c_char);
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn cipher_array_alloc_init(
    mut ca: *mut *mut *mut srtp_cipher_t,
    mut num_ciphers: libc::c_int,
    mut ctype: *mut srtp_cipher_type_t,
    mut klen: libc::c_int,
) -> srtp_err_status_t {
    let mut i: libc::c_int = 0;
    let mut j: libc::c_int = 0;
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut key: *mut uint8_t = 0 as *mut uint8_t;
    let mut cipher_array: *mut *mut srtp_cipher_t = 0 as *mut *mut srtp_cipher_t;
    let mut klen_pad: libc::c_int = (klen + 15 as libc::c_int >> 4 as libc::c_int)
        << 4 as libc::c_int;
    cipher_array = srtp_crypto_alloc(
        (::core::mem::size_of::<*mut srtp_cipher_t>() as libc::c_ulong)
            .wrapping_mul(num_ciphers as libc::c_ulong),
    ) as *mut *mut srtp_cipher_t;
    if cipher_array.is_null() {
        return srtp_err_status_alloc_fail;
    }
    *ca = cipher_array;
    key = srtp_crypto_alloc(klen_pad as size_t) as *mut uint8_t;
    if key.is_null() {
        srtp_crypto_free(cipher_array as *mut libc::c_void);
        return srtp_err_status_alloc_fail;
    }
    i = 0 as libc::c_int;
    while i < num_ciphers {
        status = srtp_cipher_type_alloc(ctype, cipher_array, klen, 16 as libc::c_int);
        if status as u64 != 0 {
            return status;
        }
        srtp_cipher_rand_for_tests(key as *mut libc::c_void, klen as uint32_t);
        j = klen;
        while j < klen_pad {
            *key.offset(j as isize) = 0 as libc::c_int as uint8_t;
            j += 1;
        }
        status = srtp_cipher_init(*cipher_array, key);
        if status as u64 != 0 {
            return status;
        }
        cipher_array = cipher_array.offset(1);
        i += 1;
    }
    srtp_crypto_free(key as *mut libc::c_void);
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn cipher_array_delete(
    mut cipher_array: *mut *mut srtp_cipher_t,
    mut num_cipher: libc::c_int,
) -> srtp_err_status_t {
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < num_cipher {
        srtp_cipher_dealloc(*cipher_array.offset(i as isize));
        i += 1;
    }
    srtp_crypto_free(cipher_array as *mut libc::c_void);
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn cipher_array_bits_per_second(
    mut cipher_array: *mut *mut srtp_cipher_t,
    mut num_cipher: libc::c_int,
    mut octets_in_buffer: libc::c_uint,
    mut num_trials: libc::c_int,
) -> uint64_t {
    let mut i: libc::c_int = 0;
    let mut nonce: v128_t = v128_t { v8: [0; 16] };
    let mut timer: clock_t = 0;
    let mut enc_buf: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut cipher_index: libc::c_int = (srtp_cipher_rand_u32_for_tests())
        .wrapping_rem(num_cipher as libc::c_uint) as libc::c_int;
    enc_buf = srtp_crypto_alloc(
        octets_in_buffer.wrapping_add(17 as libc::c_int as libc::c_uint) as size_t,
    ) as *mut libc::c_uchar;
    if enc_buf.is_null() {
        return 0 as libc::c_int as uint64_t;
    }
    nonce.v32[0 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    nonce.v32[1 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    nonce.v32[2 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    nonce.v32[3 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    timer = clock();
    i = 0 as libc::c_int;
    while i < num_trials {
        let mut octets_to_encrypt: libc::c_uint = octets_in_buffer;
        srtp_cipher_set_iv(
            *cipher_array.offset(cipher_index as isize),
            &mut nonce as *mut v128_t as *mut uint8_t,
            srtp_direction_encrypt as libc::c_int,
        );
        srtp_cipher_encrypt(
            *cipher_array.offset(cipher_index as isize),
            enc_buf,
            &mut octets_to_encrypt,
        );
        cipher_index = (*(enc_buf as *mut uint32_t))
            .wrapping_rem(num_cipher as libc::c_uint) as libc::c_int;
        i += 1;
        nonce.v32[3 as libc::c_int as usize] = i as uint32_t;
    }
    timer = clock() - timer;
    srtp_crypto_free(enc_buf as *mut libc::c_void);
    if timer == 0 as libc::c_int as libc::c_long {
        return 0 as libc::c_int as uint64_t;
    }
    return (1000000 as libc::c_int as __clock_t as uint64_t)
        .wrapping_mul(num_trials as libc::c_ulong)
        .wrapping_mul(8 as libc::c_int as libc::c_ulong)
        .wrapping_mul(octets_in_buffer as libc::c_ulong)
        .wrapping_div(timer as libc::c_ulong);
}
#[no_mangle]
pub unsafe extern "C" fn cipher_array_test_throughput(
    mut ca: *mut *mut srtp_cipher_t,
    mut num_cipher: libc::c_int,
) {
    let mut i: libc::c_int = 0;
    let mut min_enc_len: libc::c_int = 16 as libc::c_int;
    let mut max_enc_len: libc::c_int = 2048 as libc::c_int;
    let mut num_trials: libc::c_int = 1000000 as libc::c_int;
    printf(
        b"timing %s throughput with key length %d, array size %d:\n\0" as *const u8
            as *const libc::c_char,
        (*(**ca.offset(0 as libc::c_int as isize)).type_0).description,
        (**ca.offset(0 as libc::c_int as isize)).key_len,
        num_cipher,
    );
    fflush(stdout);
    i = min_enc_len;
    while i <= max_enc_len {
        printf(
            b"msg len: %d\tgigabits per second: %f\n\0" as *const u8
                as *const libc::c_char,
            i,
            cipher_array_bits_per_second(ca, num_cipher, i as libc::c_uint, num_trials)
                as libc::c_double / 1e9f64,
        );
        i = i * 4 as libc::c_int;
    }
}
#[no_mangle]
pub unsafe extern "C" fn cipher_driver_test_array_throughput(
    mut ct: *mut srtp_cipher_type_t,
    mut klen: libc::c_int,
    mut num_cipher: libc::c_int,
) -> srtp_err_status_t {
    let mut ca: *mut *mut srtp_cipher_t = 0 as *mut *mut srtp_cipher_t;
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    status = cipher_array_alloc_init(&mut ca, num_cipher, ct, klen);
    if status as u64 != 0 {
        printf(
            b"error: cipher_array_alloc_init() failed with error code %d\n\0"
                as *const u8 as *const libc::c_char,
            status as libc::c_uint,
        );
        return status;
    }
    cipher_array_test_throughput(ca, num_cipher);
    cipher_array_delete(ca, num_cipher);
    return srtp_err_status_ok;
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
