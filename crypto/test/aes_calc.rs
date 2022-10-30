#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
#![feature(extern_types)]
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    static mut stderr: *mut FILE;
    fn fprintf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    fn srtp_aes_encrypt(plaintext: *mut v128_t, exp_key: *const srtp_aes_expanded_key_t);
    fn srtp_aes_expand_encryption_key(
        key: *const uint8_t,
        key_len: libc::c_int,
        expanded_key: *mut srtp_aes_expanded_key_t,
    ) -> srtp_err_status_t;
    fn exit(_: libc::c_int) -> !;
    fn strcmp(_: *const libc::c_char, _: *const libc::c_char) -> libc::c_int;
    fn strncmp(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn v128_hex_string(x: *mut v128_t) -> *mut libc::c_char;
    fn hex_string_to_octet_string(
        raw: *mut libc::c_char,
        hex: *mut libc::c_char,
        len: libc::c_int,
    ) -> libc::c_int;
    fn octet_string_hex_string(
        s: *const libc::c_void,
        length: libc::c_int,
    ) -> *mut libc::c_char;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
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
pub struct srtp_aes_expanded_key_t {
    pub round: [v128_t; 15],
    pub num_rounds: libc::c_int,
}
#[no_mangle]
pub unsafe extern "C" fn usage(mut prog_name: *mut libc::c_char) {
    printf(
        b"usage: %s <key> <plaintext> [<ciphertext>] [-v]\n\0" as *const u8
            as *const libc::c_char,
        prog_name,
    );
    exit(255 as libc::c_int);
}
unsafe fn main_0(
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut expected_ciphertext: *const libc::c_char = 0 as *const libc::c_char;
    let mut ciphertext: *const libc::c_char = 0 as *const libc::c_char;
    let mut data: v128_t = v128_t { v8: [0; 16] };
    let mut key: [uint8_t; 32] = [0; 32];
    let mut exp_key: srtp_aes_expanded_key_t = srtp_aes_expanded_key_t {
        round: [v128_t { v8: [0; 16] }; 15],
        num_rounds: 0,
    };
    let mut key_len: libc::c_int = 0;
    let mut len: libc::c_int = 0;
    let mut verbose: libc::c_int = 0 as libc::c_int;
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    if argc > 0 as libc::c_int
        && strncmp(
            *argv.offset((argc - 1 as libc::c_int) as isize),
            b"-v\0" as *const u8 as *const libc::c_char,
            2 as libc::c_int as libc::c_ulong,
        ) == 0 as libc::c_int
    {
        verbose = 1 as libc::c_int;
        argc -= 1;
    }
    if argc < 3 as libc::c_int || argc > 4 as libc::c_int {
        usage(*argv.offset(0 as libc::c_int as isize));
    }
    if argc == 4 as libc::c_int {
        expected_ciphertext = *argv.offset(3 as libc::c_int as isize);
        if strlen(expected_ciphertext)
            != (16 as libc::c_int * 2 as libc::c_int) as libc::c_ulong
        {
            usage(*argv.offset(0 as libc::c_int as isize));
        }
    }
    if strlen(*argv.offset(1 as libc::c_int as isize))
        > (32 as libc::c_int * 2 as libc::c_int) as libc::c_ulong
    {
        fprintf(
            stderr,
            b"error: too many digits in key (should be at most %d hexadecimal digits, found %u)\n\0"
                as *const u8 as *const libc::c_char,
            32 as libc::c_int * 2 as libc::c_int,
            strlen(*argv.offset(1 as libc::c_int as isize)) as libc::c_uint,
        );
        exit(1 as libc::c_int);
    }
    len = hex_string_to_octet_string(
        key.as_mut_ptr() as *mut libc::c_char,
        *argv.offset(1 as libc::c_int as isize),
        32 as libc::c_int * 2 as libc::c_int,
    );
    if len != 32 as libc::c_int && len != 48 as libc::c_int && len != 64 as libc::c_int {
        fprintf(
            stderr,
            b"error: bad number of digits in key (should be 32/48/64 hexadecimal digits, found %d)\n\0"
                as *const u8 as *const libc::c_char,
            len,
        );
        exit(1 as libc::c_int);
    }
    key_len = len / 2 as libc::c_int;
    if strlen(*argv.offset(2 as libc::c_int as isize))
        > (16 as libc::c_int * 2 as libc::c_int) as libc::c_ulong
    {
        fprintf(
            stderr,
            b"error: too many digits in plaintext (should be %d hexadecimal digits, found %u)\n\0"
                as *const u8 as *const libc::c_char,
            16 as libc::c_int * 2 as libc::c_int,
            strlen(*argv.offset(2 as libc::c_int as isize)) as libc::c_uint,
        );
        exit(1 as libc::c_int);
    }
    len = hex_string_to_octet_string(
        &mut data as *mut v128_t as *mut libc::c_char,
        *argv.offset(2 as libc::c_int as isize),
        16 as libc::c_int * 2 as libc::c_int,
    );
    if len < 16 as libc::c_int * 2 as libc::c_int {
        fprintf(
            stderr,
            b"error: too few digits in plaintext (should be %d hexadecimal digits, found %d)\n\0"
                as *const u8 as *const libc::c_char,
            16 as libc::c_int * 2 as libc::c_int,
            len,
        );
        exit(1 as libc::c_int);
    }
    if verbose != 0 {
        printf(
            b"plaintext:\t%s\n\0" as *const u8 as *const libc::c_char,
            octet_string_hex_string(
                &mut data as *mut v128_t as *mut uint8_t as *const libc::c_void,
                16 as libc::c_int,
            ),
        );
    }
    status = srtp_aes_expand_encryption_key(key.as_mut_ptr(), key_len, &mut exp_key);
    if status as u64 != 0 {
        fprintf(
            stderr,
            b"error: AES key expansion failed.\n\0" as *const u8 as *const libc::c_char,
        );
        exit(1 as libc::c_int);
    }
    srtp_aes_encrypt(&mut data, &mut exp_key);
    if verbose != 0 {
        printf(
            b"key:\t\t%s\n\0" as *const u8 as *const libc::c_char,
            octet_string_hex_string(key.as_mut_ptr() as *const libc::c_void, key_len),
        );
        printf(b"ciphertext:\t\0" as *const u8 as *const libc::c_char);
    }
    ciphertext = v128_hex_string(&mut data);
    printf(b"%s\n\0" as *const u8 as *const libc::c_char, ciphertext);
    if !expected_ciphertext.is_null()
        && strcmp(ciphertext, expected_ciphertext) != 0 as libc::c_int
    {
        fprintf(
            stderr,
            b"error: calculated ciphertext %s does not match expected ciphertext %s\n\0"
                as *const u8 as *const libc::c_char,
            ciphertext,
            expected_ciphertext,
        );
        exit(1 as libc::c_int);
    }
    return 0 as libc::c_int;
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
