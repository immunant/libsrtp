#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
extern "C" {
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    fn getopt_s(
        argc: libc::c_int,
        argv: *const *mut libc::c_char,
        optstring: *const libc::c_char,
    ) -> libc::c_int;
    static mut optarg_s: *mut libc::c_char;
    fn exit(_: libc::c_int) -> !;
    fn srtp_crypto_kernel_set_debug_module(
        mod_name: *const libc::c_char,
        v: libc::c_int,
    ) -> srtp_err_status_t;
    fn srtp_crypto_kernel_status() -> srtp_err_status_t;
    fn srtp_crypto_kernel_shutdown() -> srtp_err_status_t;
    fn srtp_crypto_kernel_init() -> srtp_err_status_t;
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
#[no_mangle]
pub unsafe extern "C" fn usage(mut prog_name: *mut libc::c_char) {
    printf(
        b"usage: %s [ -v ][ -d debug_module ]*\n\0" as *const u8 as *const libc::c_char,
        prog_name,
    );
    exit(255 as libc::c_int);
}
unsafe fn main_0(
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut q: libc::c_int = 0;
    let mut do_validation: libc::c_int = 0 as libc::c_int;
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    if argc == 1 as libc::c_int {
        usage(*argv.offset(0 as libc::c_int as isize));
    }
    status = srtp_crypto_kernel_init();
    if status as u64 != 0 {
        printf(
            b"error: srtp_crypto_kernel init failed\n\0" as *const u8
                as *const libc::c_char,
        );
        exit(1 as libc::c_int);
    }
    printf(
        b"srtp_crypto_kernel successfully initalized\n\0" as *const u8
            as *const libc::c_char,
    );
    loop {
        q = getopt_s(
            argc,
            argv as *const *mut libc::c_char,
            b"vd:\0" as *const u8 as *const libc::c_char,
        );
        if q == -(1 as libc::c_int) {
            break;
        }
        match q {
            118 => {
                do_validation = 1 as libc::c_int;
            }
            100 => {
                status = srtp_crypto_kernel_set_debug_module(optarg_s, 1 as libc::c_int);
                if status as u64 != 0 {
                    printf(
                        b"error: set debug module (%s) failed\n\0" as *const u8
                            as *const libc::c_char,
                        optarg_s,
                    );
                    exit(1 as libc::c_int);
                }
            }
            _ => {
                usage(*argv.offset(0 as libc::c_int as isize));
            }
        }
    }
    if do_validation != 0 {
        printf(
            b"checking srtp_crypto_kernel status...\n\0" as *const u8
                as *const libc::c_char,
        );
        status = srtp_crypto_kernel_status();
        if status as u64 != 0 {
            printf(b"failed\n\0" as *const u8 as *const libc::c_char);
            exit(1 as libc::c_int);
        }
        printf(
            b"srtp_crypto_kernel passed self-tests\n\0" as *const u8
                as *const libc::c_char,
        );
    }
    status = srtp_crypto_kernel_shutdown();
    if status as u64 != 0 {
        printf(
            b"error: srtp_crypto_kernel shutdown failed\n\0" as *const u8
                as *const libc::c_char,
        );
        exit(1 as libc::c_int);
    }
    printf(
        b"srtp_crypto_kernel successfully shut down\n\0" as *const u8
            as *const libc::c_char,
    );
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
