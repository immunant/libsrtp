extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn vfprintf(
        _: *mut FILE,
        _: *const libc::c_char,
        _: ::core::ffi::VaList,
    ) -> libc::c_int;
    fn vsnprintf(
        _: *mut libc::c_char,
        _: libc::c_ulong,
        _: *const libc::c_char,
        _: ::core::ffi::VaList,
    ) -> libc::c_int;
    fn octet_string_set_to_zero(s: *mut libc::c_void, len: size_t);
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
}
pub type __builtin_va_list = [__va_list_tag; 1];
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __va_list_tag {
    pub gp_offset: libc::c_uint,
    pub fp_offset: libc::c_uint,
    pub overflow_arg_area: *mut libc::c_void,
    pub reg_save_area: *mut libc::c_void,
}
pub type size_t = libc::c_ulong;
pub type va_list = __builtin_va_list;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
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
pub type srtp_err_reporting_level_t = libc::c_uint;
pub const srtp_err_level_debug: srtp_err_reporting_level_t = 3;
pub const srtp_err_level_info: srtp_err_reporting_level_t = 2;
pub const srtp_err_level_warning: srtp_err_reporting_level_t = 1;
pub const srtp_err_level_error: srtp_err_reporting_level_t = 0;
pub type srtp_err_report_handler_func_t = unsafe extern "C" fn(
    srtp_err_reporting_level_t,
    *const libc::c_char,
) -> ();
static mut srtp_err_file: *mut FILE = 0 as *const FILE as *mut FILE;
#[no_mangle]
pub unsafe extern "C" fn srtp_err_reporting_init() -> srtp_err_status_t {
    return srtp_err_status_ok;
}
static mut srtp_err_report_handler: Option::<srtp_err_report_handler_func_t> = None;
#[no_mangle]
pub unsafe extern "C" fn srtp_install_err_report_handler(
    mut func: Option::<srtp_err_report_handler_func_t>,
) -> srtp_err_status_t {
    srtp_err_report_handler = func;
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_err_report(
    mut level: srtp_err_reporting_level_t,
    mut format: *const libc::c_char,
    mut args: ...
) {
    let mut msg: [libc::c_char; 512] = [0; 512];
    let mut args_0: ::core::ffi::VaListImpl;
    if !srtp_err_file.is_null() {
        args_0 = args.clone();
        vfprintf(srtp_err_file, format, args_0.as_va_list());
    }
    if srtp_err_report_handler.is_some() {
        args_0 = args.clone();
        if vsnprintf(
            msg.as_mut_ptr(),
            ::core::mem::size_of::<[libc::c_char; 512]>() as libc::c_ulong,
            format,
            args_0.as_va_list(),
        ) > 0 as libc::c_int
        {
            let mut l: size_t = strlen(msg.as_mut_ptr());
            if l != 0
                && msg[l.wrapping_sub(1 as libc::c_int as libc::c_ulong) as usize]
                    as libc::c_int == '\n' as i32
            {
                msg[l.wrapping_sub(1 as libc::c_int as libc::c_ulong)
                    as usize] = '\0' as i32 as libc::c_char;
            }
            srtp_err_report_handler
                .expect("non-null function pointer")(level, msg.as_mut_ptr());
            octet_string_set_to_zero(
                msg.as_mut_ptr() as *mut libc::c_void,
                ::core::mem::size_of::<[libc::c_char; 512]>() as libc::c_ulong,
            );
        }
    }
}
