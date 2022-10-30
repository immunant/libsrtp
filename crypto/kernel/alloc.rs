#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
extern "C" {
    fn calloc(_: libc::c_ulong, _: libc::c_ulong) -> *mut libc::c_void;
    fn free(_: *mut libc::c_void);
    fn srtp_err_report(
        level: srtp_err_reporting_level_t,
        format: *const libc::c_char,
        _: ...
    );
}
pub type size_t = libc::c_ulong;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct srtp_debug_module_t {
    pub on: libc::c_int,
    pub name: *const libc::c_char,
}
pub type srtp_err_reporting_level_t = libc::c_uint;
pub const srtp_err_level_debug: srtp_err_reporting_level_t = 3;
pub const srtp_err_level_info: srtp_err_reporting_level_t = 2;
pub const srtp_err_level_warning: srtp_err_reporting_level_t = 1;
pub const srtp_err_level_error: srtp_err_reporting_level_t = 0;
#[no_mangle]
pub static mut srtp_mod_alloc: srtp_debug_module_t = {
    let mut init = srtp_debug_module_t {
        on: 0 as libc::c_int,
        name: b"alloc\0" as *const u8 as *const libc::c_char,
    };
    init
};
#[no_mangle]
pub unsafe extern "C" fn srtp_crypto_alloc(mut size: size_t) -> *mut libc::c_void {
    let mut ptr: *mut libc::c_void = 0 as *mut libc::c_void;
    if size == 0 {
        return 0 as *mut libc::c_void;
    }
    ptr = calloc(1 as libc::c_int as libc::c_ulong, size);
    if !ptr.is_null() {
        if srtp_mod_alloc.on != 0 {
            srtp_err_report(
                srtp_err_level_debug,
                b"%s: (location: %p) allocated\n\0" as *const u8 as *const libc::c_char,
                srtp_mod_alloc.name,
                ptr,
            );
        }
    } else if srtp_mod_alloc.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: allocation failed (asked for %zu bytes)\n\n\0" as *const u8
                as *const libc::c_char,
            srtp_mod_alloc.name,
            size,
        );
    }
    return ptr;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_crypto_free(mut ptr: *mut libc::c_void) {
    if srtp_mod_alloc.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: (location: %p) freed\n\0" as *const u8 as *const libc::c_char,
            srtp_mod_alloc.name,
            ptr,
        );
    }
    free(ptr);
}
