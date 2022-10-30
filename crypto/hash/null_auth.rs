#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
extern "C" {
    fn srtp_err_report(
        level: srtp_err_reporting_level_t,
        format: *const libc::c_char,
        _: ...
    );
    fn srtp_crypto_free(ptr: *mut libc::c_void);
    fn srtp_crypto_alloc(size: size_t) -> *mut libc::c_void;
    fn octet_string_set_to_zero(s: *mut libc::c_void, len: size_t);
    static mut srtp_mod_auth: srtp_debug_module_t;
}
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type srtp_auth_type_id_t = uint32_t;
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
pub struct srtp_auth_type_t {
    pub alloc: srtp_auth_alloc_func,
    pub dealloc: srtp_auth_dealloc_func,
    pub init: srtp_auth_init_func,
    pub compute: srtp_auth_compute_func,
    pub update: srtp_auth_update_func,
    pub start: srtp_auth_start_func,
    pub description: *const libc::c_char,
    pub test_data: *const srtp_auth_test_case_t,
    pub id: srtp_auth_type_id_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct srtp_auth_test_case_t {
    pub key_length_octets: libc::c_int,
    pub key: *const uint8_t,
    pub data_length_octets: libc::c_int,
    pub data: *const uint8_t,
    pub tag_length_octets: libc::c_int,
    pub tag: *const uint8_t,
    pub next_test_case: *const srtp_auth_test_case_t,
}
pub type srtp_auth_start_func = Option::<
    unsafe extern "C" fn(*mut libc::c_void) -> srtp_err_status_t,
>;
pub type srtp_auth_update_func = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const uint8_t,
        libc::c_int,
    ) -> srtp_err_status_t,
>;
pub type srtp_auth_compute_func = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const uint8_t,
        libc::c_int,
        libc::c_int,
        *mut uint8_t,
    ) -> srtp_err_status_t,
>;
pub type srtp_auth_init_func = Option::<
    unsafe extern "C" fn(
        *mut libc::c_void,
        *const uint8_t,
        libc::c_int,
    ) -> srtp_err_status_t,
>;
pub type srtp_auth_dealloc_func = Option::<
    unsafe extern "C" fn(srtp_auth_pointer_t) -> srtp_err_status_t,
>;
pub type srtp_auth_pointer_t = *mut srtp_auth_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct srtp_auth_t {
    pub type_0: *const srtp_auth_type_t,
    pub state: *mut libc::c_void,
    pub out_len: libc::c_int,
    pub key_len: libc::c_int,
    pub prefix_len: libc::c_int,
}
pub type srtp_auth_alloc_func = Option::<
    unsafe extern "C" fn(
        *mut srtp_auth_pointer_t,
        libc::c_int,
        libc::c_int,
    ) -> srtp_err_status_t,
>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct srtp_null_auth_ctx_t {
    pub foo: libc::c_char,
}
pub type size_t = libc::c_ulong;
pub type srtp_err_reporting_level_t = libc::c_uint;
pub const srtp_err_level_debug: srtp_err_reporting_level_t = 3;
pub const srtp_err_level_info: srtp_err_reporting_level_t = 2;
pub const srtp_err_level_warning: srtp_err_reporting_level_t = 1;
pub const srtp_err_level_error: srtp_err_reporting_level_t = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct srtp_debug_module_t {
    pub on: libc::c_int,
    pub name: *const libc::c_char,
}
unsafe extern "C" fn srtp_null_auth_alloc(
    mut a: *mut *mut srtp_auth_t,
    mut key_len: libc::c_int,
    mut out_len: libc::c_int,
) -> srtp_err_status_t {
    extern "C" {
        #[link_name = "srtp_null_auth"]
        static srtp_null_auth_0: srtp_auth_type_t;
    }
    let mut pointer: *mut uint8_t = 0 as *mut uint8_t;
    if srtp_mod_auth.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: allocating auth func with key length %d\n\0" as *const u8
                as *const libc::c_char,
            srtp_mod_auth.name,
            key_len,
        );
    }
    if srtp_mod_auth.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s:                           tag length %d\n\0" as *const u8
                as *const libc::c_char,
            srtp_mod_auth.name,
            out_len,
        );
    }
    pointer = srtp_crypto_alloc(
        (::core::mem::size_of::<srtp_null_auth_ctx_t>() as libc::c_ulong)
            .wrapping_add(::core::mem::size_of::<srtp_auth_t>() as libc::c_ulong),
    ) as *mut uint8_t;
    if pointer.is_null() {
        return srtp_err_status_alloc_fail;
    }
    *a = pointer as *mut srtp_auth_t;
    (**a).type_0 = &srtp_null_auth;
    (**a)
        .state = pointer
        .offset(::core::mem::size_of::<srtp_auth_t>() as libc::c_ulong as isize)
        as *mut libc::c_void;
    (**a).out_len = out_len;
    (**a).prefix_len = out_len;
    (**a).key_len = key_len;
    return srtp_err_status_ok;
}
unsafe extern "C" fn srtp_null_auth_dealloc(
    mut a: *mut srtp_auth_t,
) -> srtp_err_status_t {
    extern "C" {
        #[link_name = "srtp_null_auth"]
        static srtp_null_auth_0: srtp_auth_type_t;
    }
    octet_string_set_to_zero(
        a as *mut libc::c_void,
        (::core::mem::size_of::<srtp_null_auth_ctx_t>() as libc::c_ulong)
            .wrapping_add(::core::mem::size_of::<srtp_auth_t>() as libc::c_ulong),
    );
    srtp_crypto_free(a as *mut libc::c_void);
    return srtp_err_status_ok;
}
unsafe extern "C" fn srtp_null_auth_init(
    mut statev: *mut libc::c_void,
    mut key: *const uint8_t,
    mut key_len: libc::c_int,
) -> srtp_err_status_t {
    return srtp_err_status_ok;
}
unsafe extern "C" fn srtp_null_auth_compute(
    mut statev: *mut libc::c_void,
    mut message: *const uint8_t,
    mut msg_octets: libc::c_int,
    mut tag_len: libc::c_int,
    mut result: *mut uint8_t,
) -> srtp_err_status_t {
    return srtp_err_status_ok;
}
unsafe extern "C" fn srtp_null_auth_update(
    mut statev: *mut libc::c_void,
    mut message: *const uint8_t,
    mut msg_octets: libc::c_int,
) -> srtp_err_status_t {
    return srtp_err_status_ok;
}
unsafe extern "C" fn srtp_null_auth_start(
    mut statev: *mut libc::c_void,
) -> srtp_err_status_t {
    return srtp_err_status_ok;
}
static mut srtp_null_auth_test_case_0: srtp_auth_test_case_t = {
    let mut init = srtp_auth_test_case_t {
        key_length_octets: 0 as libc::c_int,
        key: 0 as *const uint8_t,
        data_length_octets: 0 as libc::c_int,
        data: 0 as *const uint8_t,
        tag_length_octets: 0 as libc::c_int,
        tag: 0 as *const uint8_t,
        next_test_case: 0 as *const srtp_auth_test_case_t,
    };
    init
};
static mut srtp_null_auth_description: [libc::c_char; 29] = unsafe {
    *::core::mem::transmute::<
        &[u8; 29],
        &[libc::c_char; 29],
    >(b"null authentication function\0")
};
#[no_mangle]
pub static mut srtp_null_auth: srtp_auth_type_t = unsafe {
    {
        let mut init = srtp_auth_type_t {
            alloc: Some(
                srtp_null_auth_alloc
                    as unsafe extern "C" fn(
                        *mut *mut srtp_auth_t,
                        libc::c_int,
                        libc::c_int,
                    ) -> srtp_err_status_t,
            ),
            dealloc: Some(
                srtp_null_auth_dealloc
                    as unsafe extern "C" fn(*mut srtp_auth_t) -> srtp_err_status_t,
            ),
            init: Some(
                srtp_null_auth_init
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const uint8_t,
                        libc::c_int,
                    ) -> srtp_err_status_t,
            ),
            compute: Some(
                srtp_null_auth_compute
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const uint8_t,
                        libc::c_int,
                        libc::c_int,
                        *mut uint8_t,
                    ) -> srtp_err_status_t,
            ),
            update: Some(
                srtp_null_auth_update
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const uint8_t,
                        libc::c_int,
                    ) -> srtp_err_status_t,
            ),
            start: Some(
                srtp_null_auth_start
                    as unsafe extern "C" fn(*mut libc::c_void) -> srtp_err_status_t,
            ),
            description: srtp_null_auth_description.as_ptr(),
            test_data: &srtp_null_auth_test_case_0 as *const srtp_auth_test_case_t,
            id: 0 as libc::c_int as srtp_auth_type_id_t,
        };
        init
    }
};
