#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
extern "C" {
    fn srtp_err_report(
        level: srtp_err_reporting_level_t,
        format: *const libc::c_char,
        _: ...
    );
    fn srtp_sha1_final(ctx: *mut srtp_sha1_ctx_t, output: *mut uint32_t);
    fn srtp_sha1_update(
        ctx: *mut srtp_sha1_ctx_t,
        M: *const uint8_t,
        octets_in_msg: libc::c_int,
    );
    fn srtp_sha1_init(ctx: *mut srtp_sha1_ctx_t);
    fn octet_string_set_to_zero(s: *mut libc::c_void, len: size_t);
    fn srtp_octet_string_hex_string(
        str: *const libc::c_void,
        length: libc::c_int,
    ) -> *mut libc::c_char;
    fn srtp_crypto_alloc(size: size_t) -> *mut libc::c_void;
    fn srtp_crypto_free(ptr: *mut libc::c_void);
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    static srtp_hmac_test_case_0: srtp_auth_test_case_t;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct srtp_sha1_ctx_t {
    pub H: [uint32_t; 5],
    pub M: [uint32_t; 16],
    pub octets_in_buffer: libc::c_int,
    pub num_bits_in_msg: uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct srtp_hmac_ctx_t {
    pub opad: [uint8_t; 64],
    pub ctx: srtp_sha1_ctx_t,
    pub init_ctx: srtp_sha1_ctx_t,
}
#[no_mangle]
pub static mut srtp_mod_hmac: srtp_debug_module_t = {
    let mut init = srtp_debug_module_t {
        on: 0 as libc::c_int,
        name: b"hmac sha-1\0" as *const u8 as *const libc::c_char,
    };
    init
};
unsafe extern "C" fn srtp_hmac_alloc(
    mut a: *mut *mut srtp_auth_t,
    mut key_len: libc::c_int,
    mut out_len: libc::c_int,
) -> srtp_err_status_t {
    extern "C" {
        #[link_name = "srtp_hmac"]
        static srtp_hmac_0: srtp_auth_type_t;
    }
    let mut pointer: *mut uint8_t = 0 as *mut uint8_t;
    if srtp_mod_hmac.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: allocating auth func with key length %d\n\0" as *const u8
                as *const libc::c_char,
            srtp_mod_hmac.name,
            key_len,
        );
    }
    if srtp_mod_hmac.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s:                           tag length %d\n\0" as *const u8
                as *const libc::c_char,
            srtp_mod_hmac.name,
            out_len,
        );
    }
    if key_len > 20 as libc::c_int {
        return srtp_err_status_bad_param;
    }
    if out_len > 20 as libc::c_int {
        return srtp_err_status_bad_param;
    }
    pointer = srtp_crypto_alloc(
        (::core::mem::size_of::<srtp_hmac_ctx_t>() as libc::c_ulong)
            .wrapping_add(::core::mem::size_of::<srtp_auth_t>() as libc::c_ulong),
    ) as *mut uint8_t;
    if pointer.is_null() {
        return srtp_err_status_alloc_fail;
    }
    *a = pointer as *mut srtp_auth_t;
    (**a).type_0 = &srtp_hmac;
    (**a)
        .state = pointer
        .offset(::core::mem::size_of::<srtp_auth_t>() as libc::c_ulong as isize)
        as *mut libc::c_void;
    (**a).out_len = out_len;
    (**a).key_len = key_len;
    (**a).prefix_len = 0 as libc::c_int;
    return srtp_err_status_ok;
}
unsafe extern "C" fn srtp_hmac_dealloc(mut a: *mut srtp_auth_t) -> srtp_err_status_t {
    octet_string_set_to_zero(
        a as *mut libc::c_void,
        (::core::mem::size_of::<srtp_hmac_ctx_t>() as libc::c_ulong)
            .wrapping_add(::core::mem::size_of::<srtp_auth_t>() as libc::c_ulong),
    );
    srtp_crypto_free(a as *mut libc::c_void);
    return srtp_err_status_ok;
}
unsafe extern "C" fn srtp_hmac_init(
    mut statev: *mut libc::c_void,
    mut key: *const uint8_t,
    mut key_len: libc::c_int,
) -> srtp_err_status_t {
    let mut state: *mut srtp_hmac_ctx_t = statev as *mut srtp_hmac_ctx_t;
    let mut i: libc::c_int = 0;
    let mut ipad: [uint8_t; 64] = [0; 64];
    if key_len > 20 as libc::c_int {
        return srtp_err_status_bad_param;
    }
    i = 0 as libc::c_int;
    while i < key_len {
        ipad[i
            as usize] = (*key.offset(i as isize) as libc::c_int ^ 0x36 as libc::c_int)
            as uint8_t;
        (*state)
            .opad[i
            as usize] = (*key.offset(i as isize) as libc::c_int ^ 0x5c as libc::c_int)
            as uint8_t;
        i += 1;
    }
    while i < 64 as libc::c_int {
        ipad[i as usize] = 0x36 as libc::c_int as uint8_t;
        *((*state).opad)
            .as_mut_ptr()
            .offset(i as isize) = 0x5c as libc::c_int as uint8_t;
        i += 1;
    }
    if srtp_mod_hmac.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: ipad: %s\n\0" as *const u8 as *const libc::c_char,
            srtp_mod_hmac.name,
            srtp_octet_string_hex_string(
                ipad.as_mut_ptr() as *const libc::c_void,
                64 as libc::c_int,
            ),
        );
    }
    srtp_sha1_init(&mut (*state).init_ctx);
    srtp_sha1_update(&mut (*state).init_ctx, ipad.as_mut_ptr(), 64 as libc::c_int);
    memcpy(
        &mut (*state).ctx as *mut srtp_sha1_ctx_t as *mut libc::c_void,
        &mut (*state).init_ctx as *mut srtp_sha1_ctx_t as *const libc::c_void,
        ::core::mem::size_of::<srtp_sha1_ctx_t>() as libc::c_ulong,
    );
    return srtp_err_status_ok;
}
unsafe extern "C" fn srtp_hmac_start(
    mut statev: *mut libc::c_void,
) -> srtp_err_status_t {
    let mut state: *mut srtp_hmac_ctx_t = statev as *mut srtp_hmac_ctx_t;
    memcpy(
        &mut (*state).ctx as *mut srtp_sha1_ctx_t as *mut libc::c_void,
        &mut (*state).init_ctx as *mut srtp_sha1_ctx_t as *const libc::c_void,
        ::core::mem::size_of::<srtp_sha1_ctx_t>() as libc::c_ulong,
    );
    return srtp_err_status_ok;
}
unsafe extern "C" fn srtp_hmac_update(
    mut statev: *mut libc::c_void,
    mut message: *const uint8_t,
    mut msg_octets: libc::c_int,
) -> srtp_err_status_t {
    let mut state: *mut srtp_hmac_ctx_t = statev as *mut srtp_hmac_ctx_t;
    if srtp_mod_hmac.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: input: %s\n\0" as *const u8 as *const libc::c_char,
            srtp_mod_hmac.name,
            srtp_octet_string_hex_string(message as *const libc::c_void, msg_octets),
        );
    }
    srtp_sha1_update(&mut (*state).ctx, message, msg_octets);
    return srtp_err_status_ok;
}
unsafe extern "C" fn srtp_hmac_compute(
    mut statev: *mut libc::c_void,
    mut message: *const uint8_t,
    mut msg_octets: libc::c_int,
    mut tag_len: libc::c_int,
    mut result: *mut uint8_t,
) -> srtp_err_status_t {
    let mut state: *mut srtp_hmac_ctx_t = statev as *mut srtp_hmac_ctx_t;
    let mut hash_value: [uint32_t; 5] = [0; 5];
    let mut H: [uint32_t; 5] = [0; 5];
    let mut i: libc::c_int = 0;
    if tag_len > 20 as libc::c_int {
        return srtp_err_status_bad_param;
    }
    srtp_hmac_update(state as *mut libc::c_void, message, msg_octets);
    srtp_sha1_final(&mut (*state).ctx, H.as_mut_ptr());
    if srtp_mod_hmac.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: intermediate state: %s\n\0" as *const u8 as *const libc::c_char,
            srtp_mod_hmac.name,
            srtp_octet_string_hex_string(
                H.as_mut_ptr() as *mut uint8_t as *const libc::c_void,
                20 as libc::c_int,
            ),
        );
    }
    srtp_sha1_init(&mut (*state).ctx);
    srtp_sha1_update(&mut (*state).ctx, ((*state).opad).as_mut_ptr(), 64 as libc::c_int);
    srtp_sha1_update(
        &mut (*state).ctx,
        H.as_mut_ptr() as *mut uint8_t,
        20 as libc::c_int,
    );
    srtp_sha1_final(&mut (*state).ctx, hash_value.as_mut_ptr());
    i = 0 as libc::c_int;
    while i < tag_len {
        *result
            .offset(
                i as isize,
            ) = *(hash_value.as_mut_ptr() as *mut uint8_t).offset(i as isize);
        i += 1;
    }
    if srtp_mod_hmac.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: output: %s\n\0" as *const u8 as *const libc::c_char,
            srtp_mod_hmac.name,
            srtp_octet_string_hex_string(
                hash_value.as_mut_ptr() as *mut uint8_t as *const libc::c_void,
                tag_len,
            ),
        );
    }
    return srtp_err_status_ok;
}
static mut srtp_hmac_description: [libc::c_char; 35] = unsafe {
    *::core::mem::transmute::<
        &[u8; 35],
        &[libc::c_char; 35],
    >(b"hmac sha-1 authentication function\0")
};
#[no_mangle]
pub static mut srtp_hmac: srtp_auth_type_t = unsafe {
    {
        let mut init = srtp_auth_type_t {
            alloc: Some(
                srtp_hmac_alloc
                    as unsafe extern "C" fn(
                        *mut *mut srtp_auth_t,
                        libc::c_int,
                        libc::c_int,
                    ) -> srtp_err_status_t,
            ),
            dealloc: Some(
                srtp_hmac_dealloc
                    as unsafe extern "C" fn(*mut srtp_auth_t) -> srtp_err_status_t,
            ),
            init: Some(
                srtp_hmac_init
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const uint8_t,
                        libc::c_int,
                    ) -> srtp_err_status_t,
            ),
            compute: Some(
                srtp_hmac_compute
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const uint8_t,
                        libc::c_int,
                        libc::c_int,
                        *mut uint8_t,
                    ) -> srtp_err_status_t,
            ),
            update: Some(
                srtp_hmac_update
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const uint8_t,
                        libc::c_int,
                    ) -> srtp_err_status_t,
            ),
            start: Some(
                srtp_hmac_start
                    as unsafe extern "C" fn(*mut libc::c_void) -> srtp_err_status_t,
            ),
            description: srtp_hmac_description.as_ptr(),
            test_data: &srtp_hmac_test_case_0 as *const srtp_auth_test_case_t,
            id: 3 as libc::c_int as srtp_auth_type_id_t,
        };
        init
    }
};
