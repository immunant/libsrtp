#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
extern "C" {
    fn srtp_crypto_alloc(size: size_t) -> *mut libc::c_void;
    fn srtp_crypto_free(ptr: *mut libc::c_void);
    fn octet_string_set_to_zero(s: *mut libc::c_void, len: size_t);
    fn srtp_err_report(
        level: srtp_err_reporting_level_t,
        format: *const libc::c_char,
        _: ...
    );
    static mut srtp_mod_cipher: srtp_debug_module_t;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
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
unsafe extern "C" fn srtp_null_cipher_alloc(
    mut c: *mut *mut srtp_cipher_t,
    mut key_len: libc::c_int,
    mut tlen: libc::c_int,
) -> srtp_err_status_t {
    extern "C" {
        #[link_name = "srtp_null_cipher"]
        static srtp_null_cipher_0: srtp_cipher_type_t;
    }
    if srtp_mod_cipher.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: allocating cipher with key length %d\n\0" as *const u8
                as *const libc::c_char,
            srtp_mod_cipher.name,
            key_len,
        );
    }
    *c = srtp_crypto_alloc(::core::mem::size_of::<srtp_cipher_t>() as libc::c_ulong)
        as *mut srtp_cipher_t;
    if (*c).is_null() {
        return srtp_err_status_alloc_fail;
    }
    (**c).algorithm = 0 as libc::c_int;
    (**c).type_0 = &srtp_null_cipher;
    (**c).state = 0x1 as libc::c_int as *mut libc::c_void;
    (**c).key_len = key_len;
    return srtp_err_status_ok;
}
unsafe extern "C" fn srtp_null_cipher_dealloc(
    mut c: *mut srtp_cipher_t,
) -> srtp_err_status_t {
    extern "C" {
        #[link_name = "srtp_null_cipher"]
        static srtp_null_cipher_0: srtp_cipher_type_t;
    }
    octet_string_set_to_zero(
        c as *mut libc::c_void,
        ::core::mem::size_of::<srtp_cipher_t>() as libc::c_ulong,
    );
    srtp_crypto_free(c as *mut libc::c_void);
    return srtp_err_status_ok;
}
unsafe extern "C" fn srtp_null_cipher_init(
    mut cv: *mut libc::c_void,
    mut key: *const uint8_t,
) -> srtp_err_status_t {
    if srtp_mod_cipher.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: initializing null cipher\n\0" as *const u8 as *const libc::c_char,
            srtp_mod_cipher.name,
        );
    }
    return srtp_err_status_ok;
}
unsafe extern "C" fn srtp_null_cipher_set_iv(
    mut cv: *mut libc::c_void,
    mut iv: *mut uint8_t,
    mut dir: srtp_cipher_direction_t,
) -> srtp_err_status_t {
    return srtp_err_status_ok;
}
unsafe extern "C" fn srtp_null_cipher_encrypt(
    mut cv: *mut libc::c_void,
    mut buf: *mut libc::c_uchar,
    mut bytes_to_encr: *mut libc::c_uint,
) -> srtp_err_status_t {
    return srtp_err_status_ok;
}
static mut srtp_null_cipher_description: [libc::c_char; 12] = unsafe {
    *::core::mem::transmute::<&[u8; 12], &[libc::c_char; 12]>(b"null cipher\0")
};
static mut srtp_null_cipher_test_0: srtp_cipher_test_case_t = {
    let mut init = srtp_cipher_test_case_t {
        key_length_octets: 0 as libc::c_int,
        key: 0 as *const uint8_t,
        idx: 0 as *const uint8_t as *mut uint8_t,
        plaintext_length_octets: 0 as libc::c_int as libc::c_uint,
        plaintext: 0 as *const uint8_t,
        ciphertext_length_octets: 0 as libc::c_int as libc::c_uint,
        ciphertext: 0 as *const uint8_t,
        aad_length_octets: 0 as libc::c_int,
        aad: 0 as *const uint8_t,
        tag_length_octets: 0 as libc::c_int,
        next_test_case: 0 as *const srtp_cipher_test_case_t,
    };
    init
};
#[no_mangle]
pub static mut srtp_null_cipher: srtp_cipher_type_t = unsafe {
    {
        let mut init = srtp_cipher_type_t {
            alloc: Some(
                srtp_null_cipher_alloc
                    as unsafe extern "C" fn(
                        *mut *mut srtp_cipher_t,
                        libc::c_int,
                        libc::c_int,
                    ) -> srtp_err_status_t,
            ),
            dealloc: Some(
                srtp_null_cipher_dealloc
                    as unsafe extern "C" fn(*mut srtp_cipher_t) -> srtp_err_status_t,
            ),
            init: Some(
                srtp_null_cipher_init
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const uint8_t,
                    ) -> srtp_err_status_t,
            ),
            set_aad: None,
            encrypt: Some(
                srtp_null_cipher_encrypt
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *mut libc::c_uchar,
                        *mut libc::c_uint,
                    ) -> srtp_err_status_t,
            ),
            decrypt: Some(
                srtp_null_cipher_encrypt
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *mut libc::c_uchar,
                        *mut libc::c_uint,
                    ) -> srtp_err_status_t,
            ),
            set_iv: Some(
                srtp_null_cipher_set_iv
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *mut uint8_t,
                        srtp_cipher_direction_t,
                    ) -> srtp_err_status_t,
            ),
            get_tag: None,
            description: srtp_null_cipher_description.as_ptr(),
            test_data: &srtp_null_cipher_test_0 as *const srtp_cipher_test_case_t,
            id: 0 as libc::c_int as srtp_cipher_type_id_t,
        };
        init
    }
};
