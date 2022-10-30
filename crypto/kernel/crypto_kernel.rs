#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
extern "C" {
    fn srtp_crypto_free(ptr: *mut libc::c_void);
    fn srtp_crypto_alloc(size: size_t) -> *mut libc::c_void;
    fn exit(_: libc::c_int) -> !;
    fn strncmp(
        _: *const libc::c_char,
        _: *const libc::c_char,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn srtp_cipher_type_self_test(ct: *const srtp_cipher_type_t) -> srtp_err_status_t;
    fn srtp_cipher_type_test(
        ct: *const srtp_cipher_type_t,
        test_data: *const srtp_cipher_test_case_t,
    ) -> srtp_err_status_t;
    fn srtp_err_reporting_init() -> srtp_err_status_t;
    fn srtp_err_report(
        level: srtp_err_reporting_level_t,
        format: *const libc::c_char,
        _: ...
    );
    fn srtp_auth_type_self_test(at: *const srtp_auth_type_t) -> srtp_err_status_t;
    fn srtp_auth_type_test(
        at: *const srtp_auth_type_t,
        test_data: *const srtp_auth_test_case_t,
    ) -> srtp_err_status_t;
    static srtp_null_cipher: srtp_cipher_type_t;
    static srtp_aes_icm_128: srtp_cipher_type_t;
    static srtp_aes_icm_256: srtp_cipher_type_t;
    static srtp_null_auth: srtp_auth_type_t;
    static srtp_hmac: srtp_auth_type_t;
    static mut srtp_mod_auth: srtp_debug_module_t;
    static mut srtp_mod_cipher: srtp_debug_module_t;
    static mut srtp_mod_alloc: srtp_debug_module_t;
    static mut srtp_mod_aes_icm: srtp_debug_module_t;
    static mut srtp_mod_hmac: srtp_debug_module_t;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
pub type srtp_cipher_type_id_t = uint32_t;
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
pub type srtp_kernel_cipher_type_t = srtp_kernel_cipher_type;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct srtp_kernel_cipher_type {
    pub id: srtp_cipher_type_id_t,
    pub cipher_type: *const srtp_cipher_type_t,
    pub next: *mut srtp_kernel_cipher_type,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct srtp_crypto_kernel_t {
    pub state: srtp_crypto_kernel_state_t,
    pub cipher_type_list: *mut srtp_kernel_cipher_type_t,
    pub auth_type_list: *mut srtp_kernel_auth_type_t,
    pub debug_module_list: *mut srtp_kernel_debug_module_t,
}
pub type srtp_kernel_debug_module_t = srtp_kernel_debug_module;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct srtp_kernel_debug_module {
    pub mod_0: *mut srtp_debug_module_t,
    pub next: *mut srtp_kernel_debug_module,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct srtp_debug_module_t {
    pub on: libc::c_int,
    pub name: *const libc::c_char,
}
pub type srtp_kernel_auth_type_t = srtp_kernel_auth_type;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct srtp_kernel_auth_type {
    pub id: srtp_auth_type_id_t,
    pub auth_type: *const srtp_auth_type_t,
    pub next: *mut srtp_kernel_auth_type,
}
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
pub type srtp_crypto_kernel_state_t = libc::c_uint;
pub const srtp_crypto_kernel_state_secure: srtp_crypto_kernel_state_t = 1;
pub const srtp_crypto_kernel_state_insecure: srtp_crypto_kernel_state_t = 0;
pub type srtp_err_reporting_level_t = libc::c_uint;
pub const srtp_err_level_debug: srtp_err_reporting_level_t = 3;
pub const srtp_err_level_info: srtp_err_reporting_level_t = 2;
pub const srtp_err_level_warning: srtp_err_reporting_level_t = 1;
pub const srtp_err_level_error: srtp_err_reporting_level_t = 0;
#[no_mangle]
pub static mut srtp_mod_crypto_kernel: srtp_debug_module_t = {
    let mut init = srtp_debug_module_t {
        on: 0 as libc::c_int,
        name: b"crypto kernel\0" as *const u8 as *const libc::c_char,
    };
    init
};
#[no_mangle]
pub static mut crypto_kernel: srtp_crypto_kernel_t = {
    let mut init = srtp_crypto_kernel_t {
        state: srtp_crypto_kernel_state_insecure,
        cipher_type_list: 0 as *const srtp_kernel_cipher_type_t
            as *mut srtp_kernel_cipher_type_t,
        auth_type_list: 0 as *const srtp_kernel_auth_type_t
            as *mut srtp_kernel_auth_type_t,
        debug_module_list: 0 as *const srtp_kernel_debug_module_t
            as *mut srtp_kernel_debug_module_t,
    };
    init
};
#[no_mangle]
pub unsafe extern "C" fn srtp_crypto_kernel_init() -> srtp_err_status_t {
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    if crypto_kernel.state as libc::c_uint
        == srtp_crypto_kernel_state_secure as libc::c_int as libc::c_uint
    {
        return srtp_crypto_kernel_status();
    }
    status = srtp_err_reporting_init();
    if status as u64 != 0 {
        return status;
    }
    status = srtp_crypto_kernel_load_debug_module(&mut srtp_mod_crypto_kernel);
    if status as u64 != 0 {
        return status;
    }
    status = srtp_crypto_kernel_load_debug_module(&mut srtp_mod_auth);
    if status as u64 != 0 {
        return status;
    }
    status = srtp_crypto_kernel_load_debug_module(&mut srtp_mod_cipher);
    if status as u64 != 0 {
        return status;
    }
    status = srtp_crypto_kernel_load_debug_module(&mut srtp_mod_alloc);
    if status as u64 != 0 {
        return status;
    }
    status = srtp_crypto_kernel_load_cipher_type(
        &srtp_null_cipher,
        0 as libc::c_int as srtp_cipher_type_id_t,
    );
    if status as u64 != 0 {
        return status;
    }
    status = srtp_crypto_kernel_load_cipher_type(
        &srtp_aes_icm_128,
        1 as libc::c_int as srtp_cipher_type_id_t,
    );
    if status as u64 != 0 {
        return status;
    }
    status = srtp_crypto_kernel_load_cipher_type(
        &srtp_aes_icm_256,
        5 as libc::c_int as srtp_cipher_type_id_t,
    );
    if status as u64 != 0 {
        return status;
    }
    status = srtp_crypto_kernel_load_debug_module(&mut srtp_mod_aes_icm);
    if status as u64 != 0 {
        return status;
    }
    status = srtp_crypto_kernel_load_auth_type(
        &srtp_null_auth,
        0 as libc::c_int as srtp_auth_type_id_t,
    );
    if status as u64 != 0 {
        return status;
    }
    status = srtp_crypto_kernel_load_auth_type(
        &srtp_hmac,
        3 as libc::c_int as srtp_auth_type_id_t,
    );
    if status as u64 != 0 {
        return status;
    }
    status = srtp_crypto_kernel_load_debug_module(&mut srtp_mod_hmac);
    if status as u64 != 0 {
        return status;
    }
    crypto_kernel.state = srtp_crypto_kernel_state_secure;
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_crypto_kernel_status() -> srtp_err_status_t {
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut ctype: *mut srtp_kernel_cipher_type_t = crypto_kernel.cipher_type_list;
    let mut atype: *mut srtp_kernel_auth_type_t = crypto_kernel.auth_type_list;
    while !ctype.is_null() {
        srtp_err_report(
            srtp_err_level_info,
            b"cipher: %s\n\0" as *const u8 as *const libc::c_char,
            (*(*ctype).cipher_type).description,
        );
        srtp_err_report(
            srtp_err_level_info,
            b"  self-test: \0" as *const u8 as *const libc::c_char,
        );
        status = srtp_cipher_type_self_test((*ctype).cipher_type);
        if status as u64 != 0 {
            srtp_err_report(
                srtp_err_level_error,
                b"failed with error code %d\n\0" as *const u8 as *const libc::c_char,
                status as libc::c_uint,
            );
            exit(status as libc::c_int);
        }
        srtp_err_report(
            srtp_err_level_info,
            b"passed\n\0" as *const u8 as *const libc::c_char,
        );
        ctype = (*ctype).next;
    }
    while !atype.is_null() {
        srtp_err_report(
            srtp_err_level_info,
            b"auth func: %s\n\0" as *const u8 as *const libc::c_char,
            (*(*atype).auth_type).description,
        );
        srtp_err_report(
            srtp_err_level_info,
            b"  self-test: \0" as *const u8 as *const libc::c_char,
        );
        status = srtp_auth_type_self_test((*atype).auth_type);
        if status as u64 != 0 {
            srtp_err_report(
                srtp_err_level_error,
                b"failed with error code %d\n\0" as *const u8 as *const libc::c_char,
                status as libc::c_uint,
            );
            exit(status as libc::c_int);
        }
        srtp_err_report(
            srtp_err_level_info,
            b"passed\n\0" as *const u8 as *const libc::c_char,
        );
        atype = (*atype).next;
    }
    srtp_crypto_kernel_list_debug_modules();
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_crypto_kernel_list_debug_modules() -> srtp_err_status_t {
    let mut dm: *mut srtp_kernel_debug_module_t = crypto_kernel.debug_module_list;
    srtp_err_report(
        srtp_err_level_info,
        b"debug modules loaded:\n\0" as *const u8 as *const libc::c_char,
    );
    while !dm.is_null() {
        srtp_err_report(
            srtp_err_level_info,
            b"  %s \0" as *const u8 as *const libc::c_char,
            (*(*dm).mod_0).name,
        );
        if (*(*dm).mod_0).on != 0 {
            srtp_err_report(
                srtp_err_level_info,
                b"(on)\n\0" as *const u8 as *const libc::c_char,
            );
        } else {
            srtp_err_report(
                srtp_err_level_info,
                b"(off)\n\0" as *const u8 as *const libc::c_char,
            );
        }
        dm = (*dm).next;
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_crypto_kernel_shutdown() -> srtp_err_status_t {
    while !(crypto_kernel.cipher_type_list).is_null() {
        let mut ctype: *mut srtp_kernel_cipher_type_t = crypto_kernel.cipher_type_list;
        crypto_kernel.cipher_type_list = (*ctype).next;
        if srtp_mod_crypto_kernel.on != 0 {
            srtp_err_report(
                srtp_err_level_debug,
                b"%s: freeing memory for cipher %s\n\0" as *const u8
                    as *const libc::c_char,
                srtp_mod_crypto_kernel.name,
                (*(*ctype).cipher_type).description,
            );
        }
        srtp_crypto_free(ctype as *mut libc::c_void);
    }
    while !(crypto_kernel.auth_type_list).is_null() {
        let mut atype: *mut srtp_kernel_auth_type_t = crypto_kernel.auth_type_list;
        crypto_kernel.auth_type_list = (*atype).next;
        if srtp_mod_crypto_kernel.on != 0 {
            srtp_err_report(
                srtp_err_level_debug,
                b"%s: freeing memory for authentication %s\n\0" as *const u8
                    as *const libc::c_char,
                srtp_mod_crypto_kernel.name,
                (*(*atype).auth_type).description,
            );
        }
        srtp_crypto_free(atype as *mut libc::c_void);
    }
    while !(crypto_kernel.debug_module_list).is_null() {
        let mut kdm: *mut srtp_kernel_debug_module_t = crypto_kernel.debug_module_list;
        crypto_kernel.debug_module_list = (*kdm).next;
        if srtp_mod_crypto_kernel.on != 0 {
            srtp_err_report(
                srtp_err_level_debug,
                b"%s: freeing memory for debug module %s\n\0" as *const u8
                    as *const libc::c_char,
                srtp_mod_crypto_kernel.name,
                (*(*kdm).mod_0).name,
            );
        }
        srtp_crypto_free(kdm as *mut libc::c_void);
    }
    crypto_kernel.state = srtp_crypto_kernel_state_insecure;
    return srtp_err_status_ok;
}
#[inline]
unsafe extern "C" fn srtp_crypto_kernel_do_load_cipher_type(
    mut new_ct: *const srtp_cipher_type_t,
    mut id: srtp_cipher_type_id_t,
    mut replace: libc::c_int,
) -> srtp_err_status_t {
    let mut ctype: *mut srtp_kernel_cipher_type_t = 0 as *mut srtp_kernel_cipher_type_t;
    let mut new_ctype: *mut srtp_kernel_cipher_type_t = 0
        as *mut srtp_kernel_cipher_type_t;
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    if new_ct.is_null() {
        return srtp_err_status_bad_param;
    }
    if (*new_ct).id != id {
        return srtp_err_status_bad_param;
    }
    status = srtp_cipher_type_self_test(new_ct);
    if status as u64 != 0 {
        return status;
    }
    ctype = crypto_kernel.cipher_type_list;
    while !ctype.is_null() {
        if id == (*ctype).id {
            if replace == 0 {
                return srtp_err_status_bad_param;
            }
            status = srtp_cipher_type_test(new_ct, (*(*ctype).cipher_type).test_data);
            if status as u64 != 0 {
                return status;
            }
            new_ctype = ctype;
            break;
        } else {
            if new_ct == (*ctype).cipher_type {
                return srtp_err_status_bad_param;
            }
            ctype = (*ctype).next;
        }
    }
    if ctype.is_null() {
        new_ctype = srtp_crypto_alloc(
            ::core::mem::size_of::<srtp_kernel_cipher_type_t>() as libc::c_ulong,
        ) as *mut srtp_kernel_cipher_type_t;
        if new_ctype.is_null() {
            return srtp_err_status_alloc_fail;
        }
        (*new_ctype).next = crypto_kernel.cipher_type_list;
        crypto_kernel.cipher_type_list = new_ctype;
    }
    (*new_ctype).cipher_type = new_ct;
    (*new_ctype).id = id;
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_crypto_kernel_load_cipher_type(
    mut new_ct: *const srtp_cipher_type_t,
    mut id: srtp_cipher_type_id_t,
) -> srtp_err_status_t {
    return srtp_crypto_kernel_do_load_cipher_type(new_ct, id, 0 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn srtp_replace_cipher_type(
    mut new_ct: *const srtp_cipher_type_t,
    mut id: srtp_cipher_type_id_t,
) -> srtp_err_status_t {
    return srtp_crypto_kernel_do_load_cipher_type(new_ct, id, 1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn srtp_crypto_kernel_do_load_auth_type(
    mut new_at: *const srtp_auth_type_t,
    mut id: srtp_auth_type_id_t,
    mut replace: libc::c_int,
) -> srtp_err_status_t {
    let mut atype: *mut srtp_kernel_auth_type_t = 0 as *mut srtp_kernel_auth_type_t;
    let mut new_atype: *mut srtp_kernel_auth_type_t = 0 as *mut srtp_kernel_auth_type_t;
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    if new_at.is_null() {
        return srtp_err_status_bad_param;
    }
    if (*new_at).id != id {
        return srtp_err_status_bad_param;
    }
    status = srtp_auth_type_self_test(new_at);
    if status as u64 != 0 {
        return status;
    }
    atype = crypto_kernel.auth_type_list;
    while !atype.is_null() {
        if id == (*atype).id {
            if replace == 0 {
                return srtp_err_status_bad_param;
            }
            status = srtp_auth_type_test(new_at, (*(*atype).auth_type).test_data);
            if status as u64 != 0 {
                return status;
            }
            new_atype = atype;
            break;
        } else {
            if new_at == (*atype).auth_type {
                return srtp_err_status_bad_param;
            }
            atype = (*atype).next;
        }
    }
    if atype.is_null() {
        new_atype = srtp_crypto_alloc(
            ::core::mem::size_of::<srtp_kernel_auth_type_t>() as libc::c_ulong,
        ) as *mut srtp_kernel_auth_type_t;
        if new_atype.is_null() {
            return srtp_err_status_alloc_fail;
        }
        (*new_atype).next = crypto_kernel.auth_type_list;
        crypto_kernel.auth_type_list = new_atype;
    }
    (*new_atype).auth_type = new_at;
    (*new_atype).id = id;
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_crypto_kernel_load_auth_type(
    mut new_at: *const srtp_auth_type_t,
    mut id: srtp_auth_type_id_t,
) -> srtp_err_status_t {
    return srtp_crypto_kernel_do_load_auth_type(new_at, id, 0 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn srtp_replace_auth_type(
    mut new_at: *const srtp_auth_type_t,
    mut id: srtp_auth_type_id_t,
) -> srtp_err_status_t {
    return srtp_crypto_kernel_do_load_auth_type(new_at, id, 1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn srtp_crypto_kernel_get_cipher_type(
    mut id: srtp_cipher_type_id_t,
) -> *const srtp_cipher_type_t {
    let mut ctype: *mut srtp_kernel_cipher_type_t = 0 as *mut srtp_kernel_cipher_type_t;
    ctype = crypto_kernel.cipher_type_list;
    while !ctype.is_null() {
        if id == (*ctype).id {
            return (*ctype).cipher_type;
        }
        ctype = (*ctype).next;
    }
    return 0 as *const srtp_cipher_type_t;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_crypto_kernel_alloc_cipher(
    mut id: srtp_cipher_type_id_t,
    mut cp: *mut srtp_cipher_pointer_t,
    mut key_len: libc::c_int,
    mut tag_len: libc::c_int,
) -> srtp_err_status_t {
    let mut ct: *const srtp_cipher_type_t = 0 as *const srtp_cipher_type_t;
    if crypto_kernel.state as libc::c_uint
        != srtp_crypto_kernel_state_secure as libc::c_int as libc::c_uint
    {
        return srtp_err_status_init_fail;
    }
    ct = srtp_crypto_kernel_get_cipher_type(id);
    if ct.is_null() {
        return srtp_err_status_fail;
    }
    return ((*ct).alloc).expect("non-null function pointer")(cp, key_len, tag_len);
}
#[no_mangle]
pub unsafe extern "C" fn srtp_crypto_kernel_get_auth_type(
    mut id: srtp_auth_type_id_t,
) -> *const srtp_auth_type_t {
    let mut atype: *mut srtp_kernel_auth_type_t = 0 as *mut srtp_kernel_auth_type_t;
    atype = crypto_kernel.auth_type_list;
    while !atype.is_null() {
        if id == (*atype).id {
            return (*atype).auth_type;
        }
        atype = (*atype).next;
    }
    return 0 as *const srtp_auth_type_t;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_crypto_kernel_alloc_auth(
    mut id: srtp_auth_type_id_t,
    mut ap: *mut srtp_auth_pointer_t,
    mut key_len: libc::c_int,
    mut tag_len: libc::c_int,
) -> srtp_err_status_t {
    let mut at: *const srtp_auth_type_t = 0 as *const srtp_auth_type_t;
    if crypto_kernel.state as libc::c_uint
        != srtp_crypto_kernel_state_secure as libc::c_int as libc::c_uint
    {
        return srtp_err_status_init_fail;
    }
    at = srtp_crypto_kernel_get_auth_type(id);
    if at.is_null() {
        return srtp_err_status_fail;
    }
    return ((*at).alloc).expect("non-null function pointer")(ap, key_len, tag_len);
}
#[no_mangle]
pub unsafe extern "C" fn srtp_crypto_kernel_load_debug_module(
    mut new_dm: *mut srtp_debug_module_t,
) -> srtp_err_status_t {
    let mut kdm: *mut srtp_kernel_debug_module_t = 0 as *mut srtp_kernel_debug_module_t;
    let mut new: *mut srtp_kernel_debug_module_t = 0 as *mut srtp_kernel_debug_module_t;
    if new_dm.is_null() || ((*new_dm).name).is_null() {
        return srtp_err_status_bad_param;
    }
    kdm = crypto_kernel.debug_module_list;
    while !kdm.is_null() {
        if strncmp(
            (*new_dm).name,
            (*(*kdm).mod_0).name,
            64 as libc::c_int as libc::c_ulong,
        ) == 0 as libc::c_int
        {
            return srtp_err_status_bad_param;
        }
        kdm = (*kdm).next;
    }
    new = srtp_crypto_alloc(
        ::core::mem::size_of::<srtp_kernel_debug_module_t>() as libc::c_ulong,
    ) as *mut srtp_kernel_debug_module_t;
    if new.is_null() {
        return srtp_err_status_alloc_fail;
    }
    (*new).mod_0 = new_dm;
    (*new).next = crypto_kernel.debug_module_list;
    crypto_kernel.debug_module_list = new;
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_crypto_kernel_set_debug_module(
    mut name: *const libc::c_char,
    mut on: libc::c_int,
) -> srtp_err_status_t {
    let mut kdm: *mut srtp_kernel_debug_module_t = 0 as *mut srtp_kernel_debug_module_t;
    kdm = crypto_kernel.debug_module_list;
    while !kdm.is_null() {
        if strncmp(name, (*(*kdm).mod_0).name, 64 as libc::c_int as libc::c_ulong)
            == 0 as libc::c_int
        {
            (*(*kdm).mod_0).on = on;
            return srtp_err_status_ok;
        }
        kdm = (*kdm).next;
    }
    return srtp_err_status_fail;
}
