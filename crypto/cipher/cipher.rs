#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
use crate::v128_t;
extern "C" {
    fn srtp_err_report(
        level: srtp_err_reporting_level_t,
        format: *const libc::c_char,
        _: ...
    );
    fn srtp_octet_string_hex_string(
        str: *const libc::c_void,
        length: libc::c_int,
    ) -> *mut libc::c_char;
    fn octet_string_set_to_zero(s: *mut libc::c_void, len: size_t);
    fn rand() -> libc::c_int;
    fn srtp_crypto_alloc(size: size_t) -> *mut libc::c_void;
    fn clock() -> clock_t;
    fn srtp_crypto_free(ptr: *mut libc::c_void);
}
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __clock_t = libc::c_long;
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
pub type clock_t = __clock_t;
pub type size_t = libc::c_ulong;
#[no_mangle]
pub static mut srtp_mod_cipher: srtp_debug_module_t = {
    let mut init = srtp_debug_module_t {
        on: 0 as libc::c_int,
        name: b"cipher\0" as *const u8 as *const libc::c_char,
    };
    init
};
#[no_mangle]
pub unsafe extern "C" fn srtp_cipher_type_alloc(
    mut ct: *const srtp_cipher_type_t,
    mut c: *mut *mut srtp_cipher_t,
    mut key_len: libc::c_int,
    mut tlen: libc::c_int,
) -> srtp_err_status_t {
    if ct.is_null() || ((*ct).alloc).is_none() {
        return srtp_err_status_bad_param;
    }
    return ((*ct).alloc).expect("non-null function pointer")(c, key_len, tlen);
}
#[no_mangle]
pub unsafe extern "C" fn srtp_cipher_dealloc(
    mut c: *mut srtp_cipher_t,
) -> srtp_err_status_t {
    if c.is_null() || ((*c).type_0).is_null() {
        return srtp_err_status_bad_param;
    }
    return ((*(*c).type_0).dealloc).expect("non-null function pointer")(c);
}
#[no_mangle]
pub unsafe extern "C" fn srtp_cipher_init(
    mut c: *mut srtp_cipher_t,
    mut key: *const uint8_t,
) -> srtp_err_status_t {
    if c.is_null() || ((*c).type_0).is_null() || ((*c).state).is_null() {
        return srtp_err_status_bad_param;
    }
    return ((*(*c).type_0).init).expect("non-null function pointer")((*c).state, key);
}
#[no_mangle]
pub unsafe extern "C" fn srtp_cipher_set_iv(
    mut c: *mut srtp_cipher_t,
    mut iv: *mut uint8_t,
    mut direction: libc::c_int,
) -> srtp_err_status_t {
    if c.is_null() || ((*c).type_0).is_null() || ((*c).state).is_null() {
        return srtp_err_status_bad_param;
    }
    return ((*(*c).type_0).set_iv)
        .expect(
            "non-null function pointer",
        )((*c).state, iv, direction as srtp_cipher_direction_t);
}
#[no_mangle]
pub unsafe extern "C" fn srtp_cipher_output(
    mut c: *mut srtp_cipher_t,
    mut buffer: *mut uint8_t,
    mut num_octets_to_output: *mut uint32_t,
) -> srtp_err_status_t {
    octet_string_set_to_zero(
        buffer as *mut libc::c_void,
        *num_octets_to_output as size_t,
    );
    return ((*(*c).type_0).encrypt)
        .expect("non-null function pointer")((*c).state, buffer, num_octets_to_output);
}
#[no_mangle]
pub unsafe extern "C" fn srtp_cipher_encrypt(
    mut c: *mut srtp_cipher_t,
    mut buffer: *mut uint8_t,
    mut num_octets_to_output: *mut uint32_t,
) -> srtp_err_status_t {
    if c.is_null() || ((*c).type_0).is_null() || ((*c).state).is_null() {
        return srtp_err_status_bad_param;
    }
    return ((*(*c).type_0).encrypt)
        .expect("non-null function pointer")((*c).state, buffer, num_octets_to_output);
}
#[no_mangle]
pub unsafe extern "C" fn srtp_cipher_decrypt(
    mut c: *mut srtp_cipher_t,
    mut buffer: *mut uint8_t,
    mut num_octets_to_output: *mut uint32_t,
) -> srtp_err_status_t {
    if c.is_null() || ((*c).type_0).is_null() || ((*c).state).is_null() {
        return srtp_err_status_bad_param;
    }
    return ((*(*c).type_0).decrypt)
        .expect("non-null function pointer")((*c).state, buffer, num_octets_to_output);
}
#[no_mangle]
pub unsafe extern "C" fn srtp_cipher_get_tag(
    mut c: *mut srtp_cipher_t,
    mut buffer: *mut uint8_t,
    mut tag_len: *mut uint32_t,
) -> srtp_err_status_t {
    if c.is_null() || ((*c).type_0).is_null() || ((*c).state).is_null() {
        return srtp_err_status_bad_param;
    }
    if ((*(*c).type_0).get_tag).is_none() {
        return srtp_err_status_no_such_op;
    }
    return ((*(*c).type_0).get_tag)
        .expect("non-null function pointer")((*c).state, buffer, tag_len);
}
#[no_mangle]
pub unsafe extern "C" fn srtp_cipher_set_aad(
    mut c: *mut srtp_cipher_t,
    mut aad: *const uint8_t,
    mut aad_len: uint32_t,
) -> srtp_err_status_t {
    if c.is_null() || ((*c).type_0).is_null() || ((*c).state).is_null() {
        return srtp_err_status_bad_param;
    }
    if ((*(*c).type_0).set_aad).is_none() {
        return srtp_err_status_no_such_op;
    }
    return ((*(*c).type_0).set_aad)
        .expect("non-null function pointer")((*c).state, aad, aad_len);
}
#[no_mangle]
pub unsafe extern "C" fn srtp_cipher_get_key_length(
    mut c: *const srtp_cipher_t,
) -> libc::c_int {
    return (*c).key_len;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_cipher_rand_for_tests(
    mut dest: *mut libc::c_void,
    mut len: uint32_t,
) {
    let mut dst: *mut uint8_t = dest as *mut uint8_t;
    while len != 0 {
        let mut val: libc::c_int = rand();
        let fresh0 = dst;
        dst = dst.offset(1);
        *fresh0 = (val & 0xff as libc::c_int) as uint8_t;
        len = len.wrapping_sub(1);
    }
}
#[no_mangle]
pub unsafe extern "C" fn srtp_cipher_rand_u32_for_tests() -> uint32_t {
    let mut r: uint32_t = 0;
    srtp_cipher_rand_for_tests(
        &mut r as *mut uint32_t as *mut libc::c_void,
        ::core::mem::size_of::<uint32_t>() as libc::c_ulong as uint32_t,
    );
    return r;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_cipher_type_test(
    mut ct: *const srtp_cipher_type_t,
    mut test_data: *const srtp_cipher_test_case_t,
) -> srtp_err_status_t {
    let mut test_case: *const srtp_cipher_test_case_t = test_data;
    let mut c: *mut srtp_cipher_t = 0 as *mut srtp_cipher_t;
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut buffer: [uint8_t; 128] = [0; 128];
    let mut buffer2: [uint8_t; 128] = [0; 128];
    let mut tag_len: uint32_t = 0;
    let mut len: libc::c_uint = 0;
    let mut i: libc::c_int = 0;
    let mut j: libc::c_int = 0;
    let mut case_num: libc::c_int = 0 as libc::c_int;
    let mut k: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    if srtp_mod_cipher.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: running self-test for cipher %s\n\0" as *const u8
                as *const libc::c_char,
            srtp_mod_cipher.name,
            (*ct).description,
        );
    }
    if test_case.is_null() {
        return srtp_err_status_cant_check;
    }
    while !test_case.is_null() {
        status = srtp_cipher_type_alloc(
            ct,
            &mut c,
            (*test_case).key_length_octets,
            (*test_case).tag_length_octets,
        );
        if status as u64 != 0 {
            return status;
        }
        if srtp_mod_cipher.on != 0 {
            srtp_err_report(
                srtp_err_level_debug,
                b"%s: testing encryption\n\0" as *const u8 as *const libc::c_char,
                srtp_mod_cipher.name,
            );
        }
        status = srtp_cipher_init(c, (*test_case).key);
        if status as u64 != 0 {
            srtp_cipher_dealloc(c);
            return status;
        }
        if (*test_case).ciphertext_length_octets > 128 as libc::c_int as libc::c_uint {
            srtp_cipher_dealloc(c);
            return srtp_err_status_bad_param;
        }
        k = 0 as libc::c_int as libc::c_uint;
        while k < (*test_case).plaintext_length_octets {
            buffer[k as usize] = *((*test_case).plaintext).offset(k as isize);
            k = k.wrapping_add(1);
        }
        if srtp_mod_cipher.on != 0 {
            srtp_err_report(
                srtp_err_level_debug,
                b"%s: plaintext:    %s\n\0" as *const u8 as *const libc::c_char,
                srtp_mod_cipher.name,
                srtp_octet_string_hex_string(
                    buffer.as_mut_ptr() as *const libc::c_void,
                    (*test_case).plaintext_length_octets as libc::c_int,
                ),
            );
        }
        status = srtp_cipher_set_iv(
            c,
            (*test_case).idx,
            srtp_direction_encrypt as libc::c_int,
        );
        if status as u64 != 0 {
            srtp_cipher_dealloc(c);
            return status;
        }
        if (*c).algorithm == 6 as libc::c_int || (*c).algorithm == 7 as libc::c_int {
            if srtp_mod_cipher.on != 0 {
                srtp_err_report(
                    srtp_err_level_debug,
                    b"%s: IV:    %s\n\0" as *const u8 as *const libc::c_char,
                    srtp_mod_cipher.name,
                    srtp_octet_string_hex_string(
                        (*test_case).idx as *const libc::c_void,
                        12 as libc::c_int,
                    ),
                );
            }
            status = srtp_cipher_set_aad(
                c,
                (*test_case).aad,
                (*test_case).aad_length_octets as uint32_t,
            );
            if status as u64 != 0 {
                srtp_cipher_dealloc(c);
                return status;
            }
            if srtp_mod_cipher.on != 0 {
                srtp_err_report(
                    srtp_err_level_debug,
                    b"%s: AAD:    %s\n\0" as *const u8 as *const libc::c_char,
                    srtp_mod_cipher.name,
                    srtp_octet_string_hex_string(
                        (*test_case).aad as *const libc::c_void,
                        (*test_case).aad_length_octets,
                    ),
                );
            }
        }
        len = (*test_case).plaintext_length_octets;
        status = srtp_cipher_encrypt(c, buffer.as_mut_ptr(), &mut len);
        if status as u64 != 0 {
            srtp_cipher_dealloc(c);
            return status;
        }
        if (*c).algorithm == 6 as libc::c_int || (*c).algorithm == 7 as libc::c_int {
            status = srtp_cipher_get_tag(
                c,
                buffer.as_mut_ptr().offset(len as isize),
                &mut tag_len,
            );
            if status as u64 != 0 {
                srtp_cipher_dealloc(c);
                return status;
            }
            len = len.wrapping_add(tag_len);
        }
        if srtp_mod_cipher.on != 0 {
            srtp_err_report(
                srtp_err_level_debug,
                b"%s: ciphertext:   %s\n\0" as *const u8 as *const libc::c_char,
                srtp_mod_cipher.name,
                srtp_octet_string_hex_string(
                    buffer.as_mut_ptr() as *const libc::c_void,
                    (*test_case).ciphertext_length_octets as libc::c_int,
                ),
            );
        }
        if len != (*test_case).ciphertext_length_octets {
            srtp_cipher_dealloc(c);
            return srtp_err_status_algo_fail;
        }
        status = srtp_err_status_ok;
        k = 0 as libc::c_int as libc::c_uint;
        while k < (*test_case).ciphertext_length_octets {
            if buffer[k as usize] as libc::c_int
                != *((*test_case).ciphertext).offset(k as isize) as libc::c_int
            {
                status = srtp_err_status_algo_fail;
                if srtp_mod_cipher.on != 0 {
                    srtp_err_report(
                        srtp_err_level_debug,
                        b"%s: test case %d failed\n\0" as *const u8
                            as *const libc::c_char,
                        srtp_mod_cipher.name,
                        case_num,
                    );
                }
                if srtp_mod_cipher.on != 0 {
                    srtp_err_report(
                        srtp_err_level_debug,
                        b"%s: (failure at byte %u)\n\0" as *const u8
                            as *const libc::c_char,
                        srtp_mod_cipher.name,
                        k,
                    );
                }
                break;
            } else {
                k = k.wrapping_add(1);
            }
        }
        if status as u64 != 0 {
            if srtp_mod_cipher.on != 0 {
                srtp_err_report(
                    srtp_err_level_debug,
                    b"%s: c computed: %s\n\0" as *const u8 as *const libc::c_char,
                    srtp_mod_cipher.name,
                    srtp_octet_string_hex_string(
                        buffer.as_mut_ptr() as *const libc::c_void,
                        (2 as libc::c_int as libc::c_uint)
                            .wrapping_mul((*test_case).plaintext_length_octets)
                            as libc::c_int,
                    ),
                );
            }
            if srtp_mod_cipher.on != 0 {
                srtp_err_report(
                    srtp_err_level_debug,
                    b"%s: c expected: %s\n\0" as *const u8 as *const libc::c_char,
                    srtp_mod_cipher.name,
                    srtp_octet_string_hex_string(
                        (*test_case).ciphertext as *const libc::c_void,
                        (2 as libc::c_int as libc::c_uint)
                            .wrapping_mul((*test_case).plaintext_length_octets)
                            as libc::c_int,
                    ),
                );
            }
            srtp_cipher_dealloc(c);
            return srtp_err_status_algo_fail;
        }
        if srtp_mod_cipher.on != 0 {
            srtp_err_report(
                srtp_err_level_debug,
                b"%s: testing decryption\n\0" as *const u8 as *const libc::c_char,
                srtp_mod_cipher.name,
            );
        }
        status = srtp_cipher_init(c, (*test_case).key);
        if status as u64 != 0 {
            srtp_cipher_dealloc(c);
            return status;
        }
        if (*test_case).ciphertext_length_octets > 128 as libc::c_int as libc::c_uint {
            srtp_cipher_dealloc(c);
            return srtp_err_status_bad_param;
        }
        k = 0 as libc::c_int as libc::c_uint;
        while k < (*test_case).ciphertext_length_octets {
            buffer[k as usize] = *((*test_case).ciphertext).offset(k as isize);
            k = k.wrapping_add(1);
        }
        if srtp_mod_cipher.on != 0 {
            srtp_err_report(
                srtp_err_level_debug,
                b"%s: ciphertext:    %s\n\0" as *const u8 as *const libc::c_char,
                srtp_mod_cipher.name,
                srtp_octet_string_hex_string(
                    buffer.as_mut_ptr() as *const libc::c_void,
                    (*test_case).plaintext_length_octets as libc::c_int,
                ),
            );
        }
        status = srtp_cipher_set_iv(
            c,
            (*test_case).idx,
            srtp_direction_decrypt as libc::c_int,
        );
        if status as u64 != 0 {
            srtp_cipher_dealloc(c);
            return status;
        }
        if (*c).algorithm == 6 as libc::c_int || (*c).algorithm == 7 as libc::c_int {
            status = srtp_cipher_set_aad(
                c,
                (*test_case).aad,
                (*test_case).aad_length_octets as uint32_t,
            );
            if status as u64 != 0 {
                srtp_cipher_dealloc(c);
                return status;
            }
            if srtp_mod_cipher.on != 0 {
                srtp_err_report(
                    srtp_err_level_debug,
                    b"%s: AAD:    %s\n\0" as *const u8 as *const libc::c_char,
                    srtp_mod_cipher.name,
                    srtp_octet_string_hex_string(
                        (*test_case).aad as *const libc::c_void,
                        (*test_case).aad_length_octets,
                    ),
                );
            }
        }
        len = (*test_case).ciphertext_length_octets;
        status = srtp_cipher_decrypt(c, buffer.as_mut_ptr(), &mut len);
        if status as u64 != 0 {
            srtp_cipher_dealloc(c);
            return status;
        }
        if srtp_mod_cipher.on != 0 {
            srtp_err_report(
                srtp_err_level_debug,
                b"%s: plaintext:   %s\n\0" as *const u8 as *const libc::c_char,
                srtp_mod_cipher.name,
                srtp_octet_string_hex_string(
                    buffer.as_mut_ptr() as *const libc::c_void,
                    (*test_case).plaintext_length_octets as libc::c_int,
                ),
            );
        }
        if len != (*test_case).plaintext_length_octets {
            srtp_cipher_dealloc(c);
            return srtp_err_status_algo_fail;
        }
        status = srtp_err_status_ok;
        k = 0 as libc::c_int as libc::c_uint;
        while k < (*test_case).plaintext_length_octets {
            if buffer[k as usize] as libc::c_int
                != *((*test_case).plaintext).offset(k as isize) as libc::c_int
            {
                status = srtp_err_status_algo_fail;
                if srtp_mod_cipher.on != 0 {
                    srtp_err_report(
                        srtp_err_level_debug,
                        b"%s: test case %d failed\n\0" as *const u8
                            as *const libc::c_char,
                        srtp_mod_cipher.name,
                        case_num,
                    );
                }
                if srtp_mod_cipher.on != 0 {
                    srtp_err_report(
                        srtp_err_level_debug,
                        b"%s: (failure at byte %u)\n\0" as *const u8
                            as *const libc::c_char,
                        srtp_mod_cipher.name,
                        k,
                    );
                }
            }
            k = k.wrapping_add(1);
        }
        if status as u64 != 0 {
            if srtp_mod_cipher.on != 0 {
                srtp_err_report(
                    srtp_err_level_debug,
                    b"%s: p computed: %s\n\0" as *const u8 as *const libc::c_char,
                    srtp_mod_cipher.name,
                    srtp_octet_string_hex_string(
                        buffer.as_mut_ptr() as *const libc::c_void,
                        (2 as libc::c_int as libc::c_uint)
                            .wrapping_mul((*test_case).plaintext_length_octets)
                            as libc::c_int,
                    ),
                );
            }
            if srtp_mod_cipher.on != 0 {
                srtp_err_report(
                    srtp_err_level_debug,
                    b"%s: p expected: %s\n\0" as *const u8 as *const libc::c_char,
                    srtp_mod_cipher.name,
                    srtp_octet_string_hex_string(
                        (*test_case).plaintext as *const libc::c_void,
                        (2 as libc::c_int as libc::c_uint)
                            .wrapping_mul((*test_case).plaintext_length_octets)
                            as libc::c_int,
                    ),
                );
            }
            srtp_cipher_dealloc(c);
            return srtp_err_status_algo_fail;
        }
        status = srtp_cipher_dealloc(c);
        if status as u64 != 0 {
            return status;
        }
        test_case = (*test_case).next_test_case;
        case_num += 1;
    }
    test_case = test_data;
    status = srtp_cipher_type_alloc(
        ct,
        &mut c,
        (*test_case).key_length_octets,
        (*test_case).tag_length_octets,
    );
    if status as u64 != 0 {
        return status;
    }
    j = 0 as libc::c_int;
    while j < 128 as libc::c_int {
        let mut length: libc::c_uint = 0;
        let mut plaintext_len: libc::c_uint = 0;
        let mut key: [uint8_t; 64] = [0; 64];
        let mut iv: [uint8_t; 64] = [0; 64];
        length = (srtp_cipher_rand_u32_for_tests())
            .wrapping_rem((128 as libc::c_int - 64 as libc::c_int) as libc::c_uint);
        if srtp_mod_cipher.on != 0 {
            srtp_err_report(
                srtp_err_level_debug,
                b"%s: random plaintext length %d\n\n\0" as *const u8
                    as *const libc::c_char,
                srtp_mod_cipher.name,
                length,
            );
        }
        srtp_cipher_rand_for_tests(buffer.as_mut_ptr() as *mut libc::c_void, length);
        if srtp_mod_cipher.on != 0 {
            srtp_err_report(
                srtp_err_level_debug,
                b"%s: plaintext:    %s\n\0" as *const u8 as *const libc::c_char,
                srtp_mod_cipher.name,
                srtp_octet_string_hex_string(
                    buffer.as_mut_ptr() as *const libc::c_void,
                    length as libc::c_int,
                ),
            );
        }
        i = 0 as libc::c_int;
        while (i as libc::c_uint) < length {
            buffer2[i as usize] = buffer[i as usize];
            i += 1;
        }
        if (*test_case).key_length_octets > 64 as libc::c_int {
            srtp_cipher_dealloc(c);
            return srtp_err_status_cant_check;
        }
        srtp_cipher_rand_for_tests(
            key.as_mut_ptr() as *mut libc::c_void,
            (*test_case).key_length_octets as uint32_t,
        );
        srtp_cipher_rand_for_tests(
            iv.as_mut_ptr() as *mut libc::c_void,
            64 as libc::c_int as uint32_t,
        );
        status = srtp_cipher_init(c, key.as_mut_ptr());
        if status as u64 != 0 {
            srtp_cipher_dealloc(c);
            return status;
        }
        status = srtp_cipher_set_iv(
            c,
            (*test_case).idx,
            srtp_direction_encrypt as libc::c_int,
        );
        if status as u64 != 0 {
            srtp_cipher_dealloc(c);
            return status;
        }
        if (*c).algorithm == 6 as libc::c_int || (*c).algorithm == 7 as libc::c_int {
            status = srtp_cipher_set_aad(
                c,
                (*test_case).aad,
                (*test_case).aad_length_octets as uint32_t,
            );
            if status as u64 != 0 {
                srtp_cipher_dealloc(c);
                return status;
            }
            if srtp_mod_cipher.on != 0 {
                srtp_err_report(
                    srtp_err_level_debug,
                    b"%s: AAD:    %s\n\0" as *const u8 as *const libc::c_char,
                    srtp_mod_cipher.name,
                    srtp_octet_string_hex_string(
                        (*test_case).aad as *const libc::c_void,
                        (*test_case).aad_length_octets,
                    ),
                );
            }
        }
        plaintext_len = length;
        status = srtp_cipher_encrypt(c, buffer.as_mut_ptr(), &mut length);
        if status as u64 != 0 {
            srtp_cipher_dealloc(c);
            return status;
        }
        if (*c).algorithm == 6 as libc::c_int || (*c).algorithm == 7 as libc::c_int {
            status = srtp_cipher_get_tag(
                c,
                buffer.as_mut_ptr().offset(length as isize),
                &mut tag_len,
            );
            if status as u64 != 0 {
                srtp_cipher_dealloc(c);
                return status;
            }
            length = length.wrapping_add(tag_len);
        }
        if srtp_mod_cipher.on != 0 {
            srtp_err_report(
                srtp_err_level_debug,
                b"%s: ciphertext:   %s\n\0" as *const u8 as *const libc::c_char,
                srtp_mod_cipher.name,
                srtp_octet_string_hex_string(
                    buffer.as_mut_ptr() as *const libc::c_void,
                    length as libc::c_int,
                ),
            );
        }
        status = srtp_cipher_init(c, key.as_mut_ptr());
        if status as u64 != 0 {
            srtp_cipher_dealloc(c);
            return status;
        }
        status = srtp_cipher_set_iv(
            c,
            (*test_case).idx,
            srtp_direction_decrypt as libc::c_int,
        );
        if status as u64 != 0 {
            srtp_cipher_dealloc(c);
            return status;
        }
        if (*c).algorithm == 6 as libc::c_int || (*c).algorithm == 7 as libc::c_int {
            status = srtp_cipher_set_aad(
                c,
                (*test_case).aad,
                (*test_case).aad_length_octets as uint32_t,
            );
            if status as u64 != 0 {
                srtp_cipher_dealloc(c);
                return status;
            }
            if srtp_mod_cipher.on != 0 {
                srtp_err_report(
                    srtp_err_level_debug,
                    b"%s: AAD:    %s\n\0" as *const u8 as *const libc::c_char,
                    srtp_mod_cipher.name,
                    srtp_octet_string_hex_string(
                        (*test_case).aad as *const libc::c_void,
                        (*test_case).aad_length_octets,
                    ),
                );
            }
        }
        status = srtp_cipher_decrypt(c, buffer.as_mut_ptr(), &mut length);
        if status as u64 != 0 {
            srtp_cipher_dealloc(c);
            return status;
        }
        if srtp_mod_cipher.on != 0 {
            srtp_err_report(
                srtp_err_level_debug,
                b"%s: plaintext[2]: %s\n\0" as *const u8 as *const libc::c_char,
                srtp_mod_cipher.name,
                srtp_octet_string_hex_string(
                    buffer.as_mut_ptr() as *const libc::c_void,
                    length as libc::c_int,
                ),
            );
        }
        if length != plaintext_len {
            srtp_cipher_dealloc(c);
            return srtp_err_status_algo_fail;
        }
        status = srtp_err_status_ok;
        k = 0 as libc::c_int as libc::c_uint;
        while k < plaintext_len {
            if buffer[k as usize] as libc::c_int != buffer2[k as usize] as libc::c_int {
                status = srtp_err_status_algo_fail;
                if srtp_mod_cipher.on != 0 {
                    srtp_err_report(
                        srtp_err_level_debug,
                        b"%s: random test case %d failed\n\0" as *const u8
                            as *const libc::c_char,
                        srtp_mod_cipher.name,
                        case_num,
                    );
                }
                if srtp_mod_cipher.on != 0 {
                    srtp_err_report(
                        srtp_err_level_debug,
                        b"%s: (failure at byte %u)\n\0" as *const u8
                            as *const libc::c_char,
                        srtp_mod_cipher.name,
                        k,
                    );
                }
            }
            k = k.wrapping_add(1);
        }
        if status as u64 != 0 {
            srtp_cipher_dealloc(c);
            return srtp_err_status_algo_fail;
        }
        j += 1;
    }
    status = srtp_cipher_dealloc(c);
    if status as u64 != 0 {
        return status;
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_cipher_type_self_test(
    mut ct: *const srtp_cipher_type_t,
) -> srtp_err_status_t {
    return srtp_cipher_type_test(ct, (*ct).test_data);
}
#[no_mangle]
pub unsafe extern "C" fn srtp_cipher_bits_per_second(
    mut c: *mut srtp_cipher_t,
    mut octets_in_buffer: libc::c_int,
    mut num_trials: libc::c_int,
) -> uint64_t {
    let mut i: libc::c_int = 0;
    let mut nonce: v128_t = v128_t { v8: [0; 16] };
    let mut timer: clock_t = 0;
    let mut enc_buf: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut len: libc::c_uint = octets_in_buffer as libc::c_uint;
    enc_buf = srtp_crypto_alloc(octets_in_buffer as size_t) as *mut libc::c_uchar;
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
        if srtp_cipher_set_iv(
            c,
            &mut nonce as *mut v128_t as *mut uint8_t,
            srtp_direction_encrypt as libc::c_int,
        ) as libc::c_uint != srtp_err_status_ok as libc::c_int as libc::c_uint
        {
            srtp_crypto_free(enc_buf as *mut libc::c_void);
            return 0 as libc::c_int as uint64_t;
        }
        if srtp_cipher_encrypt(c, enc_buf, &mut len) as libc::c_uint
            != srtp_err_status_ok as libc::c_int as libc::c_uint
        {
            srtp_crypto_free(enc_buf as *mut libc::c_void);
            return 0 as libc::c_int as uint64_t;
        }
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
