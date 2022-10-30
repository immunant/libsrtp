#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
use crate::v128_t;
extern "C" {
    fn srtp_crypto_alloc(size: size_t) -> *mut libc::c_void;
    fn srtp_crypto_free(ptr: *mut libc::c_void);
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn srtp_octet_string_hex_string(
        str: *const libc::c_void,
        length: libc::c_int,
    ) -> *mut libc::c_char;
    fn v128_hex_string(x: *mut v128_t) -> *mut libc::c_char;
    fn v128_copy_octet_string(x: *mut v128_t, s: *const uint8_t);
    fn octet_string_set_to_zero(s: *mut libc::c_void, len: size_t);
    fn srtp_err_report(
        level: srtp_err_reporting_level_t,
        format: *const libc::c_char,
        _: ...
    );
    fn srtp_aes_expand_encryption_key(
        key: *const uint8_t,
        key_len: libc::c_int,
        expanded_key: *mut srtp_aes_expanded_key_t,
    ) -> srtp_err_status_t;
    fn srtp_aes_encrypt(plaintext: *mut v128_t, exp_key: *const srtp_aes_expanded_key_t);
    static srtp_aes_icm_128_test_case_0: srtp_cipher_test_case_t;
    static srtp_aes_icm_256_test_case_0: srtp_cipher_test_case_t;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type uintptr_t = libc::c_ulong;
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
pub struct srtp_aes_expanded_key_t {
    pub round: [v128_t; 15],
    pub num_rounds: libc::c_int,
}
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
pub struct srtp_aes_icm_ctx_t {
    pub counter: v128_t,
    pub offset: v128_t,
    pub keystream_buffer: v128_t,
    pub expanded_key: srtp_aes_expanded_key_t,
    pub bytes_in_buffer: libc::c_int,
    pub key_size: libc::c_int,
}
#[inline]
unsafe extern "C" fn __bswap_16(mut __bsx: __uint16_t) -> __uint16_t {
    return (__bsx as libc::c_int >> 8 as libc::c_int & 0xff as libc::c_int
        | (__bsx as libc::c_int & 0xff as libc::c_int) << 8 as libc::c_int)
        as __uint16_t;
}
#[no_mangle]
pub static mut srtp_mod_aes_icm: srtp_debug_module_t = {
    let mut init = srtp_debug_module_t {
        on: 0 as libc::c_int,
        name: b"aes icm\0" as *const u8 as *const libc::c_char,
    };
    init
};
unsafe extern "C" fn srtp_aes_icm_alloc(
    mut c: *mut *mut srtp_cipher_t,
    mut key_len: libc::c_int,
    mut tlen: libc::c_int,
) -> srtp_err_status_t {
    let mut icm: *mut srtp_aes_icm_ctx_t = 0 as *mut srtp_aes_icm_ctx_t;
    if srtp_mod_aes_icm.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: allocating cipher with key length %d\n\0" as *const u8
                as *const libc::c_char,
            srtp_mod_aes_icm.name,
            key_len,
        );
    }
    if key_len != 14 as libc::c_int + 16 as libc::c_int
        && key_len != 14 as libc::c_int + 32 as libc::c_int
    {
        return srtp_err_status_bad_param;
    }
    *c = srtp_crypto_alloc(::core::mem::size_of::<srtp_cipher_t>() as libc::c_ulong)
        as *mut srtp_cipher_t;
    if (*c).is_null() {
        return srtp_err_status_alloc_fail;
    }
    icm = srtp_crypto_alloc(
        ::core::mem::size_of::<srtp_aes_icm_ctx_t>() as libc::c_ulong,
    ) as *mut srtp_aes_icm_ctx_t;
    if icm.is_null() {
        srtp_crypto_free(*c as *mut libc::c_void);
        *c = 0 as *mut srtp_cipher_t;
        return srtp_err_status_alloc_fail;
    }
    (**c).state = icm as *mut libc::c_void;
    match key_len {
        46 => {
            (**c).algorithm = 5 as libc::c_int;
            (**c).type_0 = &srtp_aes_icm_256;
        }
        _ => {
            (**c).algorithm = 1 as libc::c_int;
            (**c).type_0 = &srtp_aes_icm_128;
        }
    }
    (*icm).key_size = key_len;
    (**c).key_len = key_len;
    return srtp_err_status_ok;
}
unsafe extern "C" fn srtp_aes_icm_dealloc(
    mut c: *mut srtp_cipher_t,
) -> srtp_err_status_t {
    let mut ctx: *mut srtp_aes_icm_ctx_t = 0 as *mut srtp_aes_icm_ctx_t;
    if c.is_null() {
        return srtp_err_status_bad_param;
    }
    ctx = (*c).state as *mut srtp_aes_icm_ctx_t;
    if !ctx.is_null() {
        octet_string_set_to_zero(
            ctx as *mut libc::c_void,
            ::core::mem::size_of::<srtp_aes_icm_ctx_t>() as libc::c_ulong,
        );
        srtp_crypto_free(ctx as *mut libc::c_void);
    }
    srtp_crypto_free(c as *mut libc::c_void);
    return srtp_err_status_ok;
}
unsafe extern "C" fn srtp_aes_icm_context_init(
    mut cv: *mut libc::c_void,
    mut key: *const uint8_t,
) -> srtp_err_status_t {
    let mut c: *mut srtp_aes_icm_ctx_t = cv as *mut srtp_aes_icm_ctx_t;
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut base_key_len: libc::c_int = 0;
    let mut copy_len: libc::c_int = 0;
    if (*c).key_size == 14 as libc::c_int + 16 as libc::c_int
        || (*c).key_size == 14 as libc::c_int + 32 as libc::c_int
    {
        base_key_len = (*c).key_size - 14 as libc::c_int;
    } else {
        return srtp_err_status_bad_param
    }
    (*c).counter.v32[0 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    (*c).counter.v32[1 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    (*c).counter.v32[2 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    (*c).counter.v32[3 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    (*c).offset.v32[0 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    (*c).offset.v32[1 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    (*c).offset.v32[2 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    (*c).offset.v32[3 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    copy_len = (*c).key_size - base_key_len;
    if copy_len > 14 as libc::c_int {
        copy_len = 14 as libc::c_int;
    }
    memcpy(
        &mut (*c).counter as *mut v128_t as *mut libc::c_void,
        key.offset(base_key_len as isize) as *const libc::c_void,
        copy_len as libc::c_ulong,
    );
    memcpy(
        &mut (*c).offset as *mut v128_t as *mut libc::c_void,
        key.offset(base_key_len as isize) as *const libc::c_void,
        copy_len as libc::c_ulong,
    );
    if srtp_mod_aes_icm.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: key:  %s\n\0" as *const u8 as *const libc::c_char,
            srtp_mod_aes_icm.name,
            srtp_octet_string_hex_string(key as *const libc::c_void, base_key_len),
        );
    }
    if srtp_mod_aes_icm.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: offset: %s\n\0" as *const u8 as *const libc::c_char,
            srtp_mod_aes_icm.name,
            v128_hex_string(&mut (*c).offset),
        );
    }
    status = srtp_aes_expand_encryption_key(key, base_key_len, &mut (*c).expanded_key);
    if status as u64 != 0 {
        (*c).counter.v32[0 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
        (*c).counter.v32[1 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
        (*c).counter.v32[2 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
        (*c).counter.v32[3 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
        (*c).offset.v32[0 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
        (*c).offset.v32[1 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
        (*c).offset.v32[2 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
        (*c).offset.v32[3 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
        return status;
    }
    (*c).bytes_in_buffer = 0 as libc::c_int;
    return srtp_err_status_ok;
}
unsafe extern "C" fn srtp_aes_icm_set_iv(
    mut cv: *mut libc::c_void,
    mut iv: *mut uint8_t,
    mut direction: srtp_cipher_direction_t,
) -> srtp_err_status_t {
    let mut c: *mut srtp_aes_icm_ctx_t = cv as *mut srtp_aes_icm_ctx_t;
    let mut nonce: v128_t = v128_t { v8: [0; 16] };
    v128_copy_octet_string(&mut nonce, iv as *const uint8_t);
    if srtp_mod_aes_icm.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: setting iv: %s\n\0" as *const u8 as *const libc::c_char,
            srtp_mod_aes_icm.name,
            v128_hex_string(&mut nonce),
        );
    }
    (*c)
        .counter
        .v32[0 as libc::c_int
        as usize] = (*c).offset.v32[0 as libc::c_int as usize]
        ^ nonce.v32[0 as libc::c_int as usize];
    (*c)
        .counter
        .v32[1 as libc::c_int
        as usize] = (*c).offset.v32[1 as libc::c_int as usize]
        ^ nonce.v32[1 as libc::c_int as usize];
    (*c)
        .counter
        .v32[2 as libc::c_int
        as usize] = (*c).offset.v32[2 as libc::c_int as usize]
        ^ nonce.v32[2 as libc::c_int as usize];
    (*c)
        .counter
        .v32[3 as libc::c_int
        as usize] = (*c).offset.v32[3 as libc::c_int as usize]
        ^ nonce.v32[3 as libc::c_int as usize];
    if srtp_mod_aes_icm.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: set_counter: %s\n\0" as *const u8 as *const libc::c_char,
            srtp_mod_aes_icm.name,
            v128_hex_string(&mut (*c).counter),
        );
    }
    (*c).bytes_in_buffer = 0 as libc::c_int;
    return srtp_err_status_ok;
}
unsafe extern "C" fn srtp_aes_icm_advance(mut c: *mut srtp_aes_icm_ctx_t) {
    (*c)
        .keystream_buffer
        .v32[0 as libc::c_int as usize] = (*c).counter.v32[0 as libc::c_int as usize];
    (*c)
        .keystream_buffer
        .v32[1 as libc::c_int as usize] = (*c).counter.v32[1 as libc::c_int as usize];
    (*c)
        .keystream_buffer
        .v32[2 as libc::c_int as usize] = (*c).counter.v32[2 as libc::c_int as usize];
    (*c)
        .keystream_buffer
        .v32[3 as libc::c_int as usize] = (*c).counter.v32[3 as libc::c_int as usize];
    srtp_aes_encrypt(&mut (*c).keystream_buffer, &mut (*c).expanded_key);
    (*c)
        .bytes_in_buffer = ::core::mem::size_of::<v128_t>() as libc::c_ulong
        as libc::c_int;
    if srtp_mod_aes_icm.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: counter:    %s\n\0" as *const u8 as *const libc::c_char,
            srtp_mod_aes_icm.name,
            v128_hex_string(&mut (*c).counter),
        );
    }
    if srtp_mod_aes_icm.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: ciphertext: %s\n\0" as *const u8 as *const libc::c_char,
            srtp_mod_aes_icm.name,
            v128_hex_string(&mut (*c).keystream_buffer),
        );
    }
    (*c)
        .counter
        .v8[15 as libc::c_int
        as usize] = ((*c).counter.v8[15 as libc::c_int as usize]).wrapping_add(1);
    if (*c).counter.v8[15 as libc::c_int as usize] == 0 {
        (*c)
            .counter
            .v8[14 as libc::c_int
            as usize] = ((*c).counter.v8[14 as libc::c_int as usize]).wrapping_add(1);
    }
}
unsafe extern "C" fn srtp_aes_icm_encrypt(
    mut cv: *mut libc::c_void,
    mut buf: *mut libc::c_uchar,
    mut enc_len: *mut libc::c_uint,
) -> srtp_err_status_t {
    let mut c: *mut srtp_aes_icm_ctx_t = cv as *mut srtp_aes_icm_ctx_t;
    let mut bytes_to_encr: libc::c_uint = *enc_len;
    let mut i: libc::c_uint = 0;
    let mut b: *mut uint32_t = 0 as *mut uint32_t;
    let mut bytes_of_new_keystream: libc::c_uint = bytes_to_encr
        .wrapping_sub((*c).bytes_in_buffer as libc::c_uint);
    let mut blocks_of_new_keystream: libc::c_uint = bytes_of_new_keystream
        .wrapping_add(15 as libc::c_int as libc::c_uint) >> 4 as libc::c_int;
    if blocks_of_new_keystream
        .wrapping_add(
            __bswap_16((*c).counter.v16[7 as libc::c_int as usize]) as libc::c_uint,
        ) > 0xffff as libc::c_int as libc::c_uint
    {
        return srtp_err_status_terminus;
    }
    if srtp_mod_aes_icm.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: block index: %d\n\0" as *const u8 as *const libc::c_char,
            srtp_mod_aes_icm.name,
            __bswap_16((*c).counter.v16[7 as libc::c_int as usize]) as libc::c_int,
        );
    }
    if bytes_to_encr <= (*c).bytes_in_buffer as libc::c_uint {
        i = (::core::mem::size_of::<v128_t>() as libc::c_ulong)
            .wrapping_sub((*c).bytes_in_buffer as libc::c_ulong) as libc::c_uint;
        while (i as libc::c_ulong)
            < (::core::mem::size_of::<v128_t>() as libc::c_ulong)
                .wrapping_sub((*c).bytes_in_buffer as libc::c_ulong)
                .wrapping_add(bytes_to_encr as libc::c_ulong)
        {
            let fresh0 = buf;
            buf = buf.offset(1);
            *fresh0 = (*fresh0 as libc::c_int
                ^ (*c).keystream_buffer.v8[i as usize] as libc::c_int) as libc::c_uchar;
            i = i.wrapping_add(1);
        }
        (*c)
            .bytes_in_buffer = ((*c).bytes_in_buffer as libc::c_uint)
            .wrapping_sub(bytes_to_encr) as libc::c_int as libc::c_int;
        return srtp_err_status_ok;
    } else {
        i = (::core::mem::size_of::<v128_t>() as libc::c_ulong)
            .wrapping_sub((*c).bytes_in_buffer as libc::c_ulong) as libc::c_uint;
        while (i as libc::c_ulong) < ::core::mem::size_of::<v128_t>() as libc::c_ulong {
            let fresh1 = buf;
            buf = buf.offset(1);
            *fresh1 = (*fresh1 as libc::c_int
                ^ (*c).keystream_buffer.v8[i as usize] as libc::c_int) as libc::c_uchar;
            i = i.wrapping_add(1);
        }
        bytes_to_encr = bytes_to_encr.wrapping_sub((*c).bytes_in_buffer as libc::c_uint);
        (*c).bytes_in_buffer = 0 as libc::c_int;
    }
    i = 0 as libc::c_int as libc::c_uint;
    while (i as libc::c_ulong)
        < (bytes_to_encr as libc::c_ulong)
            .wrapping_div(::core::mem::size_of::<v128_t>() as libc::c_ulong)
    {
        srtp_aes_icm_advance(c);
        if buf as uintptr_t & 0x3 as libc::c_int as libc::c_ulong
            != 0 as libc::c_int as libc::c_ulong
        {
            let fresh2 = buf;
            buf = buf.offset(1);
            *fresh2 = (*fresh2 as libc::c_int
                ^ (*c).keystream_buffer.v8[0 as libc::c_int as usize] as libc::c_int)
                as libc::c_uchar;
            let fresh3 = buf;
            buf = buf.offset(1);
            *fresh3 = (*fresh3 as libc::c_int
                ^ (*c).keystream_buffer.v8[1 as libc::c_int as usize] as libc::c_int)
                as libc::c_uchar;
            let fresh4 = buf;
            buf = buf.offset(1);
            *fresh4 = (*fresh4 as libc::c_int
                ^ (*c).keystream_buffer.v8[2 as libc::c_int as usize] as libc::c_int)
                as libc::c_uchar;
            let fresh5 = buf;
            buf = buf.offset(1);
            *fresh5 = (*fresh5 as libc::c_int
                ^ (*c).keystream_buffer.v8[3 as libc::c_int as usize] as libc::c_int)
                as libc::c_uchar;
            let fresh6 = buf;
            buf = buf.offset(1);
            *fresh6 = (*fresh6 as libc::c_int
                ^ (*c).keystream_buffer.v8[4 as libc::c_int as usize] as libc::c_int)
                as libc::c_uchar;
            let fresh7 = buf;
            buf = buf.offset(1);
            *fresh7 = (*fresh7 as libc::c_int
                ^ (*c).keystream_buffer.v8[5 as libc::c_int as usize] as libc::c_int)
                as libc::c_uchar;
            let fresh8 = buf;
            buf = buf.offset(1);
            *fresh8 = (*fresh8 as libc::c_int
                ^ (*c).keystream_buffer.v8[6 as libc::c_int as usize] as libc::c_int)
                as libc::c_uchar;
            let fresh9 = buf;
            buf = buf.offset(1);
            *fresh9 = (*fresh9 as libc::c_int
                ^ (*c).keystream_buffer.v8[7 as libc::c_int as usize] as libc::c_int)
                as libc::c_uchar;
            let fresh10 = buf;
            buf = buf.offset(1);
            *fresh10 = (*fresh10 as libc::c_int
                ^ (*c).keystream_buffer.v8[8 as libc::c_int as usize] as libc::c_int)
                as libc::c_uchar;
            let fresh11 = buf;
            buf = buf.offset(1);
            *fresh11 = (*fresh11 as libc::c_int
                ^ (*c).keystream_buffer.v8[9 as libc::c_int as usize] as libc::c_int)
                as libc::c_uchar;
            let fresh12 = buf;
            buf = buf.offset(1);
            *fresh12 = (*fresh12 as libc::c_int
                ^ (*c).keystream_buffer.v8[10 as libc::c_int as usize] as libc::c_int)
                as libc::c_uchar;
            let fresh13 = buf;
            buf = buf.offset(1);
            *fresh13 = (*fresh13 as libc::c_int
                ^ (*c).keystream_buffer.v8[11 as libc::c_int as usize] as libc::c_int)
                as libc::c_uchar;
            let fresh14 = buf;
            buf = buf.offset(1);
            *fresh14 = (*fresh14 as libc::c_int
                ^ (*c).keystream_buffer.v8[12 as libc::c_int as usize] as libc::c_int)
                as libc::c_uchar;
            let fresh15 = buf;
            buf = buf.offset(1);
            *fresh15 = (*fresh15 as libc::c_int
                ^ (*c).keystream_buffer.v8[13 as libc::c_int as usize] as libc::c_int)
                as libc::c_uchar;
            let fresh16 = buf;
            buf = buf.offset(1);
            *fresh16 = (*fresh16 as libc::c_int
                ^ (*c).keystream_buffer.v8[14 as libc::c_int as usize] as libc::c_int)
                as libc::c_uchar;
            let fresh17 = buf;
            buf = buf.offset(1);
            *fresh17 = (*fresh17 as libc::c_int
                ^ (*c).keystream_buffer.v8[15 as libc::c_int as usize] as libc::c_int)
                as libc::c_uchar;
        } else {
            b = buf as *mut uint32_t;
            let fresh18 = b;
            b = b.offset(1);
            *fresh18 ^= (*c).keystream_buffer.v32[0 as libc::c_int as usize];
            let fresh19 = b;
            b = b.offset(1);
            *fresh19 ^= (*c).keystream_buffer.v32[1 as libc::c_int as usize];
            let fresh20 = b;
            b = b.offset(1);
            *fresh20 ^= (*c).keystream_buffer.v32[2 as libc::c_int as usize];
            let fresh21 = b;
            b = b.offset(1);
            *fresh21 ^= (*c).keystream_buffer.v32[3 as libc::c_int as usize];
            buf = b as *mut uint8_t;
        }
        i = i.wrapping_add(1);
    }
    if bytes_to_encr & 0xf as libc::c_int as libc::c_uint
        != 0 as libc::c_int as libc::c_uint
    {
        srtp_aes_icm_advance(c);
        i = 0 as libc::c_int as libc::c_uint;
        while i < bytes_to_encr & 0xf as libc::c_int as libc::c_uint {
            let fresh22 = buf;
            buf = buf.offset(1);
            *fresh22 = (*fresh22 as libc::c_int
                ^ (*c).keystream_buffer.v8[i as usize] as libc::c_int) as libc::c_uchar;
            i = i.wrapping_add(1);
        }
        (*c)
            .bytes_in_buffer = (::core::mem::size_of::<v128_t>() as libc::c_ulong)
            .wrapping_sub(i as libc::c_ulong) as libc::c_int;
    } else {
        (*c).bytes_in_buffer = 0 as libc::c_int;
    }
    return srtp_err_status_ok;
}
static mut srtp_aes_icm_128_description: [libc::c_char; 29] = unsafe {
    *::core::mem::transmute::<
        &[u8; 29],
        &[libc::c_char; 29],
    >(b"AES-128 integer counter mode\0")
};
static mut srtp_aes_icm_256_description: [libc::c_char; 29] = unsafe {
    *::core::mem::transmute::<
        &[u8; 29],
        &[libc::c_char; 29],
    >(b"AES-256 integer counter mode\0")
};
#[no_mangle]
pub static mut srtp_aes_icm_128: srtp_cipher_type_t = unsafe {
    {
        let mut init = srtp_cipher_type_t {
            alloc: Some(
                srtp_aes_icm_alloc
                    as unsafe extern "C" fn(
                        *mut *mut srtp_cipher_t,
                        libc::c_int,
                        libc::c_int,
                    ) -> srtp_err_status_t,
            ),
            dealloc: Some(
                srtp_aes_icm_dealloc
                    as unsafe extern "C" fn(*mut srtp_cipher_t) -> srtp_err_status_t,
            ),
            init: Some(
                srtp_aes_icm_context_init
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const uint8_t,
                    ) -> srtp_err_status_t,
            ),
            set_aad: None,
            encrypt: Some(
                srtp_aes_icm_encrypt
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *mut libc::c_uchar,
                        *mut libc::c_uint,
                    ) -> srtp_err_status_t,
            ),
            decrypt: Some(
                srtp_aes_icm_encrypt
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *mut libc::c_uchar,
                        *mut libc::c_uint,
                    ) -> srtp_err_status_t,
            ),
            set_iv: Some(
                srtp_aes_icm_set_iv
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *mut uint8_t,
                        srtp_cipher_direction_t,
                    ) -> srtp_err_status_t,
            ),
            get_tag: None,
            description: srtp_aes_icm_128_description.as_ptr(),
            test_data: &srtp_aes_icm_128_test_case_0 as *const srtp_cipher_test_case_t,
            id: 1 as libc::c_int as srtp_cipher_type_id_t,
        };
        init
    }
};
#[no_mangle]
pub static mut srtp_aes_icm_256: srtp_cipher_type_t = unsafe {
    {
        let mut init = srtp_cipher_type_t {
            alloc: Some(
                srtp_aes_icm_alloc
                    as unsafe extern "C" fn(
                        *mut *mut srtp_cipher_t,
                        libc::c_int,
                        libc::c_int,
                    ) -> srtp_err_status_t,
            ),
            dealloc: Some(
                srtp_aes_icm_dealloc
                    as unsafe extern "C" fn(*mut srtp_cipher_t) -> srtp_err_status_t,
            ),
            init: Some(
                srtp_aes_icm_context_init
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *const uint8_t,
                    ) -> srtp_err_status_t,
            ),
            set_aad: None,
            encrypt: Some(
                srtp_aes_icm_encrypt
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *mut libc::c_uchar,
                        *mut libc::c_uint,
                    ) -> srtp_err_status_t,
            ),
            decrypt: Some(
                srtp_aes_icm_encrypt
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *mut libc::c_uchar,
                        *mut libc::c_uint,
                    ) -> srtp_err_status_t,
            ),
            set_iv: Some(
                srtp_aes_icm_set_iv
                    as unsafe extern "C" fn(
                        *mut libc::c_void,
                        *mut uint8_t,
                        srtp_cipher_direction_t,
                    ) -> srtp_err_status_t,
            ),
            get_tag: None,
            description: srtp_aes_icm_256_description.as_ptr(),
            test_data: &srtp_aes_icm_256_test_case_0 as *const srtp_cipher_test_case_t,
            id: 5 as libc::c_int as srtp_cipher_type_id_t,
        };
        init
    }
};
