#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
extern "C" {
    fn srtp_err_report(
        level: srtp_err_reporting_level_t,
        format: *const libc::c_char,
        _: ...
    );
    fn octet_string_set_to_zero(s: *mut libc::c_void, len: size_t);
    fn srtp_octet_string_hex_string(
        str: *const libc::c_void,
        length: libc::c_int,
    ) -> *mut libc::c_char;
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
pub struct srtp_debug_module_t {
    pub on: libc::c_int,
    pub name: *const libc::c_char,
}
pub type srtp_err_reporting_level_t = libc::c_uint;
pub const srtp_err_level_debug: srtp_err_reporting_level_t = 3;
pub const srtp_err_level_info: srtp_err_reporting_level_t = 2;
pub const srtp_err_level_warning: srtp_err_reporting_level_t = 1;
pub const srtp_err_level_error: srtp_err_reporting_level_t = 0;
pub type size_t = libc::c_ulong;
#[no_mangle]
pub static mut srtp_mod_auth: srtp_debug_module_t = {
    let mut init = srtp_debug_module_t {
        on: 0 as libc::c_int,
        name: b"auth func\0" as *const u8 as *const libc::c_char,
    };
    init
};
#[no_mangle]
pub unsafe extern "C" fn srtp_auth_get_key_length(
    mut a: *const srtp_auth_t,
) -> libc::c_int {
    return (*a).key_len;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_auth_get_tag_length(
    mut a: *const srtp_auth_t,
) -> libc::c_int {
    return (*a).out_len;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_auth_get_prefix_length(
    mut a: *const srtp_auth_t,
) -> libc::c_int {
    return (*a).prefix_len;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_auth_type_test(
    mut at: *const srtp_auth_type_t,
    mut test_data: *const srtp_auth_test_case_t,
) -> srtp_err_status_t {
    let mut test_case: *const srtp_auth_test_case_t = test_data;
    let mut a: *mut srtp_auth_t = 0 as *mut srtp_auth_t;
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut tag: [uint8_t; 32] = [0; 32];
    let mut i: libc::c_int = 0;
    let mut case_num: libc::c_int = 0 as libc::c_int;
    if srtp_mod_auth.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: running self-test for auth function %s\n\0" as *const u8
                as *const libc::c_char,
            srtp_mod_auth.name,
            (*at).description,
        );
    }
    if test_case.is_null() {
        return srtp_err_status_cant_check;
    }
    while !test_case.is_null() {
        if (*test_case).tag_length_octets > 32 as libc::c_int {
            return srtp_err_status_bad_param;
        }
        status = ((*at).alloc)
            .expect(
                "non-null function pointer",
            )(&mut a, (*test_case).key_length_octets, (*test_case).tag_length_octets);
        if status as u64 != 0 {
            return status;
        }
        status = ((*(*a).type_0).init)
            .expect(
                "non-null function pointer",
            )((*a).state, (*test_case).key, (*a).key_len);
        if status as u64 != 0 {
            ((*(*a).type_0).dealloc).expect("non-null function pointer")(a);
            return status;
        }
        status = ((*(*a).type_0).start).expect("non-null function pointer")((*a).state);
        if status as u64 != 0 {
            ((*(*a).type_0).dealloc).expect("non-null function pointer")(a);
            return status;
        }
        octet_string_set_to_zero(
            tag.as_mut_ptr() as *mut libc::c_void,
            (*test_case).tag_length_octets as size_t,
        );
        status = ((*(*a).type_0).compute)
            .expect(
                "non-null function pointer",
            )(
            (*a).state,
            (*test_case).data,
            (*test_case).data_length_octets,
            (*a).out_len,
            tag.as_mut_ptr(),
        );
        if status as u64 != 0 {
            ((*(*a).type_0).dealloc).expect("non-null function pointer")(a);
            return status;
        }
        if srtp_mod_auth.on != 0 {
            srtp_err_report(
                srtp_err_level_debug,
                b"%s: key: %s\n\0" as *const u8 as *const libc::c_char,
                srtp_mod_auth.name,
                srtp_octet_string_hex_string(
                    (*test_case).key as *const libc::c_void,
                    (*test_case).key_length_octets,
                ),
            );
        }
        if srtp_mod_auth.on != 0 {
            srtp_err_report(
                srtp_err_level_debug,
                b"%s: data: %s\n\0" as *const u8 as *const libc::c_char,
                srtp_mod_auth.name,
                srtp_octet_string_hex_string(
                    (*test_case).data as *const libc::c_void,
                    (*test_case).data_length_octets,
                ),
            );
        }
        if srtp_mod_auth.on != 0 {
            srtp_err_report(
                srtp_err_level_debug,
                b"%s: tag computed: %s\n\0" as *const u8 as *const libc::c_char,
                srtp_mod_auth.name,
                srtp_octet_string_hex_string(
                    tag.as_mut_ptr() as *const libc::c_void,
                    (*test_case).tag_length_octets,
                ),
            );
        }
        if srtp_mod_auth.on != 0 {
            srtp_err_report(
                srtp_err_level_debug,
                b"%s: tag expected: %s\n\0" as *const u8 as *const libc::c_char,
                srtp_mod_auth.name,
                srtp_octet_string_hex_string(
                    (*test_case).tag as *const libc::c_void,
                    (*test_case).tag_length_octets,
                ),
            );
        }
        status = srtp_err_status_ok;
        i = 0 as libc::c_int;
        while i < (*test_case).tag_length_octets {
            if tag[i as usize] as libc::c_int
                != *((*test_case).tag).offset(i as isize) as libc::c_int
            {
                status = srtp_err_status_algo_fail;
                if srtp_mod_auth.on != 0 {
                    srtp_err_report(
                        srtp_err_level_debug,
                        b"%s: test case %d failed\n\0" as *const u8
                            as *const libc::c_char,
                        srtp_mod_auth.name,
                        case_num,
                    );
                }
                if srtp_mod_auth.on != 0 {
                    srtp_err_report(
                        srtp_err_level_debug,
                        b"%s:   (mismatch at octet %d)\n\0" as *const u8
                            as *const libc::c_char,
                        srtp_mod_auth.name,
                        i,
                    );
                }
            }
            i += 1;
        }
        if status as u64 != 0 {
            ((*(*a).type_0).dealloc).expect("non-null function pointer")(a);
            return srtp_err_status_algo_fail;
        }
        status = ((*(*a).type_0).dealloc).expect("non-null function pointer")(a);
        if status as u64 != 0 {
            return status;
        }
        test_case = (*test_case).next_test_case;
        case_num += 1;
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_auth_type_self_test(
    mut at: *const srtp_auth_type_t,
) -> srtp_err_status_t {
    return srtp_auth_type_test(at, (*at).test_data);
}
