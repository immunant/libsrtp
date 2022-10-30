#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
#![feature(extern_types)]
use c2rust_bitfields::BitfieldStruct;
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn clock() -> clock_t;
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    fn free(_: *mut libc::c_void);
    fn exit(_: libc::c_int) -> !;
    static mut stdout: *mut FILE;
    static mut stderr: *mut FILE;
    fn fprintf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    fn sprintf(_: *mut libc::c_char, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn getopt_s(
        argc: libc::c_int,
        argv: *const *mut libc::c_char,
        optstring: *const libc::c_char,
    ) -> libc::c_int;
    static mut optarg_s: *mut libc::c_char;
    fn srtp_init() -> srtp_err_status_t;
    fn srtp_shutdown() -> srtp_err_status_t;
    fn srtp_protect(
        ctx: srtp_t,
        rtp_hdr: *mut libc::c_void,
        len_ptr: *mut libc::c_int,
    ) -> srtp_err_status_t;
    fn srtp_protect_mki(
        ctx: *mut srtp_ctx_t,
        rtp_hdr: *mut libc::c_void,
        pkt_octet_len: *mut libc::c_int,
        use_mki: libc::c_uint,
        mki_index: libc::c_uint,
    ) -> srtp_err_status_t;
    fn srtp_unprotect(
        ctx: srtp_t,
        srtp_hdr: *mut libc::c_void,
        len_ptr: *mut libc::c_int,
    ) -> srtp_err_status_t;
    fn srtp_unprotect_mki(
        ctx: srtp_t,
        srtp_hdr: *mut libc::c_void,
        len_ptr: *mut libc::c_int,
        use_mki: libc::c_uint,
    ) -> srtp_err_status_t;
    fn srtp_create(
        session: *mut srtp_t,
        policy: *const srtp_policy_t,
    ) -> srtp_err_status_t;
    fn srtp_add_stream(
        session: srtp_t,
        policy: *const srtp_policy_t,
    ) -> srtp_err_status_t;
    fn srtp_remove_stream(session: srtp_t, ssrc: libc::c_uint) -> srtp_err_status_t;
    fn srtp_update(session: srtp_t, policy: *const srtp_policy_t) -> srtp_err_status_t;
    fn srtp_crypto_policy_set_rtp_default(p: *mut srtp_crypto_policy_t);
    fn srtp_crypto_policy_set_rtcp_default(p: *mut srtp_crypto_policy_t);
    fn srtp_crypto_policy_set_null_cipher_hmac_sha1_80(p: *mut srtp_crypto_policy_t);
    fn srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80(p: *mut srtp_crypto_policy_t);
    fn srtp_dealloc(s: srtp_t) -> srtp_err_status_t;
    fn srtp_protect_rtcp(
        ctx: srtp_t,
        rtcp_hdr: *mut libc::c_void,
        pkt_octet_len: *mut libc::c_int,
    ) -> srtp_err_status_t;
    fn srtp_protect_rtcp_mki(
        ctx: srtp_t,
        rtcp_hdr: *mut libc::c_void,
        pkt_octet_len: *mut libc::c_int,
        use_mki: libc::c_uint,
        mki_index: libc::c_uint,
    ) -> srtp_err_status_t;
    fn srtp_unprotect_rtcp(
        ctx: srtp_t,
        srtcp_hdr: *mut libc::c_void,
        pkt_octet_len: *mut libc::c_int,
    ) -> srtp_err_status_t;
    fn srtp_unprotect_rtcp_mki(
        ctx: srtp_t,
        srtcp_hdr: *mut libc::c_void,
        pkt_octet_len: *mut libc::c_int,
        use_mki: libc::c_uint,
    ) -> srtp_err_status_t;
    fn srtp_set_debug_module(
        mod_name: *const libc::c_char,
        v: libc::c_int,
    ) -> srtp_err_status_t;
    fn srtp_list_debug_modules() -> srtp_err_status_t;
    fn srtp_install_log_handler(
        func: Option::<srtp_log_handler_func_t>,
        data: *mut libc::c_void,
    ) -> srtp_err_status_t;
    fn srtp_get_protect_trailer_length(
        session: srtp_t,
        use_mki: uint32_t,
        mki_index: uint32_t,
        length: *mut uint32_t,
    ) -> srtp_err_status_t;
    fn srtp_get_protect_rtcp_trailer_length(
        session: srtp_t,
        use_mki: uint32_t,
        mki_index: uint32_t,
        length: *mut uint32_t,
    ) -> srtp_err_status_t;
    fn srtp_set_stream_roc(
        session: srtp_t,
        ssrc: uint32_t,
        roc: uint32_t,
    ) -> srtp_err_status_t;
    fn srtp_get_stream_roc(
        session: srtp_t,
        ssrc: uint32_t,
        roc: *mut uint32_t,
    ) -> srtp_err_status_t;
    fn srtp_octet_string_hex_string(
        str: *const libc::c_void,
        length: libc::c_int,
    ) -> *mut libc::c_char;
    fn srtp_octet_string_is_eq(
        a: *mut uint8_t,
        b: *mut uint8_t,
        len: libc::c_int,
    ) -> libc::c_int;
    fn srtp_err_report(
        level: srtp_err_reporting_level_t,
        format: *const libc::c_char,
        _: ...
    );
    fn srtp_rdbx_get_window_size(rdbx: *const srtp_rdbx_t) -> libc::c_ulong;
    fn srtp_crypto_kernel_load_debug_module(
        new_dm: *mut srtp_debug_module_t,
    ) -> srtp_err_status_t;
    fn srtp_get_stream(srtp: srtp_t, ssrc: uint32_t) -> srtp_stream_t;
    fn octet_string_hex_string(
        s: *const libc::c_void,
        length: libc::c_int,
    ) -> *mut libc::c_char;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __clock_t = libc::c_long;
pub type clock_t = __clock_t;
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
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct srtp_ctx_t_ {
    pub stream_list: *mut srtp_stream_ctx_t_,
    pub stream_template: *mut srtp_stream_ctx_t_,
    pub user_data: *mut libc::c_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct srtp_stream_ctx_t_ {
    pub ssrc: uint32_t,
    pub session_keys: *mut srtp_session_keys_t,
    pub num_master_keys: libc::c_uint,
    pub rtp_rdbx: srtp_rdbx_t,
    pub rtp_services: srtp_sec_serv_t,
    pub rtcp_rdb: srtp_rdb_t,
    pub rtcp_services: srtp_sec_serv_t,
    pub direction: direction_t,
    pub allow_repeat_tx: libc::c_int,
    pub enc_xtn_hdr: *mut libc::c_int,
    pub enc_xtn_hdr_count: libc::c_int,
    pub pending_roc: uint32_t,
    pub next: *mut srtp_stream_ctx_t_,
}
pub type direction_t = libc::c_uint;
pub const dir_srtp_receiver: direction_t = 2;
pub const dir_srtp_sender: direction_t = 1;
pub const dir_unknown: direction_t = 0;
pub type srtp_sec_serv_t = libc::c_uint;
pub const sec_serv_conf_and_auth: srtp_sec_serv_t = 3;
pub const sec_serv_auth: srtp_sec_serv_t = 2;
pub const sec_serv_conf: srtp_sec_serv_t = 1;
pub const sec_serv_none: srtp_sec_serv_t = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct srtp_rdb_t {
    pub window_start: uint32_t,
    pub bitmask: v128_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union v128_t {
    pub v8: [uint8_t; 16],
    pub v16: [uint16_t; 8],
    pub v32: [uint32_t; 4],
    pub v64: [uint64_t; 2],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct srtp_rdbx_t {
    pub index: srtp_xtd_seq_num_t,
    pub bitmask: bitvector_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct bitvector_t {
    pub length: uint32_t,
    pub word: *mut uint32_t,
}
pub type srtp_xtd_seq_num_t = uint64_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct srtp_session_keys_t {
    pub rtp_cipher: *mut srtp_cipher_t,
    pub rtp_xtn_hdr_cipher: *mut srtp_cipher_t,
    pub rtp_auth: *mut srtp_auth_t,
    pub rtcp_cipher: *mut srtp_cipher_t,
    pub rtcp_auth: *mut srtp_auth_t,
    pub salt: [uint8_t; 12],
    pub c_salt: [uint8_t; 12],
    pub mki_id: *mut uint8_t,
    pub mki_size: libc::c_uint,
    pub limit: *mut srtp_key_limit_ctx_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct srtp_key_limit_ctx_t {
    pub num_left: srtp_xtd_seq_num_t,
    pub state: srtp_key_state_t,
}
pub type srtp_key_state_t = libc::c_uint;
pub const srtp_key_state_expired: srtp_key_state_t = 2;
pub const srtp_key_state_past_soft_limit: srtp_key_state_t = 1;
pub const srtp_key_state_normal: srtp_key_state_t = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct srtp_auth_t {
    pub type_0: *const srtp_auth_type_t,
    pub state: *mut libc::c_void,
    pub out_len: libc::c_int,
    pub key_len: libc::c_int,
    pub prefix_len: libc::c_int,
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
pub type srtp_auth_alloc_func = Option::<
    unsafe extern "C" fn(
        *mut srtp_auth_pointer_t,
        libc::c_int,
        libc::c_int,
    ) -> srtp_err_status_t,
>;
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
pub type srtp_cipher_direction_t = libc::c_uint;
pub const srtp_direction_any: srtp_cipher_direction_t = 2;
pub const srtp_direction_decrypt: srtp_cipher_direction_t = 1;
pub const srtp_direction_encrypt: srtp_cipher_direction_t = 0;
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
pub type srtp_ctx_t = srtp_ctx_t_;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct srtp_crypto_policy_t {
    pub cipher_type: srtp_cipher_type_id_t,
    pub cipher_key_len: libc::c_int,
    pub auth_type: srtp_auth_type_id_t,
    pub auth_key_len: libc::c_int,
    pub auth_tag_len: libc::c_int,
    pub sec_serv: srtp_sec_serv_t,
}
pub type srtp_ssrc_type_t = libc::c_uint;
pub const ssrc_any_outbound: srtp_ssrc_type_t = 3;
pub const ssrc_any_inbound: srtp_ssrc_type_t = 2;
pub const ssrc_specific: srtp_ssrc_type_t = 1;
pub const ssrc_undefined: srtp_ssrc_type_t = 0;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct srtp_ssrc_t {
    pub type_0: srtp_ssrc_type_t,
    pub value: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct srtp_master_key_t {
    pub key: *mut libc::c_uchar,
    pub mki_id: *mut libc::c_uchar,
    pub mki_size: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct srtp_policy_t {
    pub ssrc: srtp_ssrc_t,
    pub rtp: srtp_crypto_policy_t,
    pub rtcp: srtp_crypto_policy_t,
    pub key: *mut libc::c_uchar,
    pub keys: *mut *mut srtp_master_key_t,
    pub num_master_keys: libc::c_ulong,
    pub deprecated_ekt: *mut libc::c_void,
    pub window_size: libc::c_ulong,
    pub allow_repeat_tx: libc::c_int,
    pub enc_xtn_hdr: *mut libc::c_int,
    pub enc_xtn_hdr_count: libc::c_int,
    pub next: *mut srtp_policy_t,
}
pub type srtp_t = *mut srtp_ctx_t;
pub type srtp_log_level_t = libc::c_uint;
pub const srtp_log_level_debug: srtp_log_level_t = 3;
pub const srtp_log_level_info: srtp_log_level_t = 2;
pub const srtp_log_level_warning: srtp_log_level_t = 1;
pub const srtp_log_level_error: srtp_log_level_t = 0;
pub type srtp_log_handler_func_t = unsafe extern "C" fn(
    srtp_log_level_t,
    *const libc::c_char,
    *mut libc::c_void,
) -> ();
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
pub type srtp_stream_ctx_t = srtp_stream_ctx_t_;
pub type srtp_stream_t = *mut srtp_stream_ctx_t;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct srtp_hdr_t {
    #[bitfield(name = "cc", ty = "libc::c_uchar", bits = "0..=3")]
    #[bitfield(name = "x", ty = "libc::c_uchar", bits = "4..=4")]
    #[bitfield(name = "p", ty = "libc::c_uchar", bits = "5..=5")]
    #[bitfield(name = "version", ty = "libc::c_uchar", bits = "6..=7")]
    #[bitfield(name = "pt", ty = "libc::c_uchar", bits = "8..=14")]
    #[bitfield(name = "m", ty = "libc::c_uchar", bits = "15..=15")]
    pub cc_x_p_version_pt_m: [u8; 2],
    pub seq: uint16_t,
    pub ts: uint32_t,
    pub ssrc: uint32_t,
}
#[inline]
unsafe extern "C" fn __bswap_16(mut __bsx: __uint16_t) -> __uint16_t {
    return (__bsx as libc::c_int >> 8 as libc::c_int & 0xff as libc::c_int
        | (__bsx as libc::c_int & 0xff as libc::c_int) << 8 as libc::c_int)
        as __uint16_t;
}
#[inline]
unsafe extern "C" fn __bswap_32(mut __bsx: __uint32_t) -> __uint32_t {
    return (__bsx & 0xff000000 as libc::c_uint) >> 24 as libc::c_int
        | (__bsx & 0xff0000 as libc::c_uint) >> 8 as libc::c_int
        | (__bsx & 0xff00 as libc::c_uint) << 8 as libc::c_int
        | (__bsx & 0xff as libc::c_uint) << 24 as libc::c_int;
}
#[no_mangle]
pub static mut master_key_1: srtp_master_key_t = unsafe {
    {
        let mut init = srtp_master_key_t {
            key: test_key.as_ptr() as *mut _,
            mki_id: test_mki_id.as_ptr() as *mut _,
            mki_size: 4 as libc::c_int as libc::c_uint,
        };
        init
    }
};
#[no_mangle]
pub static mut master_key_2: srtp_master_key_t = unsafe {
    {
        let mut init = srtp_master_key_t {
            key: test_key_2.as_ptr() as *mut _,
            mki_id: test_mki_id_2.as_ptr() as *mut _,
            mki_size: 4 as libc::c_int as libc::c_uint,
        };
        init
    }
};
#[no_mangle]
pub static mut test_keys: [*mut srtp_master_key_t; 2] = unsafe {
    [
        &master_key_1 as *const srtp_master_key_t as *mut srtp_master_key_t,
        &master_key_2 as *const srtp_master_key_t as *mut srtp_master_key_t,
    ]
};
#[no_mangle]
pub unsafe extern "C" fn usage(mut prog_name: *mut libc::c_char) {
    printf(
        b"usage: %s [ -t ][ -c ][ -v ][ -o ][-d <debug_module> ]* [ -l ]\n  -t         run timing test\n  -r         run rejection timing test\n  -c         run codec timing test\n  -v         run validation tests\n  -o         output logging to stdout\n  -d <mod>   turn on debugging module <mod>\n  -l         list debugging modules\n\0"
            as *const u8 as *const libc::c_char,
        prog_name,
    );
    exit(1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn log_handler(
    mut level: srtp_log_level_t,
    mut msg: *const libc::c_char,
    mut data: *mut libc::c_void,
) {
    let mut level_char: libc::c_char = '?' as i32 as libc::c_char;
    match level as libc::c_uint {
        0 => {
            level_char = 'e' as i32 as libc::c_char;
        }
        1 => {
            level_char = 'w' as i32 as libc::c_char;
        }
        2 => {
            level_char = 'i' as i32 as libc::c_char;
        }
        3 => {
            level_char = 'd' as i32 as libc::c_char;
        }
        _ => {}
    }
    printf(
        b"SRTP-LOG [%c]: %s\n\0" as *const u8 as *const libc::c_char,
        level_char as libc::c_int,
        msg,
    );
}
#[no_mangle]
pub static mut mod_driver: srtp_debug_module_t = {
    let mut init = srtp_debug_module_t {
        on: 0 as libc::c_int,
        name: b"driver\0" as *const u8 as *const libc::c_char,
    };
    init
};
unsafe fn main_0(
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut q: libc::c_int = 0;
    let mut do_timing_test: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut do_rejection_test: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut do_codec_timing: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut do_validation: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut do_list_mods: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut do_log_stdout: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let hdr_size: size_t = 12 as libc::c_int as size_t;
    if ::core::mem::size_of::<srtp_hdr_t>() as libc::c_ulong != hdr_size {
        printf(
            b"error: srtp_hdr_t has incorrect size(size is %ld bytes, expected %ld)\n\0"
                as *const u8 as *const libc::c_char,
            ::core::mem::size_of::<srtp_hdr_t>() as libc::c_ulong as libc::c_long,
            hdr_size as libc::c_long,
        );
        exit(1 as libc::c_int);
    }
    status = srtp_init();
    if status as u64 != 0 {
        printf(
            b"error: srtp init failed with error code %d\n\0" as *const u8
                as *const libc::c_char,
            status as libc::c_uint,
        );
        exit(1 as libc::c_int);
    }
    status = srtp_crypto_kernel_load_debug_module(&mut mod_driver);
    if status as u64 != 0 {
        printf(
            b"error: load of srtp_driver debug module failed with error code %d\n\0"
                as *const u8 as *const libc::c_char,
            status as libc::c_uint,
        );
        exit(1 as libc::c_int);
    }
    loop {
        q = getopt_s(
            argc,
            argv as *const *mut libc::c_char,
            b"trcvold:\0" as *const u8 as *const libc::c_char,
        );
        if q == -(1 as libc::c_int) {
            break;
        }
        match q {
            116 => {
                do_timing_test = 1 as libc::c_int as libc::c_uint;
            }
            114 => {
                do_rejection_test = 1 as libc::c_int as libc::c_uint;
            }
            99 => {
                do_codec_timing = 1 as libc::c_int as libc::c_uint;
            }
            118 => {
                do_validation = 1 as libc::c_int as libc::c_uint;
            }
            111 => {
                do_log_stdout = 1 as libc::c_int as libc::c_uint;
            }
            108 => {
                do_list_mods = 1 as libc::c_int as libc::c_uint;
            }
            100 => {
                status = srtp_set_debug_module(optarg_s, 1 as libc::c_int);
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
    if do_validation == 0 && do_timing_test == 0 && do_codec_timing == 0
        && do_list_mods == 0 && do_rejection_test == 0
    {
        usage(*argv.offset(0 as libc::c_int as isize));
    }
    if do_log_stdout != 0 {
        status = srtp_install_log_handler(
            Some(
                log_handler
                    as unsafe extern "C" fn(
                        srtp_log_level_t,
                        *const libc::c_char,
                        *mut libc::c_void,
                    ) -> (),
            ),
            0 as *mut libc::c_void,
        );
        if status as u64 != 0 {
            printf(
                b"error: install log handler failed\n\0" as *const u8
                    as *const libc::c_char,
            );
            exit(1 as libc::c_int);
        }
    }
    if do_list_mods != 0 {
        status = srtp_list_debug_modules();
        if status as u64 != 0 {
            printf(
                b"error: list of debug modules failed\n\0" as *const u8
                    as *const libc::c_char,
            );
            exit(1 as libc::c_int);
        }
    }
    if do_validation != 0 {
        let mut policy: *mut *const srtp_policy_t = policy_array.as_mut_ptr();
        let mut big_policy: *mut srtp_policy_t = 0 as *mut srtp_policy_t;
        let mut srtp_sender: srtp_t = 0 as *mut srtp_ctx_t;
        while !(*policy).is_null() {
            printf(
                b"testing srtp_protect and srtp_unprotect\n\0" as *const u8
                    as *const libc::c_char,
            );
            if srtp_test(*policy, 0 as libc::c_int, -(1 as libc::c_int)) as libc::c_uint
                == srtp_err_status_ok as libc::c_int as libc::c_uint
            {
                printf(b"passed\n\n\0" as *const u8 as *const libc::c_char);
            } else {
                printf(b"failed\n\0" as *const u8 as *const libc::c_char);
                exit(1 as libc::c_int);
            }
            printf(
                b"testing srtp_protect and srtp_unprotect with encrypted extensions headers\n\0"
                    as *const u8 as *const libc::c_char,
            );
            if srtp_test(*policy, 1 as libc::c_int, -(1 as libc::c_int)) as libc::c_uint
                == srtp_err_status_ok as libc::c_int as libc::c_uint
            {
                printf(b"passed\n\n\0" as *const u8 as *const libc::c_char);
            } else {
                printf(b"failed\n\0" as *const u8 as *const libc::c_char);
                exit(1 as libc::c_int);
            }
            printf(
                b"testing srtp_protect_rtcp and srtp_unprotect_rtcp\n\0" as *const u8
                    as *const libc::c_char,
            );
            if srtcp_test(*policy, -(1 as libc::c_int)) as libc::c_uint
                == srtp_err_status_ok as libc::c_int as libc::c_uint
            {
                printf(b"passed\n\n\0" as *const u8 as *const libc::c_char);
            } else {
                printf(b"failed\n\0" as *const u8 as *const libc::c_char);
                exit(1 as libc::c_int);
            }
            printf(
                b"testing srtp_protect_rtp and srtp_unprotect_rtp with MKI index set to 0\n\0"
                    as *const u8 as *const libc::c_char,
            );
            if srtp_test(*policy, 0 as libc::c_int, 0 as libc::c_int) as libc::c_uint
                == srtp_err_status_ok as libc::c_int as libc::c_uint
            {
                printf(b"passed\n\n\0" as *const u8 as *const libc::c_char);
            } else {
                printf(b"failed\n\0" as *const u8 as *const libc::c_char);
                exit(1 as libc::c_int);
            }
            printf(
                b"testing srtp_protect_rtp and srtp_unprotect_rtp with MKI index set to 1\n\0"
                    as *const u8 as *const libc::c_char,
            );
            if srtp_test(*policy, 0 as libc::c_int, 1 as libc::c_int) as libc::c_uint
                == srtp_err_status_ok as libc::c_int as libc::c_uint
            {
                printf(b"passed\n\n\0" as *const u8 as *const libc::c_char);
            } else {
                printf(b"failed\n\0" as *const u8 as *const libc::c_char);
                exit(1 as libc::c_int);
            }
            printf(
                b"testing srtp_protect_rtcp and srtp_unprotect_rtcp with MKI index set to 0\n\0"
                    as *const u8 as *const libc::c_char,
            );
            if srtcp_test(*policy, 0 as libc::c_int) as libc::c_uint
                == srtp_err_status_ok as libc::c_int as libc::c_uint
            {
                printf(b"passed\n\n\0" as *const u8 as *const libc::c_char);
            } else {
                printf(b"failed\n\0" as *const u8 as *const libc::c_char);
                exit(1 as libc::c_int);
            }
            printf(
                b"testing srtp_protect_rtcp and srtp_unprotect_rtcp with MKI index set to 1\n\0"
                    as *const u8 as *const libc::c_char,
            );
            if srtcp_test(*policy, 1 as libc::c_int) as libc::c_uint
                == srtp_err_status_ok as libc::c_int as libc::c_uint
            {
                printf(b"passed\n\n\0" as *const u8 as *const libc::c_char);
            } else {
                printf(b"failed\n\0" as *const u8 as *const libc::c_char);
                exit(1 as libc::c_int);
            }
            policy = policy.offset(1);
        }
        policy = invalid_policy_array.as_mut_ptr();
        while !(*policy).is_null() {
            printf(
                b"testing srtp_create fails with invalid policy\n\0" as *const u8
                    as *const libc::c_char,
            );
            if srtp_create(&mut srtp_sender, *policy) as libc::c_uint
                != srtp_err_status_ok as libc::c_int as libc::c_uint
            {
                printf(b"passed\n\n\0" as *const u8 as *const libc::c_char);
            } else {
                printf(b"failed\n\0" as *const u8 as *const libc::c_char);
                exit(1 as libc::c_int);
            }
            policy = policy.offset(1);
        }
        status = srtp_create_big_policy(&mut big_policy);
        if status as u64 != 0 {
            printf(
                b"unexpected failure with error code %d\n\0" as *const u8
                    as *const libc::c_char,
                status as libc::c_uint,
            );
            exit(1 as libc::c_int);
        }
        printf(
            b"testing srtp_protect and srtp_unprotect with big policy\n\0" as *const u8
                as *const libc::c_char,
        );
        if srtp_test(big_policy, 0 as libc::c_int, -(1 as libc::c_int)) as libc::c_uint
            == srtp_err_status_ok as libc::c_int as libc::c_uint
        {
            printf(b"passed\n\n\0" as *const u8 as *const libc::c_char);
        } else {
            printf(b"failed\n\0" as *const u8 as *const libc::c_char);
            exit(1 as libc::c_int);
        }
        printf(
            b"testing srtp_protect and srtp_unprotect with big policy and encrypted extensions headers\n\0"
                as *const u8 as *const libc::c_char,
        );
        if srtp_test(big_policy, 1 as libc::c_int, -(1 as libc::c_int)) as libc::c_uint
            == srtp_err_status_ok as libc::c_int as libc::c_uint
        {
            printf(b"passed\n\n\0" as *const u8 as *const libc::c_char);
        } else {
            printf(b"failed\n\0" as *const u8 as *const libc::c_char);
            exit(1 as libc::c_int);
        }
        status = srtp_dealloc_big_policy(big_policy);
        if status as u64 != 0 {
            printf(
                b"unexpected failure with error code %d\n\0" as *const u8
                    as *const libc::c_char,
                status as libc::c_uint,
            );
            exit(1 as libc::c_int);
        }
        printf(
            b"testing srtp_protect and srtp_unprotect on wildcard ssrc policy\n\0"
                as *const u8 as *const libc::c_char,
        );
        if srtp_test(&wildcard_policy, 0 as libc::c_int, -(1 as libc::c_int))
            as libc::c_uint == srtp_err_status_ok as libc::c_int as libc::c_uint
        {
            printf(b"passed\n\n\0" as *const u8 as *const libc::c_char);
        } else {
            printf(b"failed\n\0" as *const u8 as *const libc::c_char);
            exit(1 as libc::c_int);
        }
        printf(
            b"testing srtp_protect and srtp_unprotect on wildcard ssrc policy and encrypted extensions headers\n\0"
                as *const u8 as *const libc::c_char,
        );
        if srtp_test(&wildcard_policy, 1 as libc::c_int, -(1 as libc::c_int))
            as libc::c_uint == srtp_err_status_ok as libc::c_int as libc::c_uint
        {
            printf(b"passed\n\n\0" as *const u8 as *const libc::c_char);
        } else {
            printf(b"failed\n\0" as *const u8 as *const libc::c_char);
            exit(1 as libc::c_int);
        }
        printf(
            b"testing srtp_protect and srtp_unprotect against reference packet\n\0"
                as *const u8 as *const libc::c_char,
        );
        if srtp_validate() as libc::c_uint
            == srtp_err_status_ok as libc::c_int as libc::c_uint
        {
            printf(b"passed\n\n\0" as *const u8 as *const libc::c_char);
        } else {
            printf(b"failed\n\0" as *const u8 as *const libc::c_char);
            exit(1 as libc::c_int);
        }
        printf(
            b"testing srtp_protect and srtp_unprotect against reference packet using null cipher and HMAC\n\0"
                as *const u8 as *const libc::c_char,
        );
        if srtp_validate_null() as libc::c_uint
            == srtp_err_status_ok as libc::c_int as libc::c_uint
        {
            printf(b"passed\n\n\0" as *const u8 as *const libc::c_char);
        } else {
            printf(b"failed\n\0" as *const u8 as *const libc::c_char);
            exit(1 as libc::c_int);
        }
        printf(
            b"testing srtp_protect and srtp_unprotect against reference packet with encrypted extensions headers\n\0"
                as *const u8 as *const libc::c_char,
        );
        if srtp_validate_encrypted_extensions_headers() as libc::c_uint
            == srtp_err_status_ok as libc::c_int as libc::c_uint
        {
            printf(b"passed\n\n\0" as *const u8 as *const libc::c_char);
        } else {
            printf(b"failed\n\0" as *const u8 as *const libc::c_char);
            exit(1 as libc::c_int);
        }
        printf(
            b"testing srtp_protect and srtp_unprotect against reference packet (AES-256)\n\0"
                as *const u8 as *const libc::c_char,
        );
        if srtp_validate_aes_256() as libc::c_uint
            == srtp_err_status_ok as libc::c_int as libc::c_uint
        {
            printf(b"passed\n\n\0" as *const u8 as *const libc::c_char);
        } else {
            printf(b"failed\n\0" as *const u8 as *const libc::c_char);
            exit(1 as libc::c_int);
        }
        printf(
            b"testing srtp_protect and srtp_unprotect against packet with empty payload\n\0"
                as *const u8 as *const libc::c_char,
        );
        if srtp_test_empty_payload() as libc::c_uint
            == srtp_err_status_ok as libc::c_int as libc::c_uint
        {
            printf(b"passed\n\0" as *const u8 as *const libc::c_char);
        } else {
            printf(b"failed\n\0" as *const u8 as *const libc::c_char);
            exit(1 as libc::c_int);
        }
        printf(b"testing srtp_remove_stream()...\0" as *const u8 as *const libc::c_char);
        if srtp_test_remove_stream() as libc::c_uint
            == srtp_err_status_ok as libc::c_int as libc::c_uint
        {
            printf(b"passed\n\0" as *const u8 as *const libc::c_char);
        } else {
            printf(b"failed\n\0" as *const u8 as *const libc::c_char);
            exit(1 as libc::c_int);
        }
        printf(b"testing srtp_update()...\0" as *const u8 as *const libc::c_char);
        if srtp_test_update() as libc::c_uint
            == srtp_err_status_ok as libc::c_int as libc::c_uint
        {
            printf(b"passed\n\0" as *const u8 as *const libc::c_char);
        } else {
            printf(b"failed\n\0" as *const u8 as *const libc::c_char);
            exit(1 as libc::c_int);
        }
        printf(
            b"testing srtp_get_protect_trailer_length()...\0" as *const u8
                as *const libc::c_char,
        );
        if srtp_test_protect_trailer_length() as libc::c_uint
            == srtp_err_status_ok as libc::c_int as libc::c_uint
        {
            printf(b"passed\n\0" as *const u8 as *const libc::c_char);
        } else {
            printf(b"failed\n\0" as *const u8 as *const libc::c_char);
            exit(1 as libc::c_int);
        }
        printf(
            b"testing srtp_get_protect_rtcp_trailer_length()...\0" as *const u8
                as *const libc::c_char,
        );
        if srtp_test_protect_rtcp_trailer_length() as libc::c_uint
            == srtp_err_status_ok as libc::c_int as libc::c_uint
        {
            printf(b"passed\n\0" as *const u8 as *const libc::c_char);
        } else {
            printf(b"failed\n\0" as *const u8 as *const libc::c_char);
            exit(1 as libc::c_int);
        }
        printf(
            b"testing srtp_test_out_of_order_after_rollover()...\0" as *const u8
                as *const libc::c_char,
        );
        if srtp_test_out_of_order_after_rollover() as libc::c_uint
            == srtp_err_status_ok as libc::c_int as libc::c_uint
        {
            printf(b"passed\n\0" as *const u8 as *const libc::c_char);
        } else {
            printf(b"failed\n\0" as *const u8 as *const libc::c_char);
            exit(1 as libc::c_int);
        }
        printf(b"testing srtp_test_get_roc()...\0" as *const u8 as *const libc::c_char);
        if srtp_test_get_roc() as libc::c_uint
            == srtp_err_status_ok as libc::c_int as libc::c_uint
        {
            printf(b"passed\n\0" as *const u8 as *const libc::c_char);
        } else {
            printf(b"failed\n\0" as *const u8 as *const libc::c_char);
            exit(1 as libc::c_int);
        }
        printf(
            b"testing srtp_test_set_receiver_roc()...\0" as *const u8
                as *const libc::c_char,
        );
        if srtp_test_set_receiver_roc() as libc::c_uint
            == srtp_err_status_ok as libc::c_int as libc::c_uint
        {
            printf(b"passed\n\0" as *const u8 as *const libc::c_char);
        } else {
            printf(b"failed\n\0" as *const u8 as *const libc::c_char);
            exit(1 as libc::c_int);
        }
        printf(
            b"testing srtp_test_set_sender_roc()...\0" as *const u8
                as *const libc::c_char,
        );
        if srtp_test_set_sender_roc() as libc::c_uint
            == srtp_err_status_ok as libc::c_int as libc::c_uint
        {
            printf(b"passed\n\0" as *const u8 as *const libc::c_char);
        } else {
            printf(b"failed\n\0" as *const u8 as *const libc::c_char);
            exit(1 as libc::c_int);
        }
    }
    if do_timing_test != 0 {
        let mut policy_0: *mut *const srtp_policy_t = policy_array.as_mut_ptr();
        while !(*policy_0).is_null() {
            srtp_print_policy(*policy_0);
            srtp_do_timing(*policy_0);
            policy_0 = policy_0.offset(1);
        }
    }
    if do_rejection_test != 0 {
        let mut policy_1: *mut *const srtp_policy_t = policy_array.as_mut_ptr();
        while !(*policy_1).is_null() {
            srtp_print_policy(*policy_1);
            srtp_do_rejection_timing(*policy_1);
            policy_1 = policy_1.offset(1);
        }
    }
    if do_codec_timing != 0 {
        let mut policy_2: srtp_policy_t = srtp_policy_t {
            ssrc: srtp_ssrc_t {
                type_0: ssrc_undefined,
                value: 0,
            },
            rtp: srtp_crypto_policy_t {
                cipher_type: 0,
                cipher_key_len: 0,
                auth_type: 0,
                auth_key_len: 0,
                auth_tag_len: 0,
                sec_serv: sec_serv_none,
            },
            rtcp: srtp_crypto_policy_t {
                cipher_type: 0,
                cipher_key_len: 0,
                auth_type: 0,
                auth_key_len: 0,
                auth_tag_len: 0,
                sec_serv: sec_serv_none,
            },
            key: 0 as *mut libc::c_uchar,
            keys: 0 as *mut *mut srtp_master_key_t,
            num_master_keys: 0,
            deprecated_ekt: 0 as *mut libc::c_void,
            window_size: 0,
            allow_repeat_tx: 0,
            enc_xtn_hdr: 0 as *mut libc::c_int,
            enc_xtn_hdr_count: 0,
            next: 0 as *mut srtp_policy_t,
        };
        let mut ignore: libc::c_int = 0;
        let mut mips_value: libc::c_double = mips_estimate(
            1000000000 as libc::c_int,
            &mut ignore,
        );
        memset(
            &mut policy_2 as *mut srtp_policy_t as *mut libc::c_void,
            0 as libc::c_int,
            ::core::mem::size_of::<srtp_policy_t>() as libc::c_ulong,
        );
        srtp_crypto_policy_set_rtp_default(&mut policy_2.rtp);
        srtp_crypto_policy_set_rtcp_default(&mut policy_2.rtcp);
        policy_2.ssrc.type_0 = ssrc_specific;
        policy_2.ssrc.value = 0xdecafbad as libc::c_uint;
        policy_2.key = test_key.as_mut_ptr();
        policy_2.deprecated_ekt = 0 as *mut libc::c_void;
        policy_2.window_size = 128 as libc::c_int as libc::c_ulong;
        policy_2.allow_repeat_tx = 0 as libc::c_int;
        policy_2.next = 0 as *mut srtp_policy_t;
        printf(b"mips estimate: %e\n\0" as *const u8 as *const libc::c_char, mips_value);
        printf(
            b"testing srtp processing time for voice codecs:\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(
            b"codec\t\tlength (octets)\t\tsrtp instructions/second\n\0" as *const u8
                as *const libc::c_char,
        );
        printf(
            b"G.711\t\t%d\t\t\t%e\n\0" as *const u8 as *const libc::c_char,
            80 as libc::c_int,
            mips_value * (80 as libc::c_int * 8 as libc::c_int) as libc::c_double
                / srtp_bits_per_second(80 as libc::c_int, &mut policy_2) / 0.01f64,
        );
        printf(
            b"G.711\t\t%d\t\t\t%e\n\0" as *const u8 as *const libc::c_char,
            160 as libc::c_int,
            mips_value * (160 as libc::c_int * 8 as libc::c_int) as libc::c_double
                / srtp_bits_per_second(160 as libc::c_int, &mut policy_2) / 0.02f64,
        );
        printf(
            b"G.726-32\t%d\t\t\t%e\n\0" as *const u8 as *const libc::c_char,
            40 as libc::c_int,
            mips_value * (40 as libc::c_int * 8 as libc::c_int) as libc::c_double
                / srtp_bits_per_second(40 as libc::c_int, &mut policy_2) / 0.01f64,
        );
        printf(
            b"G.726-32\t%d\t\t\t%e\n\0" as *const u8 as *const libc::c_char,
            80 as libc::c_int,
            mips_value * (80 as libc::c_int * 8 as libc::c_int) as libc::c_double
                / srtp_bits_per_second(80 as libc::c_int, &mut policy_2) / 0.02f64,
        );
        printf(
            b"G.729\t\t%d\t\t\t%e\n\0" as *const u8 as *const libc::c_char,
            10 as libc::c_int,
            mips_value * (10 as libc::c_int * 8 as libc::c_int) as libc::c_double
                / srtp_bits_per_second(10 as libc::c_int, &mut policy_2) / 0.01f64,
        );
        printf(
            b"G.729\t\t%d\t\t\t%e\n\0" as *const u8 as *const libc::c_char,
            20 as libc::c_int,
            mips_value * (20 as libc::c_int * 8 as libc::c_int) as libc::c_double
                / srtp_bits_per_second(20 as libc::c_int, &mut policy_2) / 0.02f64,
        );
        printf(
            b"Wideband\t%d\t\t\t%e\n\0" as *const u8 as *const libc::c_char,
            320 as libc::c_int,
            mips_value * (320 as libc::c_int * 8 as libc::c_int) as libc::c_double
                / srtp_bits_per_second(320 as libc::c_int, &mut policy_2) / 0.01f64,
        );
        printf(
            b"Wideband\t%d\t\t\t%e\n\0" as *const u8 as *const libc::c_char,
            640 as libc::c_int,
            mips_value * (640 as libc::c_int * 8 as libc::c_int) as libc::c_double
                / srtp_bits_per_second(640 as libc::c_int, &mut policy_2) / 0.02f64,
        );
    }
    status = srtp_shutdown();
    if status as u64 != 0 {
        printf(
            b"error: srtp shutdown failed with error code %d\n\0" as *const u8
                as *const libc::c_char,
            status as libc::c_uint,
        );
        exit(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_create_test_packet(
    mut pkt_octet_len: libc::c_int,
    mut ssrc: uint32_t,
    mut pkt_len: *mut libc::c_int,
) -> *mut srtp_hdr_t {
    let mut i: libc::c_int = 0;
    let mut buffer: *mut uint8_t = 0 as *mut uint8_t;
    let mut hdr: *mut srtp_hdr_t = 0 as *mut srtp_hdr_t;
    let mut bytes_in_hdr: libc::c_int = 12 as libc::c_int;
    hdr = malloc(
        (pkt_octet_len + bytes_in_hdr + (16 as libc::c_int + 128 as libc::c_int)
            + 4 as libc::c_int) as libc::c_ulong,
    ) as *mut srtp_hdr_t;
    if hdr.is_null() {
        return 0 as *mut srtp_hdr_t;
    }
    (*hdr).set_version(2 as libc::c_int as libc::c_uchar);
    (*hdr).set_p(0 as libc::c_int as libc::c_uchar);
    (*hdr).set_x(0 as libc::c_int as libc::c_uchar);
    (*hdr).set_cc(0 as libc::c_int as libc::c_uchar);
    (*hdr).set_m(0 as libc::c_int as libc::c_uchar);
    (*hdr).set_pt(0xf as libc::c_int as libc::c_uchar);
    (*hdr).seq = __bswap_16(0x1234 as libc::c_int as __uint16_t);
    (*hdr).ts = __bswap_32(0xdecafbad as libc::c_uint);
    (*hdr).ssrc = __bswap_32(ssrc);
    buffer = hdr as *mut uint8_t;
    buffer = buffer.offset(bytes_in_hdr as isize);
    i = 0 as libc::c_int;
    while i < pkt_octet_len {
        let fresh0 = buffer;
        buffer = buffer.offset(1);
        *fresh0 = 0xab as libc::c_int as uint8_t;
        i += 1;
    }
    i = 0 as libc::c_int;
    while i < 16 as libc::c_int + 128 as libc::c_int + 4 as libc::c_int {
        let fresh1 = buffer;
        buffer = buffer.offset(1);
        *fresh1 = 0xff as libc::c_int as uint8_t;
        i += 1;
    }
    *pkt_len = bytes_in_hdr + pkt_octet_len;
    return hdr;
}
unsafe extern "C" fn srtp_create_test_packet_extended(
    mut pkt_octet_len: libc::c_int,
    mut ssrc: uint32_t,
    mut seq: uint16_t,
    mut ts: uint32_t,
    mut pkt_len: *mut libc::c_int,
) -> *mut srtp_hdr_t {
    let mut hdr: *mut srtp_hdr_t = 0 as *mut srtp_hdr_t;
    hdr = srtp_create_test_packet(pkt_octet_len, ssrc, pkt_len);
    if hdr.is_null() {
        return hdr;
    }
    (*hdr).seq = __bswap_16(seq);
    (*hdr).ts = __bswap_32(ts);
    return hdr;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_create_test_packet_ext_hdr(
    mut pkt_octet_len: libc::c_int,
    mut ssrc: uint32_t,
    mut pkt_len: *mut libc::c_int,
) -> *mut srtp_hdr_t {
    let mut i: libc::c_int = 0;
    let mut buffer: *mut uint8_t = 0 as *mut uint8_t;
    let mut hdr: *mut srtp_hdr_t = 0 as *mut srtp_hdr_t;
    let mut bytes_in_hdr: libc::c_int = 12 as libc::c_int;
    let mut extension_header: [uint8_t; 12] = [
        0xbe as libc::c_int as uint8_t,
        0xde as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0x2 as libc::c_int as uint8_t,
        0x11 as libc::c_int as uint8_t,
        0xca as libc::c_int as uint8_t,
        0xfe as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0x20 as libc::c_int as uint8_t,
        0xba as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
    ];
    hdr = malloc(
        ((pkt_octet_len + bytes_in_hdr) as libc::c_ulong)
            .wrapping_add(::core::mem::size_of::<[uint8_t; 12]>() as libc::c_ulong)
            .wrapping_add((16 as libc::c_int + 128 as libc::c_int) as libc::c_ulong)
            .wrapping_add(4 as libc::c_int as libc::c_ulong),
    ) as *mut srtp_hdr_t;
    if hdr.is_null() {
        return 0 as *mut srtp_hdr_t;
    }
    (*hdr).set_version(2 as libc::c_int as libc::c_uchar);
    (*hdr).set_p(0 as libc::c_int as libc::c_uchar);
    (*hdr).set_x(1 as libc::c_int as libc::c_uchar);
    (*hdr).set_cc(0 as libc::c_int as libc::c_uchar);
    (*hdr).set_m(0 as libc::c_int as libc::c_uchar);
    (*hdr).set_pt(0xf as libc::c_int as libc::c_uchar);
    (*hdr).seq = __bswap_16(0x1234 as libc::c_int as __uint16_t);
    (*hdr).ts = __bswap_32(0xdecafbad as libc::c_uint);
    (*hdr).ssrc = __bswap_32(ssrc);
    buffer = hdr as *mut uint8_t;
    buffer = buffer.offset(bytes_in_hdr as isize);
    memcpy(
        buffer as *mut libc::c_void,
        extension_header.as_mut_ptr() as *const libc::c_void,
        ::core::mem::size_of::<[uint8_t; 12]>() as libc::c_ulong,
    );
    buffer = buffer
        .offset(::core::mem::size_of::<[uint8_t; 12]>() as libc::c_ulong as isize);
    i = 0 as libc::c_int;
    while i < pkt_octet_len {
        let fresh2 = buffer;
        buffer = buffer.offset(1);
        *fresh2 = 0xab as libc::c_int as uint8_t;
        i += 1;
    }
    i = 0 as libc::c_int;
    while i < 16 as libc::c_int + 128 as libc::c_int + 4 as libc::c_int {
        let fresh3 = buffer;
        buffer = buffer.offset(1);
        *fresh3 = 0xff as libc::c_int as uint8_t;
        i += 1;
    }
    *pkt_len = (bytes_in_hdr as libc::c_ulong)
        .wrapping_add(::core::mem::size_of::<[uint8_t; 12]>() as libc::c_ulong)
        .wrapping_add(pkt_octet_len as libc::c_ulong) as libc::c_int;
    return hdr;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_do_timing(mut policy: *const srtp_policy_t) {
    let mut len: libc::c_int = 0;
    printf(b"# testing srtp throughput:\r\n\0" as *const u8 as *const libc::c_char);
    printf(
        b"# mesg length (octets)\tthroughput (megabits per second)\r\n\0" as *const u8
            as *const libc::c_char,
    );
    len = 16 as libc::c_int;
    while len <= 2048 as libc::c_int {
        printf(
            b"%d\t\t\t%f\r\n\0" as *const u8 as *const libc::c_char,
            len,
            srtp_bits_per_second(len, policy) / 1.0E6f64,
        );
        len *= 2 as libc::c_int;
    }
    printf(b"\r\n\r\n\0" as *const u8 as *const libc::c_char);
}
#[no_mangle]
pub unsafe extern "C" fn srtp_do_rejection_timing(mut policy: *const srtp_policy_t) {
    let mut len: libc::c_int = 0;
    printf(
        b"# testing srtp rejection throughput:\r\n\0" as *const u8 as *const libc::c_char,
    );
    printf(
        b"# mesg length (octets)\trejections per second\r\n\0" as *const u8
            as *const libc::c_char,
    );
    len = 8 as libc::c_int;
    while len <= 2048 as libc::c_int {
        printf(
            b"%d\t\t\t%e\r\n\0" as *const u8 as *const libc::c_char,
            len,
            srtp_rejections_per_second(len, policy),
        );
        len *= 2 as libc::c_int;
    }
    printf(b"\r\n\r\n\0" as *const u8 as *const libc::c_char);
}
#[no_mangle]
pub unsafe extern "C" fn srtp_bits_per_second(
    mut msg_len_octets: libc::c_int,
    mut policy: *const srtp_policy_t,
) -> libc::c_double {
    let mut srtp: srtp_t = 0 as *mut srtp_ctx_t;
    let mut mesg: *mut srtp_hdr_t = 0 as *mut srtp_hdr_t;
    let mut i: libc::c_int = 0;
    let mut timer: clock_t = 0;
    let mut num_trials: libc::c_int = 100000 as libc::c_int;
    let mut input_len: libc::c_int = 0;
    let mut len: libc::c_int = 0;
    let mut ssrc: uint32_t = 0;
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    status = srtp_create(&mut srtp, policy);
    if status as u64 != 0 {
        printf(
            b"error: srtp_create() failed with error code %d\n\0" as *const u8
                as *const libc::c_char,
            status as libc::c_uint,
        );
        exit(1 as libc::c_int);
    }
    if (*policy).ssrc.type_0 as libc::c_uint
        != ssrc_specific as libc::c_int as libc::c_uint
    {
        ssrc = 0xdeadbeef as libc::c_uint;
    } else {
        ssrc = (*policy).ssrc.value;
    }
    mesg = srtp_create_test_packet(msg_len_octets, ssrc, &mut input_len);
    if mesg.is_null() {
        return 0.0f64;
    }
    timer = clock();
    i = 0 as libc::c_int;
    while i < num_trials {
        len = input_len;
        status = srtp_protect(srtp, mesg as *mut libc::c_void, &mut len);
        if status as u64 != 0 {
            printf(
                b"error: srtp_protect() failed with error code %d\n\0" as *const u8
                    as *const libc::c_char,
                status as libc::c_uint,
            );
            exit(1 as libc::c_int);
        }
        let mut new_seq: libc::c_short = (__bswap_16((*mesg).seq) as libc::c_int
            + 1 as libc::c_int) as libc::c_short;
        (*mesg).seq = __bswap_16(new_seq as __uint16_t);
        i += 1;
    }
    timer = clock() - timer;
    free(mesg as *mut libc::c_void);
    status = srtp_dealloc(srtp);
    if status as u64 != 0 {
        printf(
            b"error: srtp_dealloc() failed with error code %d\n\0" as *const u8
                as *const libc::c_char,
            status as libc::c_uint,
        );
        exit(1 as libc::c_int);
    }
    return msg_len_octets as libc::c_double * 8 as libc::c_int as libc::c_double
        * num_trials as libc::c_double
        * 1000000 as libc::c_int as __clock_t as libc::c_double
        / timer as libc::c_double;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_rejections_per_second(
    mut msg_len_octets: libc::c_int,
    mut policy: *const srtp_policy_t,
) -> libc::c_double {
    let mut srtp: *mut srtp_ctx_t = 0 as *mut srtp_ctx_t;
    let mut mesg: *mut srtp_hdr_t = 0 as *mut srtp_hdr_t;
    let mut i: libc::c_int = 0;
    let mut len: libc::c_int = 0;
    let mut timer: clock_t = 0;
    let mut num_trials: libc::c_int = 1000000 as libc::c_int;
    let mut ssrc: uint32_t = (*policy).ssrc.value;
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    status = srtp_create(&mut srtp, policy);
    if status as u64 != 0 {
        printf(
            b"error: srtp_create() failed with error code %d\n\0" as *const u8
                as *const libc::c_char,
            status as libc::c_uint,
        );
        exit(1 as libc::c_int);
    }
    mesg = srtp_create_test_packet(msg_len_octets, ssrc, &mut len);
    if mesg.is_null() {
        return 0.0f64;
    }
    srtp_protect(srtp, mesg as *mut libc::c_void, &mut len);
    timer = clock();
    i = 0 as libc::c_int;
    while i < num_trials {
        len = msg_len_octets;
        srtp_unprotect(srtp, mesg as *mut libc::c_void, &mut len);
        i += 1;
    }
    timer = clock() - timer;
    free(mesg as *mut libc::c_void);
    status = srtp_dealloc(srtp);
    if status as u64 != 0 {
        printf(
            b"error: srtp_dealloc() failed with error code %d\n\0" as *const u8
                as *const libc::c_char,
            status as libc::c_uint,
        );
        exit(1 as libc::c_int);
    }
    return num_trials as libc::c_double
        * 1000000 as libc::c_int as __clock_t as libc::c_double
        / timer as libc::c_double;
}
#[no_mangle]
pub unsafe extern "C" fn err_check(mut s: srtp_err_status_t) {
    if s as libc::c_uint != srtp_err_status_ok as libc::c_int as libc::c_uint {
        fprintf(
            stderr,
            b"error: unexpected srtp failure (code %d)\n\0" as *const u8
                as *const libc::c_char,
            s as libc::c_uint,
        );
        exit(1 as libc::c_int);
    }
}
#[no_mangle]
pub unsafe extern "C" fn srtp_test_call_protect(
    mut srtp_sender: srtp_t,
    mut hdr: *mut srtp_hdr_t,
    mut len: *mut libc::c_int,
    mut mki_index: libc::c_int,
) -> srtp_err_status_t {
    if mki_index == -(1 as libc::c_int) {
        return srtp_protect(srtp_sender, hdr as *mut libc::c_void, len)
    } else {
        return srtp_protect_mki(
            srtp_sender,
            hdr as *mut libc::c_void,
            len,
            1 as libc::c_int as libc::c_uint,
            mki_index as libc::c_uint,
        )
    };
}
#[no_mangle]
pub unsafe extern "C" fn srtp_test_call_protect_rtcp(
    mut srtp_sender: srtp_t,
    mut hdr: *mut srtp_hdr_t,
    mut len: *mut libc::c_int,
    mut mki_index: libc::c_int,
) -> srtp_err_status_t {
    if mki_index == -(1 as libc::c_int) {
        return srtp_protect_rtcp(srtp_sender, hdr as *mut libc::c_void, len)
    } else {
        return srtp_protect_rtcp_mki(
            srtp_sender,
            hdr as *mut libc::c_void,
            len,
            1 as libc::c_int as libc::c_uint,
            mki_index as libc::c_uint,
        )
    };
}
#[no_mangle]
pub unsafe extern "C" fn srtp_test_call_unprotect(
    mut srtp_sender: srtp_t,
    mut hdr: *mut srtp_hdr_t,
    mut len: *mut libc::c_int,
    mut use_mki: libc::c_int,
) -> srtp_err_status_t {
    if use_mki == -(1 as libc::c_int) {
        return srtp_unprotect(srtp_sender, hdr as *mut libc::c_void, len)
    } else {
        return srtp_unprotect_mki(
            srtp_sender,
            hdr as *mut libc::c_void,
            len,
            use_mki as libc::c_uint,
        )
    };
}
#[no_mangle]
pub unsafe extern "C" fn srtp_test_call_unprotect_rtcp(
    mut srtp_sender: srtp_t,
    mut hdr: *mut srtp_hdr_t,
    mut len: *mut libc::c_int,
    mut use_mki: libc::c_int,
) -> srtp_err_status_t {
    if use_mki == -(1 as libc::c_int) {
        return srtp_unprotect_rtcp(srtp_sender, hdr as *mut libc::c_void, len)
    } else {
        return srtp_unprotect_rtcp_mki(
            srtp_sender,
            hdr as *mut libc::c_void,
            len,
            use_mki as libc::c_uint,
        )
    };
}
#[no_mangle]
pub unsafe extern "C" fn srtp_test(
    mut policy: *const srtp_policy_t,
    mut extension_header: libc::c_int,
    mut mki_index: libc::c_int,
) -> srtp_err_status_t {
    let mut i: libc::c_int = 0;
    let mut srtp_sender: srtp_t = 0 as *mut srtp_ctx_t;
    let mut srtp_rcvr: srtp_t = 0 as *mut srtp_ctx_t;
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut hdr: *mut srtp_hdr_t = 0 as *mut srtp_hdr_t;
    let mut hdr2: *mut srtp_hdr_t = 0 as *mut srtp_hdr_t;
    let mut hdr_enc: [uint8_t; 64] = [0; 64];
    let mut pkt_end: *mut uint8_t = 0 as *mut uint8_t;
    let mut msg_len_octets: libc::c_int = 0;
    let mut msg_len_enc: libc::c_int = 0;
    let mut msg_len: libc::c_int = 0;
    let mut len: libc::c_int = 0;
    let mut len2: libc::c_int = 0;
    let mut tag_length: uint32_t = 0;
    let mut ssrc: uint32_t = 0;
    let mut rcvr_policy: *mut srtp_policy_t = 0 as *mut srtp_policy_t;
    let mut tmp_policy: srtp_policy_t = srtp_policy_t {
        ssrc: srtp_ssrc_t {
            type_0: ssrc_undefined,
            value: 0,
        },
        rtp: srtp_crypto_policy_t {
            cipher_type: 0,
            cipher_key_len: 0,
            auth_type: 0,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: sec_serv_none,
        },
        rtcp: srtp_crypto_policy_t {
            cipher_type: 0,
            cipher_key_len: 0,
            auth_type: 0,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: sec_serv_none,
        },
        key: 0 as *mut libc::c_uchar,
        keys: 0 as *mut *mut srtp_master_key_t,
        num_master_keys: 0,
        deprecated_ekt: 0 as *mut libc::c_void,
        window_size: 0,
        allow_repeat_tx: 0,
        enc_xtn_hdr: 0 as *mut libc::c_int,
        enc_xtn_hdr_count: 0,
        next: 0 as *mut srtp_policy_t,
    };
    let mut header: libc::c_int = 1 as libc::c_int;
    let mut use_mki: libc::c_int = 0 as libc::c_int;
    if mki_index >= 0 as libc::c_int {
        use_mki = 1 as libc::c_int;
    }
    if extension_header != 0 {
        memcpy(
            &mut tmp_policy as *mut srtp_policy_t as *mut libc::c_void,
            policy as *const libc::c_void,
            ::core::mem::size_of::<srtp_policy_t>() as libc::c_ulong,
        );
        tmp_policy.enc_xtn_hdr = &mut header;
        tmp_policy.enc_xtn_hdr_count = 1 as libc::c_int;
        err_check(srtp_create(&mut srtp_sender, &mut tmp_policy));
    } else {
        err_check(srtp_create(&mut srtp_sender, policy));
    }
    err_check(srtp_session_print_policy(srtp_sender));
    if (*policy).ssrc.type_0 as libc::c_uint
        != ssrc_specific as libc::c_int as libc::c_uint
    {
        ssrc = 0xdecafbad as libc::c_uint;
    } else {
        ssrc = (*policy).ssrc.value;
    }
    msg_len_octets = 28 as libc::c_int;
    if extension_header != 0 {
        hdr = srtp_create_test_packet_ext_hdr(msg_len_octets, ssrc, &mut len);
        hdr2 = srtp_create_test_packet_ext_hdr(msg_len_octets, ssrc, &mut len2);
    } else {
        hdr = srtp_create_test_packet(msg_len_octets, ssrc, &mut len);
        hdr2 = srtp_create_test_packet(msg_len_octets, ssrc, &mut len2);
    }
    msg_len = len;
    if hdr.is_null() {
        free(hdr2 as *mut libc::c_void);
        return srtp_err_status_alloc_fail;
    }
    if hdr2.is_null() {
        free(hdr as *mut libc::c_void);
        return srtp_err_status_alloc_fail;
    }
    if mod_driver.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: before protection:\n%s\n\0" as *const u8 as *const libc::c_char,
            mod_driver.name,
            srtp_packet_to_string(hdr, len),
        );
    }
    if mod_driver.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: reference packet before protection:\n%s\n\0" as *const u8
                as *const libc::c_char,
            mod_driver.name,
            octet_string_hex_string(hdr as *mut uint8_t as *const libc::c_void, len),
        );
    }
    err_check(srtp_test_call_protect(srtp_sender, hdr, &mut len, mki_index));
    if mod_driver.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: after protection:\n%s\n\0" as *const u8 as *const libc::c_char,
            mod_driver.name,
            srtp_packet_to_string(hdr, len),
        );
    }
    if mod_driver.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: after protection:\n%s\n\0" as *const u8 as *const libc::c_char,
            mod_driver.name,
            octet_string_hex_string(hdr as *mut uint8_t as *const libc::c_void, len),
        );
    }
    memcpy(
        hdr_enc.as_mut_ptr() as *mut libc::c_void,
        hdr as *const libc::c_void,
        len as libc::c_ulong,
    );
    msg_len_enc = len;
    err_check(
        srtp_get_protect_trailer_length(
            srtp_sender,
            use_mki as uint32_t,
            mki_index as uint32_t,
            &mut tag_length,
        ),
    );
    pkt_end = (hdr as *mut uint8_t).offset(msg_len as isize).offset(tag_length as isize);
    i = 0 as libc::c_int;
    while i < 4 as libc::c_int {
        if *pkt_end.offset(i as isize) as libc::c_int != 0xff as libc::c_int {
            fprintf(
                stdout,
                b"overwrite in srtp_protect() function (expected %x, found %x in trailing octet %d)\n\0"
                    as *const u8 as *const libc::c_char,
                0xff as libc::c_int,
                *(hdr as *mut uint8_t).offset(i as isize) as libc::c_int,
                i,
            );
            free(hdr as *mut libc::c_void);
            free(hdr2 as *mut libc::c_void);
            return srtp_err_status_algo_fail;
        }
        i += 1;
    }
    if (*policy).rtp.sec_serv as libc::c_uint
        & sec_serv_conf as libc::c_int as libc::c_uint != 0
        && msg_len_octets >= 4 as libc::c_int
    {
        printf(
            b"testing that ciphertext is distinct from plaintext...\0" as *const u8
                as *const libc::c_char,
        );
        status = srtp_err_status_algo_fail;
        i = 12 as libc::c_int;
        while i < msg_len_octets + 12 as libc::c_int {
            if *(hdr as *mut uint8_t).offset(i as isize) as libc::c_int
                != *(hdr2 as *mut uint8_t).offset(i as isize) as libc::c_int
            {
                status = srtp_err_status_ok;
            }
            i += 1;
        }
        if status as u64 != 0 {
            printf(b"failed\n\0" as *const u8 as *const libc::c_char);
            free(hdr as *mut libc::c_void);
            free(hdr2 as *mut libc::c_void);
            return status;
        }
        printf(b"passed\n\0" as *const u8 as *const libc::c_char);
    }
    rcvr_policy = malloc(::core::mem::size_of::<srtp_policy_t>() as libc::c_ulong)
        as *mut srtp_policy_t;
    if rcvr_policy.is_null() {
        free(hdr as *mut libc::c_void);
        free(hdr2 as *mut libc::c_void);
        return srtp_err_status_alloc_fail;
    }
    if extension_header != 0 {
        memcpy(
            rcvr_policy as *mut libc::c_void,
            &mut tmp_policy as *mut srtp_policy_t as *const libc::c_void,
            ::core::mem::size_of::<srtp_policy_t>() as libc::c_ulong,
        );
        if tmp_policy.ssrc.type_0 as libc::c_uint
            == ssrc_any_outbound as libc::c_int as libc::c_uint
        {
            (*rcvr_policy).ssrc.type_0 = ssrc_any_inbound;
        }
    } else {
        memcpy(
            rcvr_policy as *mut libc::c_void,
            policy as *const libc::c_void,
            ::core::mem::size_of::<srtp_policy_t>() as libc::c_ulong,
        );
        if (*policy).ssrc.type_0 as libc::c_uint
            == ssrc_any_outbound as libc::c_int as libc::c_uint
        {
            (*rcvr_policy).ssrc.type_0 = ssrc_any_inbound;
        }
    }
    err_check(srtp_create(&mut srtp_rcvr, rcvr_policy));
    err_check(srtp_test_call_unprotect(srtp_rcvr, hdr, &mut len, use_mki));
    if mod_driver.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: after unprotection:\n%s\n\0" as *const u8 as *const libc::c_char,
            mod_driver.name,
            srtp_packet_to_string(hdr, len),
        );
    }
    i = 0 as libc::c_int;
    while i < len {
        if *(hdr as *mut uint8_t).offset(i as isize) as libc::c_int
            != *(hdr2 as *mut uint8_t).offset(i as isize) as libc::c_int
        {
            fprintf(
                stdout,
                b"mismatch at octet %d\n\0" as *const u8 as *const libc::c_char,
                i,
            );
            status = srtp_err_status_algo_fail;
        }
        i += 1;
    }
    if status as u64 != 0 {
        free(hdr as *mut libc::c_void);
        free(hdr2 as *mut libc::c_void);
        free(rcvr_policy as *mut libc::c_void);
        return status;
    }
    if (*policy).rtp.sec_serv as libc::c_uint
        & sec_serv_auth as libc::c_int as libc::c_uint != 0
    {
        let mut data: *mut libc::c_char = (hdr as *mut libc::c_char)
            .offset(
                (if extension_header != 0 {
                    24 as libc::c_int
                } else {
                    12 as libc::c_int
                }) as isize,
            );
        printf(
            b"testing for false positives in replay check...\0" as *const u8
                as *const libc::c_char,
        );
        status = srtp_test_call_unprotect(srtp_rcvr, hdr, &mut msg_len_enc, use_mki);
        if status as libc::c_uint
            != srtp_err_status_replay_fail as libc::c_int as libc::c_uint
        {
            printf(
                b"failed with error code %d\n\0" as *const u8 as *const libc::c_char,
                status as libc::c_uint,
            );
            free(hdr as *mut libc::c_void);
            free(hdr2 as *mut libc::c_void);
            free(rcvr_policy as *mut libc::c_void);
            return status;
        } else {
            printf(b"passed\n\0" as *const u8 as *const libc::c_char);
        }
        printf(
            b"testing for false positives in auth check...\0" as *const u8
                as *const libc::c_char,
        );
        (*hdr).seq = ((*hdr).seq).wrapping_add(1);
        err_check(srtp_test_call_protect(srtp_sender, hdr, &mut len, mki_index));
        let ref mut fresh4 = *data.offset(0 as libc::c_int as isize);
        *fresh4 = (*fresh4 as libc::c_int ^ 0xff as libc::c_int) as libc::c_char;
        status = srtp_test_call_unprotect(srtp_rcvr, hdr, &mut len, use_mki);
        if status as libc::c_uint
            != srtp_err_status_auth_fail as libc::c_int as libc::c_uint
        {
            printf(b"failed\n\0" as *const u8 as *const libc::c_char);
            free(hdr as *mut libc::c_void);
            free(hdr2 as *mut libc::c_void);
            free(rcvr_policy as *mut libc::c_void);
            return status;
        } else {
            printf(b"passed\n\0" as *const u8 as *const libc::c_char);
        }
    }
    err_check(srtp_dealloc(srtp_sender));
    err_check(srtp_dealloc(srtp_rcvr));
    free(hdr as *mut libc::c_void);
    free(hdr2 as *mut libc::c_void);
    free(rcvr_policy as *mut libc::c_void);
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtcp_test(
    mut policy: *const srtp_policy_t,
    mut mki_index: libc::c_int,
) -> srtp_err_status_t {
    let mut i: libc::c_int = 0;
    let mut srtcp_sender: srtp_t = 0 as *mut srtp_ctx_t;
    let mut srtcp_rcvr: srtp_t = 0 as *mut srtp_ctx_t;
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut hdr: *mut srtp_hdr_t = 0 as *mut srtp_hdr_t;
    let mut hdr2: *mut srtp_hdr_t = 0 as *mut srtp_hdr_t;
    let mut hdr_enc: [uint8_t; 64] = [0; 64];
    let mut pkt_end: *mut uint8_t = 0 as *mut uint8_t;
    let mut msg_len_octets: libc::c_int = 0;
    let mut msg_len_enc: libc::c_int = 0;
    let mut msg_len: libc::c_int = 0;
    let mut len: libc::c_int = 0;
    let mut len2: libc::c_int = 0;
    let mut tag_length: uint32_t = 0;
    let mut ssrc: uint32_t = 0;
    let mut rcvr_policy: *mut srtp_policy_t = 0 as *mut srtp_policy_t;
    let mut use_mki: libc::c_int = 0 as libc::c_int;
    if mki_index >= 0 as libc::c_int {
        use_mki = 1 as libc::c_int;
    }
    err_check(srtp_create(&mut srtcp_sender, policy));
    err_check(srtp_session_print_policy(srtcp_sender));
    if (*policy).ssrc.type_0 as libc::c_uint
        != ssrc_specific as libc::c_int as libc::c_uint
    {
        ssrc = 0xdecafbad as libc::c_uint;
    } else {
        ssrc = (*policy).ssrc.value;
    }
    msg_len_octets = 28 as libc::c_int;
    hdr = srtp_create_test_packet(msg_len_octets, ssrc, &mut len);
    msg_len = len;
    if hdr.is_null() {
        return srtp_err_status_alloc_fail;
    }
    hdr2 = srtp_create_test_packet(msg_len_octets, ssrc, &mut len2);
    if hdr2.is_null() {
        free(hdr as *mut libc::c_void);
        return srtp_err_status_alloc_fail;
    }
    if mod_driver.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: before protection:\n%s\n\0" as *const u8 as *const libc::c_char,
            mod_driver.name,
            srtp_packet_to_string(hdr, len),
        );
    }
    if mod_driver.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: reference packet before protection:\n%s\n\0" as *const u8
                as *const libc::c_char,
            mod_driver.name,
            octet_string_hex_string(hdr as *mut uint8_t as *const libc::c_void, len),
        );
    }
    err_check(srtp_test_call_protect_rtcp(srtcp_sender, hdr, &mut len, mki_index));
    if mod_driver.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: after protection:\n%s\n\0" as *const u8 as *const libc::c_char,
            mod_driver.name,
            srtp_packet_to_string(hdr, len),
        );
    }
    if mod_driver.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: after protection:\n%s\n\0" as *const u8 as *const libc::c_char,
            mod_driver.name,
            octet_string_hex_string(hdr as *mut uint8_t as *const libc::c_void, len),
        );
    }
    memcpy(
        hdr_enc.as_mut_ptr() as *mut libc::c_void,
        hdr as *const libc::c_void,
        len as libc::c_ulong,
    );
    msg_len_enc = len;
    srtp_get_protect_rtcp_trailer_length(
        srtcp_sender,
        use_mki as uint32_t,
        mki_index as uint32_t,
        &mut tag_length,
    );
    pkt_end = (hdr as *mut uint8_t).offset(msg_len as isize).offset(tag_length as isize);
    i = 0 as libc::c_int;
    while i < 4 as libc::c_int {
        if *pkt_end.offset(i as isize) as libc::c_int != 0xff as libc::c_int {
            fprintf(
                stdout,
                b"overwrite in srtp_protect_rtcp() function (expected %x, found %x in trailing octet %d)\n\0"
                    as *const u8 as *const libc::c_char,
                0xff as libc::c_int,
                *(hdr as *mut uint8_t).offset(i as isize) as libc::c_int,
                i,
            );
            free(hdr as *mut libc::c_void);
            free(hdr2 as *mut libc::c_void);
            return srtp_err_status_algo_fail;
        }
        i += 1;
    }
    if (*policy).rtcp.sec_serv as libc::c_uint
        & sec_serv_conf as libc::c_int as libc::c_uint != 0
        && msg_len_octets >= 4 as libc::c_int
    {
        printf(
            b"testing that ciphertext is distinct from plaintext...\0" as *const u8
                as *const libc::c_char,
        );
        status = srtp_err_status_algo_fail;
        i = 12 as libc::c_int;
        while i < msg_len_octets + 12 as libc::c_int {
            if *(hdr as *mut uint8_t).offset(i as isize) as libc::c_int
                != *(hdr2 as *mut uint8_t).offset(i as isize) as libc::c_int
            {
                status = srtp_err_status_ok;
            }
            i += 1;
        }
        if status as u64 != 0 {
            printf(b"failed\n\0" as *const u8 as *const libc::c_char);
            free(hdr as *mut libc::c_void);
            free(hdr2 as *mut libc::c_void);
            return status;
        }
        printf(b"passed\n\0" as *const u8 as *const libc::c_char);
    }
    rcvr_policy = malloc(::core::mem::size_of::<srtp_policy_t>() as libc::c_ulong)
        as *mut srtp_policy_t;
    if rcvr_policy.is_null() {
        free(hdr as *mut libc::c_void);
        free(hdr2 as *mut libc::c_void);
        return srtp_err_status_alloc_fail;
    }
    memcpy(
        rcvr_policy as *mut libc::c_void,
        policy as *const libc::c_void,
        ::core::mem::size_of::<srtp_policy_t>() as libc::c_ulong,
    );
    if (*policy).ssrc.type_0 as libc::c_uint
        == ssrc_any_outbound as libc::c_int as libc::c_uint
    {
        (*rcvr_policy).ssrc.type_0 = ssrc_any_inbound;
    }
    err_check(srtp_create(&mut srtcp_rcvr, rcvr_policy));
    err_check(srtp_test_call_unprotect_rtcp(srtcp_rcvr, hdr, &mut len, use_mki));
    if mod_driver.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: after unprotection:\n%s\n\0" as *const u8 as *const libc::c_char,
            mod_driver.name,
            srtp_packet_to_string(hdr, len),
        );
    }
    i = 0 as libc::c_int;
    while i < len {
        if *(hdr as *mut uint8_t).offset(i as isize) as libc::c_int
            != *(hdr2 as *mut uint8_t).offset(i as isize) as libc::c_int
        {
            fprintf(
                stdout,
                b"mismatch at octet %d\n\0" as *const u8 as *const libc::c_char,
                i,
            );
            status = srtp_err_status_algo_fail;
        }
        i += 1;
    }
    if status as u64 != 0 {
        free(hdr as *mut libc::c_void);
        free(hdr2 as *mut libc::c_void);
        free(rcvr_policy as *mut libc::c_void);
        return status;
    }
    if (*policy).rtp.sec_serv as libc::c_uint
        & sec_serv_auth as libc::c_int as libc::c_uint != 0
    {
        let mut data: *mut libc::c_char = (hdr as *mut libc::c_char)
            .offset(12 as libc::c_int as isize);
        printf(
            b"testing for false positives in replay check...\0" as *const u8
                as *const libc::c_char,
        );
        status = srtp_test_call_unprotect_rtcp(
            srtcp_rcvr,
            hdr,
            &mut msg_len_enc,
            use_mki,
        );
        if status as libc::c_uint
            != srtp_err_status_replay_fail as libc::c_int as libc::c_uint
        {
            printf(
                b"failed with error code %d\n\0" as *const u8 as *const libc::c_char,
                status as libc::c_uint,
            );
            free(hdr as *mut libc::c_void);
            free(hdr2 as *mut libc::c_void);
            free(rcvr_policy as *mut libc::c_void);
            return status;
        } else {
            printf(b"passed\n\0" as *const u8 as *const libc::c_char);
        }
        printf(
            b"testing for false positives in auth check...\0" as *const u8
                as *const libc::c_char,
        );
        (*hdr).seq = ((*hdr).seq).wrapping_add(1);
        err_check(srtp_test_call_protect_rtcp(srtcp_sender, hdr, &mut len, mki_index));
        let ref mut fresh5 = *data.offset(0 as libc::c_int as isize);
        *fresh5 = (*fresh5 as libc::c_int ^ 0xff as libc::c_int) as libc::c_char;
        status = srtp_test_call_unprotect_rtcp(srtcp_rcvr, hdr, &mut len, use_mki);
        if status as libc::c_uint
            != srtp_err_status_auth_fail as libc::c_int as libc::c_uint
        {
            printf(b"failed\n\0" as *const u8 as *const libc::c_char);
            free(hdr as *mut libc::c_void);
            free(hdr2 as *mut libc::c_void);
            free(rcvr_policy as *mut libc::c_void);
            return status;
        } else {
            printf(b"passed\n\0" as *const u8 as *const libc::c_char);
        }
    }
    err_check(srtp_dealloc(srtcp_sender));
    err_check(srtp_dealloc(srtcp_rcvr));
    free(hdr as *mut libc::c_void);
    free(hdr2 as *mut libc::c_void);
    free(rcvr_policy as *mut libc::c_void);
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_session_print_policy(
    mut srtp: srtp_t,
) -> srtp_err_status_t {
    let mut serv_descr: [*mut libc::c_char; 4] = [
        b"none\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"confidentiality\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"authentication\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"confidentiality and authentication\0" as *const u8 as *const libc::c_char
            as *mut libc::c_char,
    ];
    let mut direction: [*mut libc::c_char; 3] = [
        b"unknown\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"outbound\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
        b"inbound\0" as *const u8 as *const libc::c_char as *mut libc::c_char,
    ];
    let mut stream: srtp_stream_t = 0 as *mut srtp_stream_ctx_t;
    let mut session_keys: *mut srtp_session_keys_t = 0 as *mut srtp_session_keys_t;
    if srtp.is_null() {
        return srtp_err_status_fail;
    }
    if !((*srtp).stream_template).is_null() {
        stream = (*srtp).stream_template;
        session_keys = &mut *((*stream).session_keys).offset(0 as libc::c_int as isize)
            as *mut srtp_session_keys_t;
        printf(
            b"# SSRC:          any %s\r\n# rtp cipher:    %s\r\n# rtp auth:      %s\r\n# rtp services:  %s\r\n# rtcp cipher:   %s\r\n# rtcp auth:     %s\r\n# rtcp services: %s\r\n# window size:   %lu\r\n# tx rtx allowed:%s\r\n\0"
                as *const u8 as *const libc::c_char,
            direction[(*stream).direction as usize],
            (*(*(*session_keys).rtp_cipher).type_0).description,
            (*(*(*session_keys).rtp_auth).type_0).description,
            serv_descr[(*stream).rtp_services as usize],
            (*(*(*session_keys).rtcp_cipher).type_0).description,
            (*(*(*session_keys).rtcp_auth).type_0).description,
            serv_descr[(*stream).rtcp_services as usize],
            srtp_rdbx_get_window_size(&mut (*stream).rtp_rdbx),
            if (*stream).allow_repeat_tx != 0 {
                b"true\0" as *const u8 as *const libc::c_char
            } else {
                b"false\0" as *const u8 as *const libc::c_char
            },
        );
        printf(b"# Encrypted extension headers: \0" as *const u8 as *const libc::c_char);
        if !((*stream).enc_xtn_hdr).is_null()
            && (*stream).enc_xtn_hdr_count > 0 as libc::c_int
        {
            let mut enc_xtn_hdr: *mut libc::c_int = (*stream).enc_xtn_hdr;
            let mut count: libc::c_int = (*stream).enc_xtn_hdr_count;
            while count > 0 as libc::c_int {
                printf(b"%d \0" as *const u8 as *const libc::c_char, *enc_xtn_hdr);
                enc_xtn_hdr = enc_xtn_hdr.offset(1);
                count -= 1;
            }
            printf(b"\n\0" as *const u8 as *const libc::c_char);
        } else {
            printf(b"none\n\0" as *const u8 as *const libc::c_char);
        }
    }
    stream = (*srtp).stream_list;
    while !stream.is_null() {
        if (*stream).rtp_services as libc::c_uint
            > sec_serv_conf_and_auth as libc::c_int as libc::c_uint
        {
            return srtp_err_status_bad_param;
        }
        session_keys = &mut *((*stream).session_keys).offset(0 as libc::c_int as isize)
            as *mut srtp_session_keys_t;
        printf(
            b"# SSRC:          0x%08x\r\n# rtp cipher:    %s\r\n# rtp auth:      %s\r\n# rtp services:  %s\r\n# rtcp cipher:   %s\r\n# rtcp auth:     %s\r\n# rtcp services: %s\r\n# window size:   %lu\r\n# tx rtx allowed:%s\r\n\0"
                as *const u8 as *const libc::c_char,
            (*stream).ssrc,
            (*(*(*session_keys).rtp_cipher).type_0).description,
            (*(*(*session_keys).rtp_auth).type_0).description,
            serv_descr[(*stream).rtp_services as usize],
            (*(*(*session_keys).rtcp_cipher).type_0).description,
            (*(*(*session_keys).rtcp_auth).type_0).description,
            serv_descr[(*stream).rtcp_services as usize],
            srtp_rdbx_get_window_size(&mut (*stream).rtp_rdbx),
            if (*stream).allow_repeat_tx != 0 {
                b"true\0" as *const u8 as *const libc::c_char
            } else {
                b"false\0" as *const u8 as *const libc::c_char
            },
        );
        printf(b"# Encrypted extension headers: \0" as *const u8 as *const libc::c_char);
        if !((*stream).enc_xtn_hdr).is_null()
            && (*stream).enc_xtn_hdr_count > 0 as libc::c_int
        {
            let mut enc_xtn_hdr_0: *mut libc::c_int = (*stream).enc_xtn_hdr;
            let mut count_0: libc::c_int = (*stream).enc_xtn_hdr_count;
            while count_0 > 0 as libc::c_int {
                printf(b"%d \0" as *const u8 as *const libc::c_char, *enc_xtn_hdr_0);
                enc_xtn_hdr_0 = enc_xtn_hdr_0.offset(1);
                count_0 -= 1;
            }
            printf(b"\n\0" as *const u8 as *const libc::c_char);
        } else {
            printf(b"none\n\0" as *const u8 as *const libc::c_char);
        }
        stream = (*stream).next;
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_print_policy(
    mut policy: *const srtp_policy_t,
) -> srtp_err_status_t {
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut session: srtp_t = 0 as *mut srtp_ctx_t;
    status = srtp_create(&mut session, policy);
    if status as u64 != 0 {
        return status;
    }
    status = srtp_session_print_policy(session);
    if status as u64 != 0 {
        return status;
    }
    status = srtp_dealloc(session);
    if status as u64 != 0 {
        return status;
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub static mut packet_string: [libc::c_char; 2048] = [0; 2048];
#[no_mangle]
pub unsafe extern "C" fn srtp_packet_to_string(
    mut hdr: *mut srtp_hdr_t,
    mut pkt_octet_len: libc::c_int,
) -> *mut libc::c_char {
    let mut octets_in_rtp_header: libc::c_int = 12 as libc::c_int;
    let mut data: *mut uint8_t = (hdr as *mut uint8_t)
        .offset(octets_in_rtp_header as isize);
    let mut hex_len: libc::c_int = pkt_octet_len - octets_in_rtp_header;
    if hdr.is_null() || pkt_octet_len > 2048 as libc::c_int {
        return 0 as *mut libc::c_char;
    }
    sprintf(
        packet_string.as_mut_ptr(),
        b"(s)rtp packet: {\n   version:\t%d\n   p:\t\t%d\n   x:\t\t%d\n   cc:\t\t%d\n   m:\t\t%d\n   pt:\t\t%x\n   seq:\t\t%x\n   ts:\t\t%x\n   ssrc:\t%x\n   data:\t%s\n} (%d octets in total)\n\0"
            as *const u8 as *const libc::c_char,
        (*hdr).version() as libc::c_int,
        (*hdr).p() as libc::c_int,
        (*hdr).x() as libc::c_int,
        (*hdr).cc() as libc::c_int,
        (*hdr).m() as libc::c_int,
        (*hdr).pt() as libc::c_int,
        (*hdr).seq as libc::c_int,
        (*hdr).ts,
        (*hdr).ssrc,
        octet_string_hex_string(data as *const libc::c_void, hex_len),
        pkt_octet_len,
    );
    return packet_string.as_mut_ptr();
}
#[no_mangle]
pub unsafe extern "C" fn mips_estimate(
    mut num_trials: libc::c_int,
    mut ignore: *mut libc::c_int,
) -> libc::c_double {
    let mut t: clock_t = 0;
    let mut i: libc::c_int = 0;
    let mut sum: libc::c_int = 0;
    ::core::ptr::write_volatile(&mut sum as *mut libc::c_int, 0 as libc::c_int);
    t = clock();
    ::core::ptr::write_volatile(&mut i as *mut libc::c_int, 0 as libc::c_int);
    while i < num_trials {
        ::core::ptr::write_volatile(
            &mut sum as *mut libc::c_int,
            ::core::ptr::read_volatile::<libc::c_int>(&sum as *const libc::c_int) + i,
        );
        ::core::ptr::write_volatile(
            &mut i as *mut libc::c_int,
            ::core::ptr::read_volatile::<libc::c_int>(&i as *const libc::c_int) + 1,
        );
    }
    t = clock() - t;
    if t < 1 as libc::c_int as libc::c_long {
        t = 1 as libc::c_int as clock_t;
    }
    *ignore = sum;
    return num_trials as libc::c_double
        * 1000000 as libc::c_int as __clock_t as libc::c_double / t as libc::c_double;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_validate() -> srtp_err_status_t {
    let mut srtp_plaintext_ref: [uint8_t; 28] = [
        0x80 as libc::c_int as uint8_t,
        0xf as libc::c_int as uint8_t,
        0x12 as libc::c_int as uint8_t,
        0x34 as libc::c_int as uint8_t,
        0xde as libc::c_int as uint8_t,
        0xca as libc::c_int as uint8_t,
        0xfb as libc::c_int as uint8_t,
        0xad as libc::c_int as uint8_t,
        0xca as libc::c_int as uint8_t,
        0xfe as libc::c_int as uint8_t,
        0xba as libc::c_int as uint8_t,
        0xbe as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
    ];
    let mut srtp_plaintext: [uint8_t; 38] = [
        0x80 as libc::c_int as uint8_t,
        0xf as libc::c_int as uint8_t,
        0x12 as libc::c_int as uint8_t,
        0x34 as libc::c_int as uint8_t,
        0xde as libc::c_int as uint8_t,
        0xca as libc::c_int as uint8_t,
        0xfb as libc::c_int as uint8_t,
        0xad as libc::c_int as uint8_t,
        0xca as libc::c_int as uint8_t,
        0xfe as libc::c_int as uint8_t,
        0xba as libc::c_int as uint8_t,
        0xbe as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
    ];
    let mut srtp_ciphertext: [uint8_t; 38] = [
        0x80 as libc::c_int as uint8_t,
        0xf as libc::c_int as uint8_t,
        0x12 as libc::c_int as uint8_t,
        0x34 as libc::c_int as uint8_t,
        0xde as libc::c_int as uint8_t,
        0xca as libc::c_int as uint8_t,
        0xfb as libc::c_int as uint8_t,
        0xad as libc::c_int as uint8_t,
        0xca as libc::c_int as uint8_t,
        0xfe as libc::c_int as uint8_t,
        0xba as libc::c_int as uint8_t,
        0xbe as libc::c_int as uint8_t,
        0x4e as libc::c_int as uint8_t,
        0x55 as libc::c_int as uint8_t,
        0xdc as libc::c_int as uint8_t,
        0x4c as libc::c_int as uint8_t,
        0xe7 as libc::c_int as uint8_t,
        0x99 as libc::c_int as uint8_t,
        0x78 as libc::c_int as uint8_t,
        0xd8 as libc::c_int as uint8_t,
        0x8c as libc::c_int as uint8_t,
        0xa4 as libc::c_int as uint8_t,
        0xd2 as libc::c_int as uint8_t,
        0x15 as libc::c_int as uint8_t,
        0x94 as libc::c_int as uint8_t,
        0x9d as libc::c_int as uint8_t,
        0x24 as libc::c_int as uint8_t,
        0x2 as libc::c_int as uint8_t,
        0xb7 as libc::c_int as uint8_t,
        0x8d as libc::c_int as uint8_t,
        0x6a as libc::c_int as uint8_t,
        0xcc as libc::c_int as uint8_t,
        0x99 as libc::c_int as uint8_t,
        0xea as libc::c_int as uint8_t,
        0x17 as libc::c_int as uint8_t,
        0x9b as libc::c_int as uint8_t,
        0x8d as libc::c_int as uint8_t,
        0xbb as libc::c_int as uint8_t,
    ];
    let mut rtcp_plaintext_ref: [uint8_t; 24] = [
        0x81 as libc::c_int as uint8_t,
        0xc8 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0xb as libc::c_int as uint8_t,
        0xca as libc::c_int as uint8_t,
        0xfe as libc::c_int as uint8_t,
        0xba as libc::c_int as uint8_t,
        0xbe as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
    ];
    let mut rtcp_plaintext: [uint8_t; 38] = [
        0x81 as libc::c_int as uint8_t,
        0xc8 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0xb as libc::c_int as uint8_t,
        0xca as libc::c_int as uint8_t,
        0xfe as libc::c_int as uint8_t,
        0xba as libc::c_int as uint8_t,
        0xbe as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
    ];
    let mut srtcp_ciphertext: [uint8_t; 38] = [
        0x81 as libc::c_int as uint8_t,
        0xc8 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0xb as libc::c_int as uint8_t,
        0xca as libc::c_int as uint8_t,
        0xfe as libc::c_int as uint8_t,
        0xba as libc::c_int as uint8_t,
        0xbe as libc::c_int as uint8_t,
        0x71 as libc::c_int as uint8_t,
        0x28 as libc::c_int as uint8_t,
        0x3 as libc::c_int as uint8_t,
        0x5b as libc::c_int as uint8_t,
        0xe4 as libc::c_int as uint8_t,
        0x87 as libc::c_int as uint8_t,
        0xb9 as libc::c_int as uint8_t,
        0xbd as libc::c_int as uint8_t,
        0xbe as libc::c_int as uint8_t,
        0xf8 as libc::c_int as uint8_t,
        0x90 as libc::c_int as uint8_t,
        0x41 as libc::c_int as uint8_t,
        0xf9 as libc::c_int as uint8_t,
        0x77 as libc::c_int as uint8_t,
        0xa5 as libc::c_int as uint8_t,
        0xa8 as libc::c_int as uint8_t,
        0x80 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0x1 as libc::c_int as uint8_t,
        0x99 as libc::c_int as uint8_t,
        0x3e as libc::c_int as uint8_t,
        0x8 as libc::c_int as uint8_t,
        0xcd as libc::c_int as uint8_t,
        0x54 as libc::c_int as uint8_t,
        0xd6 as libc::c_int as uint8_t,
        0xc1 as libc::c_int as uint8_t,
        0x23 as libc::c_int as uint8_t,
        0x7 as libc::c_int as uint8_t,
        0x98 as libc::c_int as uint8_t,
    ];
    let mut srtp_snd: srtp_t = 0 as *mut srtp_ctx_t;
    let mut srtp_recv: srtp_t = 0 as *mut srtp_ctx_t;
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut len: libc::c_int = 0;
    let mut policy: srtp_policy_t = srtp_policy_t {
        ssrc: srtp_ssrc_t {
            type_0: ssrc_undefined,
            value: 0,
        },
        rtp: srtp_crypto_policy_t {
            cipher_type: 0,
            cipher_key_len: 0,
            auth_type: 0,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: sec_serv_none,
        },
        rtcp: srtp_crypto_policy_t {
            cipher_type: 0,
            cipher_key_len: 0,
            auth_type: 0,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: sec_serv_none,
        },
        key: 0 as *mut libc::c_uchar,
        keys: 0 as *mut *mut srtp_master_key_t,
        num_master_keys: 0,
        deprecated_ekt: 0 as *mut libc::c_void,
        window_size: 0,
        allow_repeat_tx: 0,
        enc_xtn_hdr: 0 as *mut libc::c_int,
        enc_xtn_hdr_count: 0,
        next: 0 as *mut srtp_policy_t,
    };
    memset(
        &mut policy as *mut srtp_policy_t as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<srtp_policy_t>() as libc::c_ulong,
    );
    srtp_crypto_policy_set_rtp_default(&mut policy.rtp);
    srtp_crypto_policy_set_rtcp_default(&mut policy.rtcp);
    policy.ssrc.type_0 = ssrc_specific;
    policy.ssrc.value = 0xcafebabe as libc::c_uint;
    policy.key = test_key.as_mut_ptr();
    policy.deprecated_ekt = 0 as *mut libc::c_void;
    policy.window_size = 128 as libc::c_int as libc::c_ulong;
    policy.allow_repeat_tx = 0 as libc::c_int;
    policy.next = 0 as *mut srtp_policy_t;
    status = srtp_create(&mut srtp_snd, &mut policy);
    if status as u64 != 0 {
        return status;
    }
    len = 28 as libc::c_int;
    status = srtp_protect(
        srtp_snd,
        srtp_plaintext.as_mut_ptr() as *mut libc::c_void,
        &mut len,
    );
    if status as libc::c_uint != 0 || len != 38 as libc::c_int {
        return srtp_err_status_fail;
    }
    if mod_driver.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: ciphertext:\n  %s\n\0" as *const u8 as *const libc::c_char,
            mod_driver.name,
            octet_string_hex_string(
                srtp_plaintext.as_mut_ptr() as *const libc::c_void,
                len,
            ),
        );
    }
    if mod_driver.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: ciphertext reference:\n  %s\n\0" as *const u8 as *const libc::c_char,
            mod_driver.name,
            octet_string_hex_string(
                srtp_ciphertext.as_mut_ptr() as *const libc::c_void,
                len,
            ),
        );
    }
    if srtp_octet_string_is_eq(
        srtp_plaintext.as_mut_ptr(),
        srtp_ciphertext.as_mut_ptr(),
        len,
    ) != 0
    {
        return srtp_err_status_fail;
    }
    len = 24 as libc::c_int;
    status = srtp_protect_rtcp(
        srtp_snd,
        rtcp_plaintext.as_mut_ptr() as *mut libc::c_void,
        &mut len,
    );
    if status as libc::c_uint != 0 || len != 38 as libc::c_int {
        return srtp_err_status_fail;
    }
    if mod_driver.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: srtcp ciphertext:\n  %s\n\0" as *const u8 as *const libc::c_char,
            mod_driver.name,
            octet_string_hex_string(
                rtcp_plaintext.as_mut_ptr() as *const libc::c_void,
                len,
            ),
        );
    }
    if mod_driver.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: srtcp ciphertext reference:\n  %s\n\0" as *const u8
                as *const libc::c_char,
            mod_driver.name,
            octet_string_hex_string(
                srtcp_ciphertext.as_mut_ptr() as *const libc::c_void,
                len,
            ),
        );
    }
    if srtp_octet_string_is_eq(
        rtcp_plaintext.as_mut_ptr(),
        srtcp_ciphertext.as_mut_ptr(),
        len,
    ) != 0
    {
        return srtp_err_status_fail;
    }
    status = srtp_create(&mut srtp_recv, &mut policy);
    if status as u64 != 0 {
        return status;
    }
    status = srtp_unprotect(
        srtp_recv,
        srtp_ciphertext.as_mut_ptr() as *mut libc::c_void,
        &mut len,
    );
    if status as libc::c_uint != 0 || len != 28 as libc::c_int {
        return status;
    }
    if srtp_octet_string_is_eq(
        srtp_ciphertext.as_mut_ptr(),
        srtp_plaintext_ref.as_mut_ptr(),
        len,
    ) != 0
    {
        return srtp_err_status_fail;
    }
    len = 38 as libc::c_int;
    status = srtp_unprotect_rtcp(
        srtp_recv,
        srtcp_ciphertext.as_mut_ptr() as *mut libc::c_void,
        &mut len,
    );
    if status as libc::c_uint != 0 || len != 24 as libc::c_int {
        return status;
    }
    if srtp_octet_string_is_eq(
        srtcp_ciphertext.as_mut_ptr(),
        rtcp_plaintext_ref.as_mut_ptr(),
        len,
    ) != 0
    {
        return srtp_err_status_fail;
    }
    status = srtp_dealloc(srtp_snd);
    if status as u64 != 0 {
        return status;
    }
    status = srtp_dealloc(srtp_recv);
    if status as u64 != 0 {
        return status;
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_validate_null() -> srtp_err_status_t {
    let mut srtp_plaintext_ref: [uint8_t; 28] = [
        0x80 as libc::c_int as uint8_t,
        0xf as libc::c_int as uint8_t,
        0x12 as libc::c_int as uint8_t,
        0x34 as libc::c_int as uint8_t,
        0xde as libc::c_int as uint8_t,
        0xca as libc::c_int as uint8_t,
        0xfb as libc::c_int as uint8_t,
        0xad as libc::c_int as uint8_t,
        0xca as libc::c_int as uint8_t,
        0xfe as libc::c_int as uint8_t,
        0xba as libc::c_int as uint8_t,
        0xbe as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
    ];
    let mut srtp_plaintext: [uint8_t; 38] = [
        0x80 as libc::c_int as uint8_t,
        0xf as libc::c_int as uint8_t,
        0x12 as libc::c_int as uint8_t,
        0x34 as libc::c_int as uint8_t,
        0xde as libc::c_int as uint8_t,
        0xca as libc::c_int as uint8_t,
        0xfb as libc::c_int as uint8_t,
        0xad as libc::c_int as uint8_t,
        0xca as libc::c_int as uint8_t,
        0xfe as libc::c_int as uint8_t,
        0xba as libc::c_int as uint8_t,
        0xbe as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
    ];
    let mut srtp_ciphertext: [uint8_t; 38] = [
        0x80 as libc::c_int as uint8_t,
        0xf as libc::c_int as uint8_t,
        0x12 as libc::c_int as uint8_t,
        0x34 as libc::c_int as uint8_t,
        0xde as libc::c_int as uint8_t,
        0xca as libc::c_int as uint8_t,
        0xfb as libc::c_int as uint8_t,
        0xad as libc::c_int as uint8_t,
        0xca as libc::c_int as uint8_t,
        0xfe as libc::c_int as uint8_t,
        0xba as libc::c_int as uint8_t,
        0xbe as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xa1 as libc::c_int as uint8_t,
        0x36 as libc::c_int as uint8_t,
        0x27 as libc::c_int as uint8_t,
        0xb as libc::c_int as uint8_t,
        0x67 as libc::c_int as uint8_t,
        0x91 as libc::c_int as uint8_t,
        0x34 as libc::c_int as uint8_t,
        0xce as libc::c_int as uint8_t,
        0x9b as libc::c_int as uint8_t,
    ];
    let mut rtcp_plaintext_ref: [uint8_t; 24] = [
        0x81 as libc::c_int as uint8_t,
        0xc8 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0xb as libc::c_int as uint8_t,
        0xca as libc::c_int as uint8_t,
        0xfe as libc::c_int as uint8_t,
        0xba as libc::c_int as uint8_t,
        0xbe as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
    ];
    let mut rtcp_plaintext: [uint8_t; 38] = [
        0x81 as libc::c_int as uint8_t,
        0xc8 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0xb as libc::c_int as uint8_t,
        0xca as libc::c_int as uint8_t,
        0xfe as libc::c_int as uint8_t,
        0xba as libc::c_int as uint8_t,
        0xbe as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
    ];
    let mut srtcp_ciphertext: [uint8_t; 38] = [
        0x81 as libc::c_int as uint8_t,
        0xc8 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0xb as libc::c_int as uint8_t,
        0xca as libc::c_int as uint8_t,
        0xfe as libc::c_int as uint8_t,
        0xba as libc::c_int as uint8_t,
        0xbe as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0x1 as libc::c_int as uint8_t,
        0xfe as libc::c_int as uint8_t,
        0x88 as libc::c_int as uint8_t,
        0xc7 as libc::c_int as uint8_t,
        0xfd as libc::c_int as uint8_t,
        0xfd as libc::c_int as uint8_t,
        0x37 as libc::c_int as uint8_t,
        0xeb as libc::c_int as uint8_t,
        0xce as libc::c_int as uint8_t,
        0x61 as libc::c_int as uint8_t,
        0x5d as libc::c_int as uint8_t,
    ];
    let mut srtp_snd: srtp_t = 0 as *mut srtp_ctx_t;
    let mut srtp_recv: srtp_t = 0 as *mut srtp_ctx_t;
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut len: libc::c_int = 0;
    let mut policy: srtp_policy_t = srtp_policy_t {
        ssrc: srtp_ssrc_t {
            type_0: ssrc_undefined,
            value: 0,
        },
        rtp: srtp_crypto_policy_t {
            cipher_type: 0,
            cipher_key_len: 0,
            auth_type: 0,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: sec_serv_none,
        },
        rtcp: srtp_crypto_policy_t {
            cipher_type: 0,
            cipher_key_len: 0,
            auth_type: 0,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: sec_serv_none,
        },
        key: 0 as *mut libc::c_uchar,
        keys: 0 as *mut *mut srtp_master_key_t,
        num_master_keys: 0,
        deprecated_ekt: 0 as *mut libc::c_void,
        window_size: 0,
        allow_repeat_tx: 0,
        enc_xtn_hdr: 0 as *mut libc::c_int,
        enc_xtn_hdr_count: 0,
        next: 0 as *mut srtp_policy_t,
    };
    memset(
        &mut policy as *mut srtp_policy_t as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<srtp_policy_t>() as libc::c_ulong,
    );
    srtp_crypto_policy_set_null_cipher_hmac_sha1_80(&mut policy.rtp);
    srtp_crypto_policy_set_null_cipher_hmac_sha1_80(&mut policy.rtcp);
    policy.ssrc.type_0 = ssrc_specific;
    policy.ssrc.value = 0xcafebabe as libc::c_uint;
    policy.key = test_key.as_mut_ptr();
    policy.deprecated_ekt = 0 as *mut libc::c_void;
    policy.window_size = 128 as libc::c_int as libc::c_ulong;
    policy.allow_repeat_tx = 0 as libc::c_int;
    policy.next = 0 as *mut srtp_policy_t;
    status = srtp_create(&mut srtp_snd, &mut policy);
    if status as u64 != 0 {
        return status;
    }
    len = 28 as libc::c_int;
    status = srtp_protect(
        srtp_snd,
        srtp_plaintext.as_mut_ptr() as *mut libc::c_void,
        &mut len,
    );
    if status as libc::c_uint != 0 || len != 38 as libc::c_int {
        return srtp_err_status_fail;
    }
    if mod_driver.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: ciphertext:\n  %s\n\0" as *const u8 as *const libc::c_char,
            mod_driver.name,
            octet_string_hex_string(
                srtp_plaintext.as_mut_ptr() as *const libc::c_void,
                len,
            ),
        );
    }
    if mod_driver.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: ciphertext reference:\n  %s\n\0" as *const u8 as *const libc::c_char,
            mod_driver.name,
            octet_string_hex_string(
                srtp_ciphertext.as_mut_ptr() as *const libc::c_void,
                len,
            ),
        );
    }
    if srtp_octet_string_is_eq(
        srtp_plaintext.as_mut_ptr(),
        srtp_ciphertext.as_mut_ptr(),
        len,
    ) != 0
    {
        return srtp_err_status_fail;
    }
    len = 24 as libc::c_int;
    status = srtp_protect_rtcp(
        srtp_snd,
        rtcp_plaintext.as_mut_ptr() as *mut libc::c_void,
        &mut len,
    );
    if status as libc::c_uint != 0 || len != 38 as libc::c_int {
        return srtp_err_status_fail;
    }
    if mod_driver.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: srtcp ciphertext:\n  %s\n\0" as *const u8 as *const libc::c_char,
            mod_driver.name,
            octet_string_hex_string(
                rtcp_plaintext.as_mut_ptr() as *const libc::c_void,
                len,
            ),
        );
    }
    if mod_driver.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: srtcp ciphertext reference:\n  %s\n\0" as *const u8
                as *const libc::c_char,
            mod_driver.name,
            octet_string_hex_string(
                srtcp_ciphertext.as_mut_ptr() as *const libc::c_void,
                len,
            ),
        );
    }
    if srtp_octet_string_is_eq(
        rtcp_plaintext.as_mut_ptr(),
        srtcp_ciphertext.as_mut_ptr(),
        len,
    ) != 0
    {
        return srtp_err_status_fail;
    }
    status = srtp_create(&mut srtp_recv, &mut policy);
    if status as u64 != 0 {
        return status;
    }
    status = srtp_unprotect(
        srtp_recv,
        srtp_ciphertext.as_mut_ptr() as *mut libc::c_void,
        &mut len,
    );
    if status as libc::c_uint != 0 || len != 28 as libc::c_int {
        return status;
    }
    if srtp_octet_string_is_eq(
        srtp_ciphertext.as_mut_ptr(),
        srtp_plaintext_ref.as_mut_ptr(),
        len,
    ) != 0
    {
        return srtp_err_status_fail;
    }
    len = 38 as libc::c_int;
    status = srtp_unprotect_rtcp(
        srtp_recv,
        srtcp_ciphertext.as_mut_ptr() as *mut libc::c_void,
        &mut len,
    );
    if status as libc::c_uint != 0 || len != 24 as libc::c_int {
        return status;
    }
    if srtp_octet_string_is_eq(
        srtcp_ciphertext.as_mut_ptr(),
        rtcp_plaintext_ref.as_mut_ptr(),
        len,
    ) != 0
    {
        return srtp_err_status_fail;
    }
    status = srtp_dealloc(srtp_snd);
    if status as u64 != 0 {
        return status;
    }
    status = srtp_dealloc(srtp_recv);
    if status as u64 != 0 {
        return status;
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_validate_encrypted_extensions_headers() -> srtp_err_status_t {
    let mut test_key_ext_headers: [libc::c_uchar; 30] = [
        0xe1 as libc::c_int as libc::c_uchar,
        0xf9 as libc::c_int as libc::c_uchar,
        0x7a as libc::c_int as libc::c_uchar,
        0xd as libc::c_int as libc::c_uchar,
        0x3e as libc::c_int as libc::c_uchar,
        0x1 as libc::c_int as libc::c_uchar,
        0x8b as libc::c_int as libc::c_uchar,
        0xe0 as libc::c_int as libc::c_uchar,
        0xd6 as libc::c_int as libc::c_uchar,
        0x4f as libc::c_int as libc::c_uchar,
        0xa3 as libc::c_int as libc::c_uchar,
        0x2c as libc::c_int as libc::c_uchar,
        0x6 as libc::c_int as libc::c_uchar,
        0xde as libc::c_int as libc::c_uchar,
        0x41 as libc::c_int as libc::c_uchar,
        0x39 as libc::c_int as libc::c_uchar,
        0xe as libc::c_int as libc::c_uchar,
        0xc6 as libc::c_int as libc::c_uchar,
        0x75 as libc::c_int as libc::c_uchar,
        0xad as libc::c_int as libc::c_uchar,
        0x49 as libc::c_int as libc::c_uchar,
        0x8a as libc::c_int as libc::c_uchar,
        0xfe as libc::c_int as libc::c_uchar,
        0xeb as libc::c_int as libc::c_uchar,
        0xb6 as libc::c_int as libc::c_uchar,
        0x96 as libc::c_int as libc::c_uchar,
        0xb as libc::c_int as libc::c_uchar,
        0x3a as libc::c_int as libc::c_uchar,
        0xab as libc::c_int as libc::c_uchar,
        0xe6 as libc::c_int as libc::c_uchar,
    ];
    let mut srtp_plaintext_ref: [uint8_t; 56] = [
        0x90 as libc::c_int as uint8_t,
        0xf as libc::c_int as uint8_t,
        0x12 as libc::c_int as uint8_t,
        0x34 as libc::c_int as uint8_t,
        0xde as libc::c_int as uint8_t,
        0xca as libc::c_int as uint8_t,
        0xfb as libc::c_int as uint8_t,
        0xad as libc::c_int as uint8_t,
        0xca as libc::c_int as uint8_t,
        0xfe as libc::c_int as uint8_t,
        0xba as libc::c_int as uint8_t,
        0xbe as libc::c_int as uint8_t,
        0xbe as libc::c_int as uint8_t,
        0xde as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0x6 as libc::c_int as uint8_t,
        0x17 as libc::c_int as uint8_t,
        0x41 as libc::c_int as uint8_t,
        0x42 as libc::c_int as uint8_t,
        0x73 as libc::c_int as uint8_t,
        0xa4 as libc::c_int as uint8_t,
        0x75 as libc::c_int as uint8_t,
        0x26 as libc::c_int as uint8_t,
        0x27 as libc::c_int as uint8_t,
        0x48 as libc::c_int as uint8_t,
        0x22 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0xc8 as libc::c_int as uint8_t,
        0x30 as libc::c_int as uint8_t,
        0x8e as libc::c_int as uint8_t,
        0x46 as libc::c_int as uint8_t,
        0x55 as libc::c_int as uint8_t,
        0x99 as libc::c_int as uint8_t,
        0x63 as libc::c_int as uint8_t,
        0x86 as libc::c_int as uint8_t,
        0xb3 as libc::c_int as uint8_t,
        0x95 as libc::c_int as uint8_t,
        0xfb as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
    ];
    let mut srtp_plaintext: [uint8_t; 66] = [
        0x90 as libc::c_int as uint8_t,
        0xf as libc::c_int as uint8_t,
        0x12 as libc::c_int as uint8_t,
        0x34 as libc::c_int as uint8_t,
        0xde as libc::c_int as uint8_t,
        0xca as libc::c_int as uint8_t,
        0xfb as libc::c_int as uint8_t,
        0xad as libc::c_int as uint8_t,
        0xca as libc::c_int as uint8_t,
        0xfe as libc::c_int as uint8_t,
        0xba as libc::c_int as uint8_t,
        0xbe as libc::c_int as uint8_t,
        0xbe as libc::c_int as uint8_t,
        0xde as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0x6 as libc::c_int as uint8_t,
        0x17 as libc::c_int as uint8_t,
        0x41 as libc::c_int as uint8_t,
        0x42 as libc::c_int as uint8_t,
        0x73 as libc::c_int as uint8_t,
        0xa4 as libc::c_int as uint8_t,
        0x75 as libc::c_int as uint8_t,
        0x26 as libc::c_int as uint8_t,
        0x27 as libc::c_int as uint8_t,
        0x48 as libc::c_int as uint8_t,
        0x22 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0xc8 as libc::c_int as uint8_t,
        0x30 as libc::c_int as uint8_t,
        0x8e as libc::c_int as uint8_t,
        0x46 as libc::c_int as uint8_t,
        0x55 as libc::c_int as uint8_t,
        0x99 as libc::c_int as uint8_t,
        0x63 as libc::c_int as uint8_t,
        0x86 as libc::c_int as uint8_t,
        0xb3 as libc::c_int as uint8_t,
        0x95 as libc::c_int as uint8_t,
        0xfb as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
    ];
    let mut srtp_ciphertext: [uint8_t; 66] = [
        0x90 as libc::c_int as uint8_t,
        0xf as libc::c_int as uint8_t,
        0x12 as libc::c_int as uint8_t,
        0x34 as libc::c_int as uint8_t,
        0xde as libc::c_int as uint8_t,
        0xca as libc::c_int as uint8_t,
        0xfb as libc::c_int as uint8_t,
        0xad as libc::c_int as uint8_t,
        0xca as libc::c_int as uint8_t,
        0xfe as libc::c_int as uint8_t,
        0xba as libc::c_int as uint8_t,
        0xbe as libc::c_int as uint8_t,
        0xbe as libc::c_int as uint8_t,
        0xde as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0x6 as libc::c_int as uint8_t,
        0x17 as libc::c_int as uint8_t,
        0x58 as libc::c_int as uint8_t,
        0x8a as libc::c_int as uint8_t,
        0x92 as libc::c_int as uint8_t,
        0x70 as libc::c_int as uint8_t,
        0xf4 as libc::c_int as uint8_t,
        0xe1 as libc::c_int as uint8_t,
        0x5e as libc::c_int as uint8_t,
        0x1c as libc::c_int as uint8_t,
        0x22 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0xc8 as libc::c_int as uint8_t,
        0x30 as libc::c_int as uint8_t,
        0x95 as libc::c_int as uint8_t,
        0x46 as libc::c_int as uint8_t,
        0xa9 as libc::c_int as uint8_t,
        0x94 as libc::c_int as uint8_t,
        0xf0 as libc::c_int as uint8_t,
        0xbc as libc::c_int as uint8_t,
        0x54 as libc::c_int as uint8_t,
        0x78 as libc::c_int as uint8_t,
        0x97 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0x4e as libc::c_int as uint8_t,
        0x55 as libc::c_int as uint8_t,
        0xdc as libc::c_int as uint8_t,
        0x4c as libc::c_int as uint8_t,
        0xe7 as libc::c_int as uint8_t,
        0x99 as libc::c_int as uint8_t,
        0x78 as libc::c_int as uint8_t,
        0xd8 as libc::c_int as uint8_t,
        0x8c as libc::c_int as uint8_t,
        0xa4 as libc::c_int as uint8_t,
        0xd2 as libc::c_int as uint8_t,
        0x15 as libc::c_int as uint8_t,
        0x94 as libc::c_int as uint8_t,
        0x9d as libc::c_int as uint8_t,
        0x24 as libc::c_int as uint8_t,
        0x2 as libc::c_int as uint8_t,
        0x5a as libc::c_int as uint8_t,
        0x46 as libc::c_int as uint8_t,
        0xb3 as libc::c_int as uint8_t,
        0xca as libc::c_int as uint8_t,
        0x35 as libc::c_int as uint8_t,
        0xc5 as libc::c_int as uint8_t,
        0x35 as libc::c_int as uint8_t,
        0xa8 as libc::c_int as uint8_t,
        0x91 as libc::c_int as uint8_t,
        0xc7 as libc::c_int as uint8_t,
    ];
    let mut srtp_snd: srtp_t = 0 as *mut srtp_ctx_t;
    let mut srtp_recv: srtp_t = 0 as *mut srtp_ctx_t;
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut len: libc::c_int = 0;
    let mut policy: srtp_policy_t = srtp_policy_t {
        ssrc: srtp_ssrc_t {
            type_0: ssrc_undefined,
            value: 0,
        },
        rtp: srtp_crypto_policy_t {
            cipher_type: 0,
            cipher_key_len: 0,
            auth_type: 0,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: sec_serv_none,
        },
        rtcp: srtp_crypto_policy_t {
            cipher_type: 0,
            cipher_key_len: 0,
            auth_type: 0,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: sec_serv_none,
        },
        key: 0 as *mut libc::c_uchar,
        keys: 0 as *mut *mut srtp_master_key_t,
        num_master_keys: 0,
        deprecated_ekt: 0 as *mut libc::c_void,
        window_size: 0,
        allow_repeat_tx: 0,
        enc_xtn_hdr: 0 as *mut libc::c_int,
        enc_xtn_hdr_count: 0,
        next: 0 as *mut srtp_policy_t,
    };
    let mut headers: [libc::c_int; 3] = [
        1 as libc::c_int,
        3 as libc::c_int,
        4 as libc::c_int,
    ];
    memset(
        &mut policy as *mut srtp_policy_t as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<srtp_policy_t>() as libc::c_ulong,
    );
    srtp_crypto_policy_set_rtp_default(&mut policy.rtp);
    srtp_crypto_policy_set_rtcp_default(&mut policy.rtcp);
    policy.ssrc.type_0 = ssrc_specific;
    policy.ssrc.value = 0xcafebabe as libc::c_uint;
    policy.key = test_key_ext_headers.as_mut_ptr();
    policy.deprecated_ekt = 0 as *mut libc::c_void;
    policy.window_size = 128 as libc::c_int as libc::c_ulong;
    policy.allow_repeat_tx = 0 as libc::c_int;
    policy.enc_xtn_hdr = headers.as_mut_ptr();
    policy
        .enc_xtn_hdr_count = (::core::mem::size_of::<[libc::c_int; 3]>()
        as libc::c_ulong)
        .wrapping_div(::core::mem::size_of::<libc::c_int>() as libc::c_ulong)
        as libc::c_int;
    policy.next = 0 as *mut srtp_policy_t;
    status = srtp_create(&mut srtp_snd, &mut policy);
    if status as u64 != 0 {
        return status;
    }
    len = ::core::mem::size_of::<[uint8_t; 56]>() as libc::c_ulong as libc::c_int;
    status = srtp_protect(
        srtp_snd,
        srtp_plaintext.as_mut_ptr() as *mut libc::c_void,
        &mut len,
    );
    if status as libc::c_uint != 0
        || len as libc::c_ulong
            != ::core::mem::size_of::<[uint8_t; 66]>() as libc::c_ulong
    {
        return srtp_err_status_fail;
    }
    if mod_driver.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: ciphertext:\n  %s\n\0" as *const u8 as *const libc::c_char,
            mod_driver.name,
            srtp_octet_string_hex_string(
                srtp_plaintext.as_mut_ptr() as *const libc::c_void,
                len,
            ),
        );
    }
    if mod_driver.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: ciphertext reference:\n  %s\n\0" as *const u8 as *const libc::c_char,
            mod_driver.name,
            srtp_octet_string_hex_string(
                srtp_ciphertext.as_mut_ptr() as *const libc::c_void,
                len,
            ),
        );
    }
    if srtp_octet_string_is_eq(
        srtp_plaintext.as_mut_ptr(),
        srtp_ciphertext.as_mut_ptr(),
        len,
    ) != 0
    {
        return srtp_err_status_fail;
    }
    status = srtp_create(&mut srtp_recv, &mut policy);
    if status as u64 != 0 {
        return status;
    }
    status = srtp_unprotect(
        srtp_recv,
        srtp_ciphertext.as_mut_ptr() as *mut libc::c_void,
        &mut len,
    );
    if status as u64 != 0 {
        return status
    } else {
        if len as libc::c_ulong
            != ::core::mem::size_of::<[uint8_t; 56]>() as libc::c_ulong
        {
            return srtp_err_status_fail;
        }
    }
    if srtp_octet_string_is_eq(
        srtp_ciphertext.as_mut_ptr(),
        srtp_plaintext_ref.as_mut_ptr(),
        len,
    ) != 0
    {
        return srtp_err_status_fail;
    }
    status = srtp_dealloc(srtp_snd);
    if status as u64 != 0 {
        return status;
    }
    status = srtp_dealloc(srtp_recv);
    if status as u64 != 0 {
        return status;
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_validate_aes_256() -> srtp_err_status_t {
    let mut aes_256_test_key: [libc::c_uchar; 46] = [
        0xf0 as libc::c_int as libc::c_uchar,
        0xf0 as libc::c_int as libc::c_uchar,
        0x49 as libc::c_int as libc::c_uchar,
        0x14 as libc::c_int as libc::c_uchar,
        0xb5 as libc::c_int as libc::c_uchar,
        0x13 as libc::c_int as libc::c_uchar,
        0xf2 as libc::c_int as libc::c_uchar,
        0x76 as libc::c_int as libc::c_uchar,
        0x3a as libc::c_int as libc::c_uchar,
        0x1b as libc::c_int as libc::c_uchar,
        0x1f as libc::c_int as libc::c_uchar,
        0xa1 as libc::c_int as libc::c_uchar,
        0x30 as libc::c_int as libc::c_uchar,
        0xf1 as libc::c_int as libc::c_uchar,
        0xe as libc::c_int as libc::c_uchar,
        0x29 as libc::c_int as libc::c_uchar,
        0x98 as libc::c_int as libc::c_uchar,
        0xf6 as libc::c_int as libc::c_uchar,
        0xf6 as libc::c_int as libc::c_uchar,
        0xe4 as libc::c_int as libc::c_uchar,
        0x3e as libc::c_int as libc::c_uchar,
        0x43 as libc::c_int as libc::c_uchar,
        0x9 as libc::c_int as libc::c_uchar,
        0xd1 as libc::c_int as libc::c_uchar,
        0xe6 as libc::c_int as libc::c_uchar,
        0x22 as libc::c_int as libc::c_uchar,
        0xa0 as libc::c_int as libc::c_uchar,
        0xe3 as libc::c_int as libc::c_uchar,
        0x32 as libc::c_int as libc::c_uchar,
        0xb9 as libc::c_int as libc::c_uchar,
        0xf1 as libc::c_int as libc::c_uchar,
        0xb6 as libc::c_int as libc::c_uchar,
        0x3b as libc::c_int as libc::c_uchar,
        0x4 as libc::c_int as libc::c_uchar,
        0x80 as libc::c_int as libc::c_uchar,
        0x3d as libc::c_int as libc::c_uchar,
        0xe5 as libc::c_int as libc::c_uchar,
        0x1e as libc::c_int as libc::c_uchar,
        0xe7 as libc::c_int as libc::c_uchar,
        0xc9 as libc::c_int as libc::c_uchar,
        0x64 as libc::c_int as libc::c_uchar,
        0x23 as libc::c_int as libc::c_uchar,
        0xab as libc::c_int as libc::c_uchar,
        0x5b as libc::c_int as libc::c_uchar,
        0x78 as libc::c_int as libc::c_uchar,
        0xd2 as libc::c_int as libc::c_uchar,
    ];
    let mut srtp_plaintext_ref: [uint8_t; 28] = [
        0x80 as libc::c_int as uint8_t,
        0xf as libc::c_int as uint8_t,
        0x12 as libc::c_int as uint8_t,
        0x34 as libc::c_int as uint8_t,
        0xde as libc::c_int as uint8_t,
        0xca as libc::c_int as uint8_t,
        0xfb as libc::c_int as uint8_t,
        0xad as libc::c_int as uint8_t,
        0xca as libc::c_int as uint8_t,
        0xfe as libc::c_int as uint8_t,
        0xba as libc::c_int as uint8_t,
        0xbe as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
    ];
    let mut srtp_plaintext: [uint8_t; 38] = [
        0x80 as libc::c_int as uint8_t,
        0xf as libc::c_int as uint8_t,
        0x12 as libc::c_int as uint8_t,
        0x34 as libc::c_int as uint8_t,
        0xde as libc::c_int as uint8_t,
        0xca as libc::c_int as uint8_t,
        0xfb as libc::c_int as uint8_t,
        0xad as libc::c_int as uint8_t,
        0xca as libc::c_int as uint8_t,
        0xfe as libc::c_int as uint8_t,
        0xba as libc::c_int as uint8_t,
        0xbe as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0xab as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
    ];
    let mut srtp_ciphertext: [uint8_t; 38] = [
        0x80 as libc::c_int as uint8_t,
        0xf as libc::c_int as uint8_t,
        0x12 as libc::c_int as uint8_t,
        0x34 as libc::c_int as uint8_t,
        0xde as libc::c_int as uint8_t,
        0xca as libc::c_int as uint8_t,
        0xfb as libc::c_int as uint8_t,
        0xad as libc::c_int as uint8_t,
        0xca as libc::c_int as uint8_t,
        0xfe as libc::c_int as uint8_t,
        0xba as libc::c_int as uint8_t,
        0xbe as libc::c_int as uint8_t,
        0xf1 as libc::c_int as uint8_t,
        0xd9 as libc::c_int as uint8_t,
        0xde as libc::c_int as uint8_t,
        0x17 as libc::c_int as uint8_t,
        0xff as libc::c_int as uint8_t,
        0x25 as libc::c_int as uint8_t,
        0x1f as libc::c_int as uint8_t,
        0xf1 as libc::c_int as uint8_t,
        0xaa as libc::c_int as uint8_t,
        0 as libc::c_int as uint8_t,
        0x77 as libc::c_int as uint8_t,
        0x74 as libc::c_int as uint8_t,
        0xb0 as libc::c_int as uint8_t,
        0xb4 as libc::c_int as uint8_t,
        0xb4 as libc::c_int as uint8_t,
        0xd as libc::c_int as uint8_t,
        0xa0 as libc::c_int as uint8_t,
        0x8d as libc::c_int as uint8_t,
        0x9d as libc::c_int as uint8_t,
        0x9a as libc::c_int as uint8_t,
        0x5b as libc::c_int as uint8_t,
        0x3a as libc::c_int as uint8_t,
        0x55 as libc::c_int as uint8_t,
        0xd8 as libc::c_int as uint8_t,
        0x87 as libc::c_int as uint8_t,
        0x3b as libc::c_int as uint8_t,
    ];
    let mut srtp_snd: srtp_t = 0 as *mut srtp_ctx_t;
    let mut srtp_recv: srtp_t = 0 as *mut srtp_ctx_t;
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut len: libc::c_int = 0;
    let mut policy: srtp_policy_t = srtp_policy_t {
        ssrc: srtp_ssrc_t {
            type_0: ssrc_undefined,
            value: 0,
        },
        rtp: srtp_crypto_policy_t {
            cipher_type: 0,
            cipher_key_len: 0,
            auth_type: 0,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: sec_serv_none,
        },
        rtcp: srtp_crypto_policy_t {
            cipher_type: 0,
            cipher_key_len: 0,
            auth_type: 0,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: sec_serv_none,
        },
        key: 0 as *mut libc::c_uchar,
        keys: 0 as *mut *mut srtp_master_key_t,
        num_master_keys: 0,
        deprecated_ekt: 0 as *mut libc::c_void,
        window_size: 0,
        allow_repeat_tx: 0,
        enc_xtn_hdr: 0 as *mut libc::c_int,
        enc_xtn_hdr_count: 0,
        next: 0 as *mut srtp_policy_t,
    };
    memset(
        &mut policy as *mut srtp_policy_t as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<srtp_policy_t>() as libc::c_ulong,
    );
    srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80(&mut policy.rtp);
    srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80(&mut policy.rtcp);
    policy.ssrc.type_0 = ssrc_specific;
    policy.ssrc.value = 0xcafebabe as libc::c_uint;
    policy.key = aes_256_test_key.as_mut_ptr();
    policy.deprecated_ekt = 0 as *mut libc::c_void;
    policy.window_size = 128 as libc::c_int as libc::c_ulong;
    policy.allow_repeat_tx = 0 as libc::c_int;
    policy.next = 0 as *mut srtp_policy_t;
    status = srtp_create(&mut srtp_snd, &mut policy);
    if status as u64 != 0 {
        return status;
    }
    len = 28 as libc::c_int;
    status = srtp_protect(
        srtp_snd,
        srtp_plaintext.as_mut_ptr() as *mut libc::c_void,
        &mut len,
    );
    if status as libc::c_uint != 0 || len != 38 as libc::c_int {
        return srtp_err_status_fail;
    }
    if mod_driver.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: ciphertext:\n  %s\n\0" as *const u8 as *const libc::c_char,
            mod_driver.name,
            octet_string_hex_string(
                srtp_plaintext.as_mut_ptr() as *const libc::c_void,
                len,
            ),
        );
    }
    if mod_driver.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: ciphertext reference:\n  %s\n\0" as *const u8 as *const libc::c_char,
            mod_driver.name,
            octet_string_hex_string(
                srtp_ciphertext.as_mut_ptr() as *const libc::c_void,
                len,
            ),
        );
    }
    if srtp_octet_string_is_eq(
        srtp_plaintext.as_mut_ptr(),
        srtp_ciphertext.as_mut_ptr(),
        len,
    ) != 0
    {
        return srtp_err_status_fail;
    }
    status = srtp_create(&mut srtp_recv, &mut policy);
    if status as u64 != 0 {
        return status;
    }
    status = srtp_unprotect(
        srtp_recv,
        srtp_ciphertext.as_mut_ptr() as *mut libc::c_void,
        &mut len,
    );
    if status as libc::c_uint != 0 || len != 28 as libc::c_int {
        return status;
    }
    if srtp_octet_string_is_eq(
        srtp_ciphertext.as_mut_ptr(),
        srtp_plaintext_ref.as_mut_ptr(),
        len,
    ) != 0
    {
        return srtp_err_status_fail;
    }
    status = srtp_dealloc(srtp_snd);
    if status as u64 != 0 {
        return status;
    }
    status = srtp_dealloc(srtp_recv);
    if status as u64 != 0 {
        return status;
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_create_big_policy(
    mut list: *mut *mut srtp_policy_t,
) -> srtp_err_status_t {
    extern "C" {
        #[link_name = "policy_array"]
        static mut policy_array_0: [*const srtp_policy_t; 6];
    }
    let mut p: *mut srtp_policy_t = 0 as *mut srtp_policy_t;
    let mut tmp: *mut srtp_policy_t = 0 as *mut srtp_policy_t;
    let mut i: libc::c_int = 0 as libc::c_int;
    let mut ssrc: uint32_t = 0 as libc::c_int as uint32_t;
    if list.is_null()
        || (*policy_array.as_mut_ptr().offset(0 as libc::c_int as isize)).is_null()
    {
        return srtp_err_status_bad_param;
    }
    tmp = 0 as *mut srtp_policy_t;
    while !(*policy_array.as_mut_ptr().offset(i as isize)).is_null() {
        p = malloc(::core::mem::size_of::<srtp_policy_t>() as libc::c_ulong)
            as *mut srtp_policy_t;
        if p.is_null() {
            return srtp_err_status_bad_param;
        }
        memcpy(
            p as *mut libc::c_void,
            *policy_array.as_mut_ptr().offset(i as isize) as *const libc::c_void,
            ::core::mem::size_of::<srtp_policy_t>() as libc::c_ulong,
        );
        (*p).ssrc.type_0 = ssrc_specific;
        let fresh6 = ssrc;
        ssrc = ssrc.wrapping_add(1);
        (*p).ssrc.value = fresh6;
        (*p).next = tmp;
        tmp = p;
        i += 1;
    }
    *list = p;
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_dealloc_big_policy(
    mut list: *mut srtp_policy_t,
) -> srtp_err_status_t {
    let mut p: *mut srtp_policy_t = 0 as *mut srtp_policy_t;
    let mut next: *mut srtp_policy_t = 0 as *mut srtp_policy_t;
    p = list;
    while !p.is_null() {
        next = (*p).next;
        free(p as *mut libc::c_void);
        p = next;
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_test_empty_payload() -> srtp_err_status_t {
    let mut srtp_snd: srtp_t = 0 as *mut srtp_ctx_t;
    let mut srtp_recv: srtp_t = 0 as *mut srtp_ctx_t;
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut len: libc::c_int = 0;
    let mut policy: srtp_policy_t = srtp_policy_t {
        ssrc: srtp_ssrc_t {
            type_0: ssrc_undefined,
            value: 0,
        },
        rtp: srtp_crypto_policy_t {
            cipher_type: 0,
            cipher_key_len: 0,
            auth_type: 0,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: sec_serv_none,
        },
        rtcp: srtp_crypto_policy_t {
            cipher_type: 0,
            cipher_key_len: 0,
            auth_type: 0,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: sec_serv_none,
        },
        key: 0 as *mut libc::c_uchar,
        keys: 0 as *mut *mut srtp_master_key_t,
        num_master_keys: 0,
        deprecated_ekt: 0 as *mut libc::c_void,
        window_size: 0,
        allow_repeat_tx: 0,
        enc_xtn_hdr: 0 as *mut libc::c_int,
        enc_xtn_hdr_count: 0,
        next: 0 as *mut srtp_policy_t,
    };
    let mut mesg: *mut srtp_hdr_t = 0 as *mut srtp_hdr_t;
    memset(
        &mut policy as *mut srtp_policy_t as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<srtp_policy_t>() as libc::c_ulong,
    );
    srtp_crypto_policy_set_rtp_default(&mut policy.rtp);
    srtp_crypto_policy_set_rtcp_default(&mut policy.rtcp);
    policy.ssrc.type_0 = ssrc_specific;
    policy.ssrc.value = 0xcafebabe as libc::c_uint;
    policy.key = test_key.as_mut_ptr();
    policy.deprecated_ekt = 0 as *mut libc::c_void;
    policy.window_size = 128 as libc::c_int as libc::c_ulong;
    policy.allow_repeat_tx = 0 as libc::c_int;
    policy.next = 0 as *mut srtp_policy_t;
    status = srtp_create(&mut srtp_snd, &mut policy);
    if status as u64 != 0 {
        return status;
    }
    mesg = srtp_create_test_packet(0 as libc::c_int, policy.ssrc.value, &mut len);
    if mesg.is_null() {
        return srtp_err_status_fail;
    }
    status = srtp_protect(srtp_snd, mesg as *mut libc::c_void, &mut len);
    if status as u64 != 0 {
        return status
    } else {
        if len != 12 as libc::c_int + 10 as libc::c_int {
            return srtp_err_status_fail;
        }
    }
    status = srtp_create(&mut srtp_recv, &mut policy);
    if status as u64 != 0 {
        return status;
    }
    status = srtp_unprotect(srtp_recv, mesg as *mut libc::c_void, &mut len);
    if status as u64 != 0 {
        return status
    } else {
        if len != 12 as libc::c_int {
            return srtp_err_status_fail;
        }
    }
    status = srtp_dealloc(srtp_snd);
    if status as u64 != 0 {
        return status;
    }
    status = srtp_dealloc(srtp_recv);
    if status as u64 != 0 {
        return status;
    }
    free(mesg as *mut libc::c_void);
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_test_remove_stream() -> srtp_err_status_t {
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut policy_list: *mut srtp_policy_t = 0 as *mut srtp_policy_t;
    let mut policy: srtp_policy_t = srtp_policy_t {
        ssrc: srtp_ssrc_t {
            type_0: ssrc_undefined,
            value: 0,
        },
        rtp: srtp_crypto_policy_t {
            cipher_type: 0,
            cipher_key_len: 0,
            auth_type: 0,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: sec_serv_none,
        },
        rtcp: srtp_crypto_policy_t {
            cipher_type: 0,
            cipher_key_len: 0,
            auth_type: 0,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: sec_serv_none,
        },
        key: 0 as *mut libc::c_uchar,
        keys: 0 as *mut *mut srtp_master_key_t,
        num_master_keys: 0,
        deprecated_ekt: 0 as *mut libc::c_void,
        window_size: 0,
        allow_repeat_tx: 0,
        enc_xtn_hdr: 0 as *mut libc::c_int,
        enc_xtn_hdr_count: 0,
        next: 0 as *mut srtp_policy_t,
    };
    let mut session: srtp_t = 0 as *mut srtp_ctx_t;
    let mut stream: srtp_stream_t = 0 as *mut srtp_stream_ctx_t;
    status = srtp_create_big_policy(&mut policy_list);
    if status as u64 != 0 {
        return status;
    }
    status = srtp_create(&mut session, policy_list);
    if status as u64 != 0 {
        return status;
    }
    status = srtp_remove_stream(session, __bswap_32(0xaaaaaaaa as libc::c_uint));
    if status as libc::c_uint != srtp_err_status_no_ctx as libc::c_int as libc::c_uint {
        return srtp_err_status_fail;
    }
    status = srtp_remove_stream(session, __bswap_32(0x1 as libc::c_int as __uint32_t));
    if status as libc::c_uint != srtp_err_status_ok as libc::c_int as libc::c_uint {
        return srtp_err_status_fail;
    }
    stream = srtp_get_stream(session, __bswap_32(0 as libc::c_int as __uint32_t));
    if stream.is_null() {
        return srtp_err_status_fail;
    }
    stream = srtp_get_stream(session, __bswap_32(0x2 as libc::c_int as __uint32_t));
    if stream.is_null() {
        return srtp_err_status_fail;
    }
    status = srtp_dealloc(session);
    if status as libc::c_uint != srtp_err_status_ok as libc::c_int as libc::c_uint {
        return status;
    }
    status = srtp_dealloc_big_policy(policy_list);
    if status as libc::c_uint != srtp_err_status_ok as libc::c_int as libc::c_uint {
        return status;
    }
    memset(
        &mut policy as *mut srtp_policy_t as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<srtp_policy_t>() as libc::c_ulong,
    );
    srtp_crypto_policy_set_rtp_default(&mut policy.rtp);
    srtp_crypto_policy_set_rtcp_default(&mut policy.rtcp);
    policy.ssrc.type_0 = ssrc_specific;
    policy.ssrc.value = 0xcafebabe as libc::c_uint;
    policy.key = test_key.as_mut_ptr();
    policy.deprecated_ekt = 0 as *mut libc::c_void;
    policy.window_size = 128 as libc::c_int as libc::c_ulong;
    policy.allow_repeat_tx = 0 as libc::c_int;
    policy.next = 0 as *mut srtp_policy_t;
    status = srtp_create(&mut session, 0 as *const srtp_policy_t);
    if status as libc::c_uint != srtp_err_status_ok as libc::c_int as libc::c_uint {
        return status;
    }
    status = srtp_add_stream(session, &mut policy);
    if status as libc::c_uint != srtp_err_status_ok as libc::c_int as libc::c_uint {
        return status;
    }
    status = srtp_remove_stream(session, __bswap_32(0xcafebabe as libc::c_uint));
    if status as libc::c_uint != srtp_err_status_ok as libc::c_int as libc::c_uint {
        return status;
    }
    status = srtp_dealloc(session);
    if status as libc::c_uint != srtp_err_status_ok as libc::c_int as libc::c_uint {
        return status;
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub static mut test_alt_key: [libc::c_uchar; 46] = [
    0xe5 as libc::c_int as libc::c_uchar,
    0x19 as libc::c_int as libc::c_uchar,
    0x6f as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x5e as libc::c_int as libc::c_uchar,
    0xf1 as libc::c_int as libc::c_uchar,
    0x9b as libc::c_int as libc::c_uchar,
    0xe1 as libc::c_int as libc::c_uchar,
    0xd7 as libc::c_int as libc::c_uchar,
    0x47 as libc::c_int as libc::c_uchar,
    0xa7 as libc::c_int as libc::c_uchar,
    0x27 as libc::c_int as libc::c_uchar,
    0x7 as libc::c_int as libc::c_uchar,
    0xd7 as libc::c_int as libc::c_uchar,
    0x47 as libc::c_int as libc::c_uchar,
    0x33 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0xc2 as libc::c_int as libc::c_uchar,
    0x35 as libc::c_int as libc::c_uchar,
    0x4d as libc::c_int as libc::c_uchar,
    0x59 as libc::c_int as libc::c_uchar,
    0x6a as libc::c_int as libc::c_uchar,
    0xf7 as libc::c_int as libc::c_uchar,
    0x84 as libc::c_int as libc::c_uchar,
    0x96 as libc::c_int as libc::c_uchar,
    0x98 as libc::c_int as libc::c_uchar,
    0xeb as libc::c_int as libc::c_uchar,
    0xaa as libc::c_int as libc::c_uchar,
    0xac as libc::c_int as libc::c_uchar,
    0xf6 as libc::c_int as libc::c_uchar,
    0xa1 as libc::c_int as libc::c_uchar,
    0x45 as libc::c_int as libc::c_uchar,
    0xc7 as libc::c_int as libc::c_uchar,
    0x15 as libc::c_int as libc::c_uchar,
    0xe2 as libc::c_int as libc::c_uchar,
    0xea as libc::c_int as libc::c_uchar,
    0xfe as libc::c_int as libc::c_uchar,
    0x55 as libc::c_int as libc::c_uchar,
    0x67 as libc::c_int as libc::c_uchar,
    0x96 as libc::c_int as libc::c_uchar,
    0xb6 as libc::c_int as libc::c_uchar,
    0x96 as libc::c_int as libc::c_uchar,
    0xb as libc::c_int as libc::c_uchar,
    0x3a as libc::c_int as libc::c_uchar,
    0xab as libc::c_int as libc::c_uchar,
    0xe6 as libc::c_int as libc::c_uchar,
];
#[no_mangle]
pub unsafe extern "C" fn srtp_test_update() -> srtp_err_status_t {
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut ssrc: uint32_t = 0x12121212 as libc::c_int as uint32_t;
    let mut msg_len_octets: libc::c_int = 32 as libc::c_int;
    let mut protected_msg_len_octets: libc::c_int = 0;
    let mut msg: *mut srtp_hdr_t = 0 as *mut srtp_hdr_t;
    let mut srtp_snd: srtp_t = 0 as *mut srtp_ctx_t;
    let mut srtp_recv: srtp_t = 0 as *mut srtp_ctx_t;
    let mut policy: srtp_policy_t = srtp_policy_t {
        ssrc: srtp_ssrc_t {
            type_0: ssrc_undefined,
            value: 0,
        },
        rtp: srtp_crypto_policy_t {
            cipher_type: 0,
            cipher_key_len: 0,
            auth_type: 0,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: sec_serv_none,
        },
        rtcp: srtp_crypto_policy_t {
            cipher_type: 0,
            cipher_key_len: 0,
            auth_type: 0,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: sec_serv_none,
        },
        key: 0 as *mut libc::c_uchar,
        keys: 0 as *mut *mut srtp_master_key_t,
        num_master_keys: 0,
        deprecated_ekt: 0 as *mut libc::c_void,
        window_size: 0,
        allow_repeat_tx: 0,
        enc_xtn_hdr: 0 as *mut libc::c_int,
        enc_xtn_hdr_count: 0,
        next: 0 as *mut srtp_policy_t,
    };
    memset(
        &mut policy as *mut srtp_policy_t as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<srtp_policy_t>() as libc::c_ulong,
    );
    srtp_crypto_policy_set_rtp_default(&mut policy.rtp);
    srtp_crypto_policy_set_rtcp_default(&mut policy.rtcp);
    policy.deprecated_ekt = 0 as *mut libc::c_void;
    policy.window_size = 128 as libc::c_int as libc::c_ulong;
    policy.allow_repeat_tx = 0 as libc::c_int;
    policy.next = 0 as *mut srtp_policy_t;
    policy.ssrc.type_0 = ssrc_any_outbound;
    policy.key = test_key.as_mut_ptr();
    status = srtp_create(&mut srtp_recv, &mut policy);
    if status as u64 != 0 {
        return status;
    }
    policy.ssrc.type_0 = ssrc_any_inbound;
    status = srtp_create(&mut srtp_snd, &mut policy);
    if status as u64 != 0 {
        return status;
    }
    msg = srtp_create_test_packet(msg_len_octets, ssrc, &mut protected_msg_len_octets);
    if msg.is_null() {
        return srtp_err_status_alloc_fail;
    }
    (*msg).seq = __bswap_16(65535 as libc::c_int as __uint16_t);
    status = srtp_protect(
        srtp_snd,
        msg as *mut libc::c_void,
        &mut protected_msg_len_octets,
    );
    if status as u64 != 0 {
        return srtp_err_status_fail;
    }
    status = srtp_unprotect(
        srtp_recv,
        msg as *mut libc::c_void,
        &mut protected_msg_len_octets,
    );
    if status as u64 != 0 {
        return status;
    }
    free(msg as *mut libc::c_void);
    msg = srtp_create_test_packet(msg_len_octets, ssrc, &mut protected_msg_len_octets);
    if msg.is_null() {
        return srtp_err_status_alloc_fail;
    }
    (*msg).seq = __bswap_16(1 as libc::c_int as __uint16_t);
    status = srtp_protect(
        srtp_snd,
        msg as *mut libc::c_void,
        &mut protected_msg_len_octets,
    );
    if status as u64 != 0 {
        return srtp_err_status_fail;
    }
    status = srtp_unprotect(
        srtp_recv,
        msg as *mut libc::c_void,
        &mut protected_msg_len_octets,
    );
    if status as u64 != 0 {
        return status;
    }
    free(msg as *mut libc::c_void);
    policy.ssrc.type_0 = ssrc_any_outbound;
    policy.key = test_key.as_mut_ptr();
    status = srtp_update(srtp_snd, &mut policy);
    if status as u64 != 0 {
        return status;
    }
    msg = srtp_create_test_packet(msg_len_octets, ssrc, &mut protected_msg_len_octets);
    if msg.is_null() {
        return srtp_err_status_alloc_fail;
    }
    (*msg).seq = __bswap_16(2 as libc::c_int as __uint16_t);
    status = srtp_protect(
        srtp_snd,
        msg as *mut libc::c_void,
        &mut protected_msg_len_octets,
    );
    if status as u64 != 0 {
        return srtp_err_status_fail;
    }
    status = srtp_unprotect(
        srtp_recv,
        msg as *mut libc::c_void,
        &mut protected_msg_len_octets,
    );
    if status as u64 != 0 {
        return status;
    }
    free(msg as *mut libc::c_void);
    policy.ssrc.type_0 = ssrc_any_outbound;
    policy.key = test_alt_key.as_mut_ptr();
    status = srtp_update(srtp_snd, &mut policy);
    if status as u64 != 0 {
        return status;
    }
    msg = srtp_create_test_packet(msg_len_octets, ssrc, &mut protected_msg_len_octets);
    if msg.is_null() {
        return srtp_err_status_alloc_fail;
    }
    (*msg).seq = __bswap_16(3 as libc::c_int as __uint16_t);
    status = srtp_protect(
        srtp_snd,
        msg as *mut libc::c_void,
        &mut protected_msg_len_octets,
    );
    if status as u64 != 0 {
        return srtp_err_status_fail;
    }
    status = srtp_unprotect(
        srtp_recv,
        msg as *mut libc::c_void,
        &mut protected_msg_len_octets,
    );
    if status as libc::c_uint == srtp_err_status_ok as libc::c_int as libc::c_uint {
        return srtp_err_status_fail;
    }
    let mut srtp_recv_roc_0: srtp_t = 0 as *mut srtp_ctx_t;
    policy.ssrc.type_0 = ssrc_any_inbound;
    policy.key = test_alt_key.as_mut_ptr();
    status = srtp_create(&mut srtp_recv_roc_0, &mut policy);
    if status as u64 != 0 {
        return status;
    }
    status = srtp_unprotect(
        srtp_recv_roc_0,
        msg as *mut libc::c_void,
        &mut protected_msg_len_octets,
    );
    if status as libc::c_uint == srtp_err_status_ok as libc::c_int as libc::c_uint {
        return srtp_err_status_fail;
    }
    status = srtp_dealloc(srtp_recv_roc_0);
    if status as u64 != 0 {
        return status;
    }
    policy.ssrc.type_0 = ssrc_any_inbound;
    policy.key = test_alt_key.as_mut_ptr();
    status = srtp_update(srtp_recv, &mut policy);
    if status as u64 != 0 {
        return status;
    }
    status = srtp_unprotect(
        srtp_recv,
        msg as *mut libc::c_void,
        &mut protected_msg_len_octets,
    );
    if status as u64 != 0 {
        return status;
    }
    free(msg as *mut libc::c_void);
    status = srtp_dealloc(srtp_snd);
    if status as u64 != 0 {
        return status;
    }
    status = srtp_dealloc(srtp_recv);
    if status as u64 != 0 {
        return status;
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_test_setup_protect_trailer_streams(
    mut srtp_send: *mut srtp_t,
    mut srtp_send_mki: *mut srtp_t,
    mut srtp_send_aes_gcm: *mut srtp_t,
    mut srtp_send_aes_gcm_mki: *mut srtp_t,
) -> srtp_err_status_t {
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut policy: srtp_policy_t = srtp_policy_t {
        ssrc: srtp_ssrc_t {
            type_0: ssrc_undefined,
            value: 0,
        },
        rtp: srtp_crypto_policy_t {
            cipher_type: 0,
            cipher_key_len: 0,
            auth_type: 0,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: sec_serv_none,
        },
        rtcp: srtp_crypto_policy_t {
            cipher_type: 0,
            cipher_key_len: 0,
            auth_type: 0,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: sec_serv_none,
        },
        key: 0 as *mut libc::c_uchar,
        keys: 0 as *mut *mut srtp_master_key_t,
        num_master_keys: 0,
        deprecated_ekt: 0 as *mut libc::c_void,
        window_size: 0,
        allow_repeat_tx: 0,
        enc_xtn_hdr: 0 as *mut libc::c_int,
        enc_xtn_hdr_count: 0,
        next: 0 as *mut srtp_policy_t,
    };
    let mut policy_mki: srtp_policy_t = srtp_policy_t {
        ssrc: srtp_ssrc_t {
            type_0: ssrc_undefined,
            value: 0,
        },
        rtp: srtp_crypto_policy_t {
            cipher_type: 0,
            cipher_key_len: 0,
            auth_type: 0,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: sec_serv_none,
        },
        rtcp: srtp_crypto_policy_t {
            cipher_type: 0,
            cipher_key_len: 0,
            auth_type: 0,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: sec_serv_none,
        },
        key: 0 as *mut libc::c_uchar,
        keys: 0 as *mut *mut srtp_master_key_t,
        num_master_keys: 0,
        deprecated_ekt: 0 as *mut libc::c_void,
        window_size: 0,
        allow_repeat_tx: 0,
        enc_xtn_hdr: 0 as *mut libc::c_int,
        enc_xtn_hdr_count: 0,
        next: 0 as *mut srtp_policy_t,
    };
    memset(
        &mut policy as *mut srtp_policy_t as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<srtp_policy_t>() as libc::c_ulong,
    );
    srtp_crypto_policy_set_rtp_default(&mut policy.rtp);
    srtp_crypto_policy_set_rtcp_default(&mut policy.rtcp);
    policy.deprecated_ekt = 0 as *mut libc::c_void;
    policy.window_size = 128 as libc::c_int as libc::c_ulong;
    policy.allow_repeat_tx = 0 as libc::c_int;
    policy.next = 0 as *mut srtp_policy_t;
    policy.ssrc.type_0 = ssrc_any_outbound;
    policy.key = test_key.as_mut_ptr();
    memset(
        &mut policy_mki as *mut srtp_policy_t as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<srtp_policy_t>() as libc::c_ulong,
    );
    srtp_crypto_policy_set_rtp_default(&mut policy_mki.rtp);
    srtp_crypto_policy_set_rtcp_default(&mut policy_mki.rtcp);
    policy_mki.deprecated_ekt = 0 as *mut libc::c_void;
    policy_mki.window_size = 128 as libc::c_int as libc::c_ulong;
    policy_mki.allow_repeat_tx = 0 as libc::c_int;
    policy_mki.next = 0 as *mut srtp_policy_t;
    policy_mki.ssrc.type_0 = ssrc_any_outbound;
    policy_mki.key = 0 as *mut libc::c_uchar;
    policy_mki.keys = test_keys.as_mut_ptr();
    policy_mki.num_master_keys = 2 as libc::c_int as libc::c_ulong;
    status = srtp_create(srtp_send, &mut policy);
    if status as u64 != 0 {
        return status;
    }
    status = srtp_create(srtp_send_mki, &mut policy_mki);
    if status as u64 != 0 {
        return status;
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_test_protect_trailer_length() -> srtp_err_status_t {
    let mut srtp_send: srtp_t = 0 as *mut srtp_ctx_t;
    let mut srtp_send_mki: srtp_t = 0 as *mut srtp_ctx_t;
    let mut srtp_send_aes_gcm: srtp_t = 0 as *mut srtp_ctx_t;
    let mut srtp_send_aes_gcm_mki: srtp_t = 0 as *mut srtp_ctx_t;
    let mut length: uint32_t = 0 as libc::c_int as uint32_t;
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    srtp_test_setup_protect_trailer_streams(
        &mut srtp_send,
        &mut srtp_send_mki,
        &mut srtp_send_aes_gcm,
        &mut srtp_send_aes_gcm_mki,
    );
    status = srtp_get_protect_trailer_length(
        srtp_send,
        0 as libc::c_int as uint32_t,
        0 as libc::c_int as uint32_t,
        &mut length,
    );
    if status as u64 != 0 {
        return status;
    }
    if length != 10 as libc::c_int as libc::c_uint {
        return srtp_err_status_fail;
    }
    status = srtp_get_protect_trailer_length(
        srtp_send_mki,
        1 as libc::c_int as uint32_t,
        1 as libc::c_int as uint32_t,
        &mut length,
    );
    if status as u64 != 0 {
        return status;
    }
    if length != 14 as libc::c_int as libc::c_uint {
        return srtp_err_status_fail;
    }
    srtp_dealloc(srtp_send);
    srtp_dealloc(srtp_send_mki);
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_test_protect_rtcp_trailer_length() -> srtp_err_status_t {
    let mut srtp_send: srtp_t = 0 as *mut srtp_ctx_t;
    let mut srtp_send_mki: srtp_t = 0 as *mut srtp_ctx_t;
    let mut srtp_send_aes_gcm: srtp_t = 0 as *mut srtp_ctx_t;
    let mut srtp_send_aes_gcm_mki: srtp_t = 0 as *mut srtp_ctx_t;
    let mut length: uint32_t = 0 as libc::c_int as uint32_t;
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    srtp_test_setup_protect_trailer_streams(
        &mut srtp_send,
        &mut srtp_send_mki,
        &mut srtp_send_aes_gcm,
        &mut srtp_send_aes_gcm_mki,
    );
    status = srtp_get_protect_rtcp_trailer_length(
        srtp_send,
        0 as libc::c_int as uint32_t,
        0 as libc::c_int as uint32_t,
        &mut length,
    );
    if status as u64 != 0 {
        return status;
    }
    if length != 14 as libc::c_int as libc::c_uint {
        return srtp_err_status_fail;
    }
    status = srtp_get_protect_rtcp_trailer_length(
        srtp_send_mki,
        1 as libc::c_int as uint32_t,
        1 as libc::c_int as uint32_t,
        &mut length,
    );
    if status as u64 != 0 {
        return status;
    }
    if length != 18 as libc::c_int as libc::c_uint {
        return srtp_err_status_fail;
    }
    srtp_dealloc(srtp_send);
    srtp_dealloc(srtp_send_mki);
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_test_out_of_order_after_rollover() -> srtp_err_status_t {
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut sender_policy: srtp_policy_t = srtp_policy_t {
        ssrc: srtp_ssrc_t {
            type_0: ssrc_undefined,
            value: 0,
        },
        rtp: srtp_crypto_policy_t {
            cipher_type: 0,
            cipher_key_len: 0,
            auth_type: 0,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: sec_serv_none,
        },
        rtcp: srtp_crypto_policy_t {
            cipher_type: 0,
            cipher_key_len: 0,
            auth_type: 0,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: sec_serv_none,
        },
        key: 0 as *mut libc::c_uchar,
        keys: 0 as *mut *mut srtp_master_key_t,
        num_master_keys: 0,
        deprecated_ekt: 0 as *mut libc::c_void,
        window_size: 0,
        allow_repeat_tx: 0,
        enc_xtn_hdr: 0 as *mut libc::c_int,
        enc_xtn_hdr_count: 0,
        next: 0 as *mut srtp_policy_t,
    };
    let mut sender_session: srtp_t = 0 as *mut srtp_ctx_t;
    let mut receiver_policy: srtp_policy_t = srtp_policy_t {
        ssrc: srtp_ssrc_t {
            type_0: ssrc_undefined,
            value: 0,
        },
        rtp: srtp_crypto_policy_t {
            cipher_type: 0,
            cipher_key_len: 0,
            auth_type: 0,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: sec_serv_none,
        },
        rtcp: srtp_crypto_policy_t {
            cipher_type: 0,
            cipher_key_len: 0,
            auth_type: 0,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: sec_serv_none,
        },
        key: 0 as *mut libc::c_uchar,
        keys: 0 as *mut *mut srtp_master_key_t,
        num_master_keys: 0,
        deprecated_ekt: 0 as *mut libc::c_void,
        window_size: 0,
        allow_repeat_tx: 0,
        enc_xtn_hdr: 0 as *mut libc::c_int,
        enc_xtn_hdr_count: 0,
        next: 0 as *mut srtp_policy_t,
    };
    let mut receiver_session: srtp_t = 0 as *mut srtp_ctx_t;
    let num_pkts: uint32_t = 5 as libc::c_int as uint32_t;
    let mut pkts: [*mut srtp_hdr_t; 5] = [0 as *mut srtp_hdr_t; 5];
    let mut pkt_len_octets: [libc::c_int; 5] = [0; 5];
    let mut i: uint32_t = 0;
    let mut stream_roc: uint32_t = 0;
    memset(
        &mut sender_policy as *mut srtp_policy_t as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<srtp_policy_t>() as libc::c_ulong,
    );
    srtp_crypto_policy_set_rtp_default(&mut sender_policy.rtp);
    srtp_crypto_policy_set_rtcp_default(&mut sender_policy.rtcp);
    sender_policy.key = test_key.as_mut_ptr();
    sender_policy.ssrc.type_0 = ssrc_specific;
    sender_policy.ssrc.value = 0xcafebabe as libc::c_uint;
    sender_policy.window_size = 128 as libc::c_int as libc::c_ulong;
    status = srtp_create(&mut sender_session, &mut sender_policy);
    if status as u64 != 0 {
        return status;
    }
    memset(
        &mut receiver_policy as *mut srtp_policy_t as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<srtp_policy_t>() as libc::c_ulong,
    );
    srtp_crypto_policy_set_rtp_default(&mut receiver_policy.rtp);
    srtp_crypto_policy_set_rtcp_default(&mut receiver_policy.rtcp);
    receiver_policy.key = test_key.as_mut_ptr();
    receiver_policy.ssrc.type_0 = ssrc_specific;
    receiver_policy.ssrc.value = sender_policy.ssrc.value;
    receiver_policy.window_size = 128 as libc::c_int as libc::c_ulong;
    status = srtp_create(&mut receiver_session, &mut receiver_policy);
    if status as u64 != 0 {
        return status;
    }
    pkts[0 as libc::c_int
        as usize] = srtp_create_test_packet_extended(
        64 as libc::c_int,
        sender_policy.ssrc.value,
        65534 as libc::c_int as uint16_t,
        0 as libc::c_int as uint32_t,
        &mut *pkt_len_octets.as_mut_ptr().offset(0 as libc::c_int as isize),
    );
    status = srtp_protect(
        sender_session,
        pkts[0 as libc::c_int as usize] as *mut libc::c_void,
        &mut *pkt_len_octets.as_mut_ptr().offset(0 as libc::c_int as isize),
    );
    if status as u64 != 0 {
        return status;
    }
    status = srtp_get_stream_roc(
        sender_session,
        sender_policy.ssrc.value,
        &mut stream_roc,
    );
    if status as u64 != 0 {
        return status;
    }
    if stream_roc != 0 as libc::c_int as libc::c_uint {
        return srtp_err_status_fail;
    }
    pkts[1 as libc::c_int
        as usize] = srtp_create_test_packet_extended(
        64 as libc::c_int,
        sender_policy.ssrc.value,
        65535 as libc::c_int as uint16_t,
        1 as libc::c_int as uint32_t,
        &mut *pkt_len_octets.as_mut_ptr().offset(1 as libc::c_int as isize),
    );
    status = srtp_protect(
        sender_session,
        pkts[1 as libc::c_int as usize] as *mut libc::c_void,
        &mut *pkt_len_octets.as_mut_ptr().offset(1 as libc::c_int as isize),
    );
    if status as u64 != 0 {
        return status;
    }
    status = srtp_get_stream_roc(
        sender_session,
        sender_policy.ssrc.value,
        &mut stream_roc,
    );
    if status as u64 != 0 {
        return status;
    }
    if stream_roc != 0 as libc::c_int as libc::c_uint {
        return srtp_err_status_fail;
    }
    pkts[2 as libc::c_int
        as usize] = srtp_create_test_packet_extended(
        64 as libc::c_int,
        sender_policy.ssrc.value,
        0 as libc::c_int as uint16_t,
        2 as libc::c_int as uint32_t,
        &mut *pkt_len_octets.as_mut_ptr().offset(2 as libc::c_int as isize),
    );
    status = srtp_protect(
        sender_session,
        pkts[2 as libc::c_int as usize] as *mut libc::c_void,
        &mut *pkt_len_octets.as_mut_ptr().offset(2 as libc::c_int as isize),
    );
    if status as u64 != 0 {
        return status;
    }
    status = srtp_get_stream_roc(
        sender_session,
        sender_policy.ssrc.value,
        &mut stream_roc,
    );
    if status as u64 != 0 {
        return status;
    }
    if stream_roc != 1 as libc::c_int as libc::c_uint {
        return srtp_err_status_fail;
    }
    pkts[3 as libc::c_int
        as usize] = srtp_create_test_packet_extended(
        64 as libc::c_int,
        sender_policy.ssrc.value,
        1 as libc::c_int as uint16_t,
        3 as libc::c_int as uint32_t,
        &mut *pkt_len_octets.as_mut_ptr().offset(3 as libc::c_int as isize),
    );
    status = srtp_protect(
        sender_session,
        pkts[3 as libc::c_int as usize] as *mut libc::c_void,
        &mut *pkt_len_octets.as_mut_ptr().offset(3 as libc::c_int as isize),
    );
    if status as u64 != 0 {
        return status;
    }
    status = srtp_get_stream_roc(
        sender_session,
        sender_policy.ssrc.value,
        &mut stream_roc,
    );
    if status as u64 != 0 {
        return status;
    }
    if stream_roc != 1 as libc::c_int as libc::c_uint {
        return srtp_err_status_fail;
    }
    pkts[4 as libc::c_int
        as usize] = srtp_create_test_packet_extended(
        64 as libc::c_int,
        sender_policy.ssrc.value,
        2 as libc::c_int as uint16_t,
        4 as libc::c_int as uint32_t,
        &mut *pkt_len_octets.as_mut_ptr().offset(4 as libc::c_int as isize),
    );
    status = srtp_protect(
        sender_session,
        pkts[4 as libc::c_int as usize] as *mut libc::c_void,
        &mut *pkt_len_octets.as_mut_ptr().offset(4 as libc::c_int as isize),
    );
    if status as u64 != 0 {
        return status;
    }
    status = srtp_get_stream_roc(
        sender_session,
        sender_policy.ssrc.value,
        &mut stream_roc,
    );
    if status as u64 != 0 {
        return status;
    }
    if stream_roc != 1 as libc::c_int as libc::c_uint {
        return srtp_err_status_fail;
    }
    status = srtp_unprotect(
        receiver_session,
        pkts[0 as libc::c_int as usize] as *mut libc::c_void,
        &mut *pkt_len_octets.as_mut_ptr().offset(0 as libc::c_int as isize),
    );
    if status as u64 != 0 {
        return status;
    }
    status = srtp_get_stream_roc(
        receiver_session,
        receiver_policy.ssrc.value,
        &mut stream_roc,
    );
    if status as u64 != 0 {
        return status;
    }
    if stream_roc != 0 as libc::c_int as libc::c_uint {
        return srtp_err_status_fail;
    }
    status = srtp_unprotect(
        receiver_session,
        pkts[2 as libc::c_int as usize] as *mut libc::c_void,
        &mut *pkt_len_octets.as_mut_ptr().offset(2 as libc::c_int as isize),
    );
    if status as u64 != 0 {
        return status;
    }
    status = srtp_get_stream_roc(
        receiver_session,
        receiver_policy.ssrc.value,
        &mut stream_roc,
    );
    if status as u64 != 0 {
        return status;
    }
    if stream_roc != 1 as libc::c_int as libc::c_uint {
        return srtp_err_status_fail;
    }
    status = srtp_unprotect(
        receiver_session,
        pkts[4 as libc::c_int as usize] as *mut libc::c_void,
        &mut *pkt_len_octets.as_mut_ptr().offset(4 as libc::c_int as isize),
    );
    if status as u64 != 0 {
        return status;
    }
    status = srtp_get_stream_roc(
        receiver_session,
        receiver_policy.ssrc.value,
        &mut stream_roc,
    );
    if status as u64 != 0 {
        return status;
    }
    if stream_roc != 1 as libc::c_int as libc::c_uint {
        return srtp_err_status_fail;
    }
    status = srtp_unprotect(
        receiver_session,
        pkts[3 as libc::c_int as usize] as *mut libc::c_void,
        &mut *pkt_len_octets.as_mut_ptr().offset(3 as libc::c_int as isize),
    );
    if status as u64 != 0 {
        return status;
    }
    status = srtp_get_stream_roc(
        receiver_session,
        receiver_policy.ssrc.value,
        &mut stream_roc,
    );
    if status as u64 != 0 {
        return status;
    }
    if stream_roc != 1 as libc::c_int as libc::c_uint {
        return srtp_err_status_fail;
    }
    status = srtp_unprotect(
        receiver_session,
        pkts[1 as libc::c_int as usize] as *mut libc::c_void,
        &mut *pkt_len_octets.as_mut_ptr().offset(1 as libc::c_int as isize),
    );
    if status as u64 != 0 {
        return status;
    }
    status = srtp_get_stream_roc(
        receiver_session,
        receiver_policy.ssrc.value,
        &mut stream_roc,
    );
    if status as u64 != 0 {
        return status;
    }
    if stream_roc != 1 as libc::c_int as libc::c_uint {
        return srtp_err_status_fail;
    }
    status = srtp_dealloc(sender_session);
    if status as u64 != 0 {
        return status;
    }
    status = srtp_dealloc(receiver_session);
    if status as u64 != 0 {
        return status;
    }
    i = 0 as libc::c_int as uint32_t;
    while i < num_pkts {
        free(pkts[i as usize] as *mut libc::c_void);
        i = i.wrapping_add(1);
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_test_get_roc() -> srtp_err_status_t {
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut policy: srtp_policy_t = srtp_policy_t {
        ssrc: srtp_ssrc_t {
            type_0: ssrc_undefined,
            value: 0,
        },
        rtp: srtp_crypto_policy_t {
            cipher_type: 0,
            cipher_key_len: 0,
            auth_type: 0,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: sec_serv_none,
        },
        rtcp: srtp_crypto_policy_t {
            cipher_type: 0,
            cipher_key_len: 0,
            auth_type: 0,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: sec_serv_none,
        },
        key: 0 as *mut libc::c_uchar,
        keys: 0 as *mut *mut srtp_master_key_t,
        num_master_keys: 0,
        deprecated_ekt: 0 as *mut libc::c_void,
        window_size: 0,
        allow_repeat_tx: 0,
        enc_xtn_hdr: 0 as *mut libc::c_int,
        enc_xtn_hdr_count: 0,
        next: 0 as *mut srtp_policy_t,
    };
    let mut session: srtp_t = 0 as *mut srtp_ctx_t;
    let mut pkt: *mut srtp_hdr_t = 0 as *mut srtp_hdr_t;
    let mut i: uint32_t = 0;
    let mut roc: uint32_t = 0;
    let mut ts: uint32_t = 0;
    let mut seq: uint16_t = 0;
    let mut msg_len_octets: libc::c_int = 32 as libc::c_int;
    let mut protected_msg_len_octets: libc::c_int = 0;
    memset(
        &mut policy as *mut srtp_policy_t as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<srtp_policy_t>() as libc::c_ulong,
    );
    srtp_crypto_policy_set_rtp_default(&mut policy.rtp);
    srtp_crypto_policy_set_rtcp_default(&mut policy.rtcp);
    policy.ssrc.type_0 = ssrc_specific;
    policy.ssrc.value = 0xcafebabe as libc::c_uint;
    policy.key = test_key.as_mut_ptr();
    policy.window_size = 128 as libc::c_int as libc::c_ulong;
    status = srtp_create(&mut session, &mut policy);
    if status as u64 != 0 {
        return status;
    }
    seq = 65535 as libc::c_int as uint16_t;
    ts = 0 as libc::c_int as uint32_t;
    i = 0 as libc::c_int as uint32_t;
    while i < 2 as libc::c_int as libc::c_uint {
        pkt = srtp_create_test_packet_extended(
            msg_len_octets,
            policy.ssrc.value,
            seq,
            ts,
            &mut protected_msg_len_octets,
        );
        status = srtp_protect(
            session,
            pkt as *mut libc::c_void,
            &mut protected_msg_len_octets,
        );
        free(pkt as *mut libc::c_void);
        if status as u64 != 0 {
            return status;
        }
        status = srtp_get_stream_roc(session, policy.ssrc.value, &mut roc);
        if status as u64 != 0 {
            return status;
        }
        if roc != i {
            return srtp_err_status_fail;
        }
        seq = seq.wrapping_add(1);
        ts = ts.wrapping_add(1);
        i = i.wrapping_add(1);
    }
    status = srtp_dealloc(session);
    if status as u64 != 0 {
        return status;
    }
    return srtp_err_status_ok;
}
unsafe extern "C" fn test_set_receiver_roc(
    mut packets: uint32_t,
    mut roc_to_set: uint32_t,
) -> srtp_err_status_t {
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut sender_policy: srtp_policy_t = srtp_policy_t {
        ssrc: srtp_ssrc_t {
            type_0: ssrc_undefined,
            value: 0,
        },
        rtp: srtp_crypto_policy_t {
            cipher_type: 0,
            cipher_key_len: 0,
            auth_type: 0,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: sec_serv_none,
        },
        rtcp: srtp_crypto_policy_t {
            cipher_type: 0,
            cipher_key_len: 0,
            auth_type: 0,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: sec_serv_none,
        },
        key: 0 as *mut libc::c_uchar,
        keys: 0 as *mut *mut srtp_master_key_t,
        num_master_keys: 0,
        deprecated_ekt: 0 as *mut libc::c_void,
        window_size: 0,
        allow_repeat_tx: 0,
        enc_xtn_hdr: 0 as *mut libc::c_int,
        enc_xtn_hdr_count: 0,
        next: 0 as *mut srtp_policy_t,
    };
    let mut sender_session: srtp_t = 0 as *mut srtp_ctx_t;
    let mut receiver_policy: srtp_policy_t = srtp_policy_t {
        ssrc: srtp_ssrc_t {
            type_0: ssrc_undefined,
            value: 0,
        },
        rtp: srtp_crypto_policy_t {
            cipher_type: 0,
            cipher_key_len: 0,
            auth_type: 0,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: sec_serv_none,
        },
        rtcp: srtp_crypto_policy_t {
            cipher_type: 0,
            cipher_key_len: 0,
            auth_type: 0,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: sec_serv_none,
        },
        key: 0 as *mut libc::c_uchar,
        keys: 0 as *mut *mut srtp_master_key_t,
        num_master_keys: 0,
        deprecated_ekt: 0 as *mut libc::c_void,
        window_size: 0,
        allow_repeat_tx: 0,
        enc_xtn_hdr: 0 as *mut libc::c_int,
        enc_xtn_hdr_count: 0,
        next: 0 as *mut srtp_policy_t,
    };
    let mut receiver_session: srtp_t = 0 as *mut srtp_ctx_t;
    let mut pkt_1: *mut srtp_hdr_t = 0 as *mut srtp_hdr_t;
    let mut recv_pkt_1: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut pkt_2: *mut srtp_hdr_t = 0 as *mut srtp_hdr_t;
    let mut recv_pkt_2: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut i: uint32_t = 0;
    let mut ts: uint32_t = 0;
    let mut seq: uint16_t = 0;
    let mut stride: uint16_t = 0;
    let mut msg_len_octets: libc::c_int = 32 as libc::c_int;
    let mut protected_msg_len_octets_1: libc::c_int = 0;
    let mut protected_msg_len_octets_2: libc::c_int = 0;
    memset(
        &mut sender_policy as *mut srtp_policy_t as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<srtp_policy_t>() as libc::c_ulong,
    );
    srtp_crypto_policy_set_rtp_default(&mut sender_policy.rtp);
    srtp_crypto_policy_set_rtcp_default(&mut sender_policy.rtcp);
    sender_policy.key = test_key.as_mut_ptr();
    sender_policy.ssrc.type_0 = ssrc_specific;
    sender_policy.ssrc.value = 0xcafebabe as libc::c_uint;
    sender_policy.window_size = 128 as libc::c_int as libc::c_ulong;
    status = srtp_create(&mut sender_session, &mut sender_policy);
    if status as u64 != 0 {
        return status;
    }
    i = 0 as libc::c_int as uint32_t;
    seq = 0 as libc::c_int as uint16_t;
    ts = 0 as libc::c_int as uint32_t;
    stride = 0x4000 as libc::c_int as uint16_t;
    while i < packets {
        let mut tmp_pkt: *mut srtp_hdr_t = 0 as *mut srtp_hdr_t;
        let mut tmp_len: libc::c_int = 0;
        tmp_pkt = srtp_create_test_packet_extended(
            msg_len_octets,
            sender_policy.ssrc.value,
            seq,
            ts,
            &mut tmp_len,
        );
        status = srtp_protect(
            sender_session,
            tmp_pkt as *mut libc::c_void,
            &mut tmp_len,
        );
        free(tmp_pkt as *mut libc::c_void);
        if status as u64 != 0 {
            return status;
        }
        while stride as libc::c_uint > packets.wrapping_sub(i)
            && stride as libc::c_int > 1 as libc::c_int
        {
            stride = (stride as libc::c_int >> 1 as libc::c_int) as uint16_t;
        }
        i = (i as libc::c_uint).wrapping_add(stride as libc::c_uint) as uint32_t
            as uint32_t;
        seq = (seq as libc::c_int + stride as libc::c_int) as uint16_t;
        ts = ts.wrapping_add(1);
    }
    pkt_1 = srtp_create_test_packet_extended(
        msg_len_octets,
        sender_policy.ssrc.value,
        seq,
        ts,
        &mut protected_msg_len_octets_1,
    );
    status = srtp_protect(
        sender_session,
        pkt_1 as *mut libc::c_void,
        &mut protected_msg_len_octets_1,
    );
    if status as u64 != 0 {
        return status;
    }
    seq = seq.wrapping_add(1);
    ts = ts.wrapping_add(1);
    pkt_2 = srtp_create_test_packet_extended(
        msg_len_octets,
        sender_policy.ssrc.value,
        seq,
        ts,
        &mut protected_msg_len_octets_2,
    );
    status = srtp_protect(
        sender_session,
        pkt_2 as *mut libc::c_void,
        &mut protected_msg_len_octets_2,
    );
    if status as u64 != 0 {
        return status;
    }
    memset(
        &mut receiver_policy as *mut srtp_policy_t as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<srtp_policy_t>() as libc::c_ulong,
    );
    srtp_crypto_policy_set_rtp_default(&mut receiver_policy.rtp);
    srtp_crypto_policy_set_rtcp_default(&mut receiver_policy.rtcp);
    receiver_policy.key = test_key.as_mut_ptr();
    receiver_policy.ssrc.type_0 = ssrc_specific;
    receiver_policy.ssrc.value = sender_policy.ssrc.value;
    receiver_policy.window_size = 128 as libc::c_int as libc::c_ulong;
    status = srtp_create(&mut receiver_session, &mut receiver_policy);
    if status as u64 != 0 {
        return status;
    }
    recv_pkt_1 = malloc(protected_msg_len_octets_1 as libc::c_ulong)
        as *mut libc::c_uchar;
    if recv_pkt_1.is_null() {
        return srtp_err_status_fail;
    }
    memcpy(
        recv_pkt_1 as *mut libc::c_void,
        pkt_1 as *const libc::c_void,
        protected_msg_len_octets_1 as libc::c_ulong,
    );
    recv_pkt_2 = malloc(protected_msg_len_octets_2 as libc::c_ulong)
        as *mut libc::c_uchar;
    if recv_pkt_2.is_null() {
        return srtp_err_status_fail;
    }
    memcpy(
        recv_pkt_2 as *mut libc::c_void,
        pkt_2 as *const libc::c_void,
        protected_msg_len_octets_2 as libc::c_ulong,
    );
    status = srtp_set_stream_roc(
        receiver_session,
        receiver_policy.ssrc.value,
        roc_to_set,
    );
    if status as u64 != 0 {
        return status;
    }
    status = srtp_unprotect(
        receiver_session,
        recv_pkt_1 as *mut libc::c_void,
        &mut protected_msg_len_octets_1,
    );
    if status as u64 != 0 {
        return status;
    }
    status = srtp_unprotect(
        receiver_session,
        recv_pkt_2 as *mut libc::c_void,
        &mut protected_msg_len_octets_2,
    );
    if status as u64 != 0 {
        return status;
    }
    status = srtp_dealloc(sender_session);
    if status as u64 != 0 {
        return status;
    }
    status = srtp_dealloc(receiver_session);
    if status as u64 != 0 {
        return status;
    }
    free(pkt_1 as *mut libc::c_void);
    free(recv_pkt_1 as *mut libc::c_void);
    free(pkt_2 as *mut libc::c_void);
    free(recv_pkt_2 as *mut libc::c_void);
    return srtp_err_status_ok;
}
unsafe extern "C" fn test_set_sender_roc(
    mut seq: uint16_t,
    mut roc_to_set: uint32_t,
) -> srtp_err_status_t {
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut sender_policy: srtp_policy_t = srtp_policy_t {
        ssrc: srtp_ssrc_t {
            type_0: ssrc_undefined,
            value: 0,
        },
        rtp: srtp_crypto_policy_t {
            cipher_type: 0,
            cipher_key_len: 0,
            auth_type: 0,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: sec_serv_none,
        },
        rtcp: srtp_crypto_policy_t {
            cipher_type: 0,
            cipher_key_len: 0,
            auth_type: 0,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: sec_serv_none,
        },
        key: 0 as *mut libc::c_uchar,
        keys: 0 as *mut *mut srtp_master_key_t,
        num_master_keys: 0,
        deprecated_ekt: 0 as *mut libc::c_void,
        window_size: 0,
        allow_repeat_tx: 0,
        enc_xtn_hdr: 0 as *mut libc::c_int,
        enc_xtn_hdr_count: 0,
        next: 0 as *mut srtp_policy_t,
    };
    let mut sender_session: srtp_t = 0 as *mut srtp_ctx_t;
    let mut receiver_policy: srtp_policy_t = srtp_policy_t {
        ssrc: srtp_ssrc_t {
            type_0: ssrc_undefined,
            value: 0,
        },
        rtp: srtp_crypto_policy_t {
            cipher_type: 0,
            cipher_key_len: 0,
            auth_type: 0,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: sec_serv_none,
        },
        rtcp: srtp_crypto_policy_t {
            cipher_type: 0,
            cipher_key_len: 0,
            auth_type: 0,
            auth_key_len: 0,
            auth_tag_len: 0,
            sec_serv: sec_serv_none,
        },
        key: 0 as *mut libc::c_uchar,
        keys: 0 as *mut *mut srtp_master_key_t,
        num_master_keys: 0,
        deprecated_ekt: 0 as *mut libc::c_void,
        window_size: 0,
        allow_repeat_tx: 0,
        enc_xtn_hdr: 0 as *mut libc::c_int,
        enc_xtn_hdr_count: 0,
        next: 0 as *mut srtp_policy_t,
    };
    let mut receiver_session: srtp_t = 0 as *mut srtp_ctx_t;
    let mut pkt: *mut srtp_hdr_t = 0 as *mut srtp_hdr_t;
    let mut recv_pkt: *mut libc::c_uchar = 0 as *mut libc::c_uchar;
    let mut ts: uint32_t = 0;
    let mut msg_len_octets: libc::c_int = 32 as libc::c_int;
    let mut protected_msg_len_octets: libc::c_int = 0;
    memset(
        &mut sender_policy as *mut srtp_policy_t as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<srtp_policy_t>() as libc::c_ulong,
    );
    srtp_crypto_policy_set_rtp_default(&mut sender_policy.rtp);
    srtp_crypto_policy_set_rtcp_default(&mut sender_policy.rtcp);
    sender_policy.key = test_key.as_mut_ptr();
    sender_policy.ssrc.type_0 = ssrc_specific;
    sender_policy.ssrc.value = 0xcafebabe as libc::c_uint;
    sender_policy.window_size = 128 as libc::c_int as libc::c_ulong;
    status = srtp_create(&mut sender_session, &mut sender_policy);
    if status as u64 != 0 {
        return status;
    }
    status = srtp_set_stream_roc(sender_session, sender_policy.ssrc.value, roc_to_set);
    if status as libc::c_uint != srtp_err_status_ok as libc::c_int as libc::c_uint {
        return status;
    }
    ts = 0 as libc::c_int as uint32_t;
    pkt = srtp_create_test_packet_extended(
        msg_len_octets,
        sender_policy.ssrc.value,
        seq,
        ts,
        &mut protected_msg_len_octets,
    );
    status = srtp_protect(
        sender_session,
        pkt as *mut libc::c_void,
        &mut protected_msg_len_octets,
    );
    if status as u64 != 0 {
        return status;
    }
    memset(
        &mut receiver_policy as *mut srtp_policy_t as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<srtp_policy_t>() as libc::c_ulong,
    );
    srtp_crypto_policy_set_rtp_default(&mut receiver_policy.rtp);
    srtp_crypto_policy_set_rtcp_default(&mut receiver_policy.rtcp);
    receiver_policy.key = test_key.as_mut_ptr();
    receiver_policy.ssrc.type_0 = ssrc_specific;
    receiver_policy.ssrc.value = sender_policy.ssrc.value;
    receiver_policy.window_size = 128 as libc::c_int as libc::c_ulong;
    status = srtp_create(&mut receiver_session, &mut receiver_policy);
    if status as u64 != 0 {
        return status;
    }
    recv_pkt = malloc(protected_msg_len_octets as libc::c_ulong) as *mut libc::c_uchar;
    if recv_pkt.is_null() {
        return srtp_err_status_fail;
    }
    memcpy(
        recv_pkt as *mut libc::c_void,
        pkt as *const libc::c_void,
        protected_msg_len_octets as libc::c_ulong,
    );
    status = srtp_set_stream_roc(
        receiver_session,
        receiver_policy.ssrc.value,
        roc_to_set,
    );
    if status as u64 != 0 {
        return status;
    }
    status = srtp_unprotect(
        receiver_session,
        recv_pkt as *mut libc::c_void,
        &mut protected_msg_len_octets,
    );
    if status as u64 != 0 {
        return status;
    }
    status = srtp_dealloc(sender_session);
    if status as u64 != 0 {
        return status;
    }
    status = srtp_dealloc(receiver_session);
    if status as u64 != 0 {
        return status;
    }
    free(pkt as *mut libc::c_void);
    free(recv_pkt as *mut libc::c_void);
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_test_set_receiver_roc() -> srtp_err_status_t {
    let mut packets: libc::c_int = 0;
    let mut roc: uint32_t = 0;
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    packets = 1 as libc::c_int;
    roc = 0 as libc::c_int as uint32_t;
    status = test_set_receiver_roc((packets - 1 as libc::c_int) as uint32_t, roc);
    if status as u64 != 0 {
        return status;
    }
    status = test_set_receiver_roc(packets as uint32_t, roc);
    if status as u64 != 0 {
        return status;
    }
    status = test_set_receiver_roc((packets + 1 as libc::c_int) as uint32_t, roc);
    if status as u64 != 0 {
        return status;
    }
    status = test_set_receiver_roc((packets + 60000 as libc::c_int) as uint32_t, roc);
    if status as u64 != 0 {
        return status;
    }
    packets = 65535 as libc::c_int;
    roc = 0 as libc::c_int as uint32_t;
    status = test_set_receiver_roc((packets - 1 as libc::c_int) as uint32_t, roc);
    if status as u64 != 0 {
        return status;
    }
    status = test_set_receiver_roc(packets as uint32_t, roc);
    if status as u64 != 0 {
        return status;
    }
    roc = 1 as libc::c_int as uint32_t;
    status = test_set_receiver_roc((packets + 1 as libc::c_int) as uint32_t, roc);
    if status as u64 != 0 {
        return status;
    }
    status = test_set_receiver_roc((packets + 60000 as libc::c_int) as uint32_t, roc);
    if status as u64 != 0 {
        return status;
    }
    status = test_set_receiver_roc((packets + 65535 as libc::c_int) as uint32_t, roc);
    if status as u64 != 0 {
        return status;
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_test_set_sender_roc() -> srtp_err_status_t {
    let mut roc: uint32_t = 0;
    let mut seq: uint16_t = 0;
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    seq = 43210 as libc::c_int as uint16_t;
    roc = 0 as libc::c_int as uint32_t;
    status = test_set_sender_roc(seq, roc);
    if status as u64 != 0 {
        return status;
    }
    roc = 65535 as libc::c_int as uint32_t;
    status = test_set_sender_roc(seq, roc);
    if status as u64 != 0 {
        return status;
    }
    roc = 0xffff as libc::c_int as uint32_t;
    status = test_set_sender_roc(seq, roc);
    if status as u64 != 0 {
        return status;
    }
    roc = 0xffff00 as libc::c_int as uint32_t;
    status = test_set_sender_roc(seq, roc);
    if status as u64 != 0 {
        return status;
    }
    roc = 0xfffffff0 as libc::c_uint;
    status = test_set_sender_roc(seq, roc);
    if status as u64 != 0 {
        return status;
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub static mut test_key: [libc::c_uchar; 46] = [
    0xe1 as libc::c_int as libc::c_uchar,
    0xf9 as libc::c_int as libc::c_uchar,
    0x7a as libc::c_int as libc::c_uchar,
    0xd as libc::c_int as libc::c_uchar,
    0x3e as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x8b as libc::c_int as libc::c_uchar,
    0xe0 as libc::c_int as libc::c_uchar,
    0xd6 as libc::c_int as libc::c_uchar,
    0x4f as libc::c_int as libc::c_uchar,
    0xa3 as libc::c_int as libc::c_uchar,
    0x2c as libc::c_int as libc::c_uchar,
    0x6 as libc::c_int as libc::c_uchar,
    0xde as libc::c_int as libc::c_uchar,
    0x41 as libc::c_int as libc::c_uchar,
    0x39 as libc::c_int as libc::c_uchar,
    0xe as libc::c_int as libc::c_uchar,
    0xc6 as libc::c_int as libc::c_uchar,
    0x75 as libc::c_int as libc::c_uchar,
    0xad as libc::c_int as libc::c_uchar,
    0x49 as libc::c_int as libc::c_uchar,
    0x8a as libc::c_int as libc::c_uchar,
    0xfe as libc::c_int as libc::c_uchar,
    0xeb as libc::c_int as libc::c_uchar,
    0xb6 as libc::c_int as libc::c_uchar,
    0x96 as libc::c_int as libc::c_uchar,
    0xb as libc::c_int as libc::c_uchar,
    0x3a as libc::c_int as libc::c_uchar,
    0xab as libc::c_int as libc::c_uchar,
    0xe6 as libc::c_int as libc::c_uchar,
    0xc1 as libc::c_int as libc::c_uchar,
    0x73 as libc::c_int as libc::c_uchar,
    0xc3 as libc::c_int as libc::c_uchar,
    0x17 as libc::c_int as libc::c_uchar,
    0xf2 as libc::c_int as libc::c_uchar,
    0xda as libc::c_int as libc::c_uchar,
    0xbe as libc::c_int as libc::c_uchar,
    0x35 as libc::c_int as libc::c_uchar,
    0x77 as libc::c_int as libc::c_uchar,
    0x93 as libc::c_int as libc::c_uchar,
    0xb6 as libc::c_int as libc::c_uchar,
    0x96 as libc::c_int as libc::c_uchar,
    0xb as libc::c_int as libc::c_uchar,
    0x3a as libc::c_int as libc::c_uchar,
    0xab as libc::c_int as libc::c_uchar,
    0xe6 as libc::c_int as libc::c_uchar,
];
#[no_mangle]
pub static mut test_key_2: [libc::c_uchar; 46] = [
    0xf0 as libc::c_int as libc::c_uchar,
    0xf0 as libc::c_int as libc::c_uchar,
    0x49 as libc::c_int as libc::c_uchar,
    0x14 as libc::c_int as libc::c_uchar,
    0xb5 as libc::c_int as libc::c_uchar,
    0x13 as libc::c_int as libc::c_uchar,
    0xf2 as libc::c_int as libc::c_uchar,
    0x76 as libc::c_int as libc::c_uchar,
    0x3a as libc::c_int as libc::c_uchar,
    0x1b as libc::c_int as libc::c_uchar,
    0x1f as libc::c_int as libc::c_uchar,
    0xa1 as libc::c_int as libc::c_uchar,
    0x30 as libc::c_int as libc::c_uchar,
    0xf1 as libc::c_int as libc::c_uchar,
    0xe as libc::c_int as libc::c_uchar,
    0x29 as libc::c_int as libc::c_uchar,
    0x98 as libc::c_int as libc::c_uchar,
    0xf6 as libc::c_int as libc::c_uchar,
    0xf6 as libc::c_int as libc::c_uchar,
    0xe4 as libc::c_int as libc::c_uchar,
    0x3e as libc::c_int as libc::c_uchar,
    0x43 as libc::c_int as libc::c_uchar,
    0x9 as libc::c_int as libc::c_uchar,
    0xd1 as libc::c_int as libc::c_uchar,
    0xe6 as libc::c_int as libc::c_uchar,
    0x22 as libc::c_int as libc::c_uchar,
    0xa0 as libc::c_int as libc::c_uchar,
    0xe3 as libc::c_int as libc::c_uchar,
    0x32 as libc::c_int as libc::c_uchar,
    0xb9 as libc::c_int as libc::c_uchar,
    0xf1 as libc::c_int as libc::c_uchar,
    0xb6 as libc::c_int as libc::c_uchar,
    0xc3 as libc::c_int as libc::c_uchar,
    0x17 as libc::c_int as libc::c_uchar,
    0xf2 as libc::c_int as libc::c_uchar,
    0xda as libc::c_int as libc::c_uchar,
    0xbe as libc::c_int as libc::c_uchar,
    0x35 as libc::c_int as libc::c_uchar,
    0x77 as libc::c_int as libc::c_uchar,
    0x93 as libc::c_int as libc::c_uchar,
    0xb6 as libc::c_int as libc::c_uchar,
    0x96 as libc::c_int as libc::c_uchar,
    0xb as libc::c_int as libc::c_uchar,
    0x3a as libc::c_int as libc::c_uchar,
    0xab as libc::c_int as libc::c_uchar,
    0xe6 as libc::c_int as libc::c_uchar,
];
#[no_mangle]
pub static mut test_key_gcm: [libc::c_uchar; 28] = [
    0 as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x2 as libc::c_int as libc::c_uchar,
    0x3 as libc::c_int as libc::c_uchar,
    0x4 as libc::c_int as libc::c_uchar,
    0x5 as libc::c_int as libc::c_uchar,
    0x6 as libc::c_int as libc::c_uchar,
    0x7 as libc::c_int as libc::c_uchar,
    0x8 as libc::c_int as libc::c_uchar,
    0x9 as libc::c_int as libc::c_uchar,
    0xa as libc::c_int as libc::c_uchar,
    0xb as libc::c_int as libc::c_uchar,
    0xc as libc::c_int as libc::c_uchar,
    0xd as libc::c_int as libc::c_uchar,
    0xe as libc::c_int as libc::c_uchar,
    0xf as libc::c_int as libc::c_uchar,
    0xa0 as libc::c_int as libc::c_uchar,
    0xa1 as libc::c_int as libc::c_uchar,
    0xa2 as libc::c_int as libc::c_uchar,
    0xa3 as libc::c_int as libc::c_uchar,
    0xa4 as libc::c_int as libc::c_uchar,
    0xa5 as libc::c_int as libc::c_uchar,
    0xa6 as libc::c_int as libc::c_uchar,
    0xa7 as libc::c_int as libc::c_uchar,
    0xa8 as libc::c_int as libc::c_uchar,
    0xa9 as libc::c_int as libc::c_uchar,
    0xaa as libc::c_int as libc::c_uchar,
    0xab as libc::c_int as libc::c_uchar,
];
#[no_mangle]
pub static mut test_mki_id: [libc::c_uchar; 4] = [
    0xe1 as libc::c_int as libc::c_uchar,
    0xf9 as libc::c_int as libc::c_uchar,
    0x7a as libc::c_int as libc::c_uchar,
    0xd as libc::c_int as libc::c_uchar,
];
#[no_mangle]
pub static mut test_mki_id_2: [libc::c_uchar; 4] = [
    0xf3 as libc::c_int as libc::c_uchar,
    0xa1 as libc::c_int as libc::c_uchar,
    0x46 as libc::c_int as libc::c_uchar,
    0x71 as libc::c_int as libc::c_uchar,
];
#[no_mangle]
pub static mut default_policy: srtp_policy_t = unsafe {
    {
        let mut init = srtp_policy_t {
            ssrc: {
                let mut init = srtp_ssrc_t {
                    type_0: ssrc_any_outbound,
                    value: 0 as libc::c_int as libc::c_uint,
                };
                init
            },
            rtp: {
                let mut init = srtp_crypto_policy_t {
                    cipher_type: 1 as libc::c_int as srtp_cipher_type_id_t,
                    cipher_key_len: 14 as libc::c_int + 16 as libc::c_int,
                    auth_type: 3 as libc::c_int as srtp_auth_type_id_t,
                    auth_key_len: 16 as libc::c_int,
                    auth_tag_len: 10 as libc::c_int,
                    sec_serv: sec_serv_conf_and_auth,
                };
                init
            },
            rtcp: {
                let mut init = srtp_crypto_policy_t {
                    cipher_type: 1 as libc::c_int as srtp_cipher_type_id_t,
                    cipher_key_len: 14 as libc::c_int + 16 as libc::c_int,
                    auth_type: 3 as libc::c_int as srtp_auth_type_id_t,
                    auth_key_len: 16 as libc::c_int,
                    auth_tag_len: 10 as libc::c_int,
                    sec_serv: sec_serv_conf_and_auth,
                };
                init
            },
            key: 0 as *const libc::c_uchar as *mut libc::c_uchar,
            keys: test_keys.as_ptr() as *mut _,
            num_master_keys: 2 as libc::c_int as libc::c_ulong,
            deprecated_ekt: 0 as *const libc::c_void as *mut libc::c_void,
            window_size: 128 as libc::c_int as libc::c_ulong,
            allow_repeat_tx: 0 as libc::c_int,
            enc_xtn_hdr: 0 as *const libc::c_int as *mut libc::c_int,
            enc_xtn_hdr_count: 0 as libc::c_int,
            next: 0 as *const srtp_policy_t as *mut srtp_policy_t,
        };
        init
    }
};
#[no_mangle]
pub static mut aes_only_policy: srtp_policy_t = unsafe {
    {
        let mut init = srtp_policy_t {
            ssrc: {
                let mut init = srtp_ssrc_t {
                    type_0: ssrc_any_outbound,
                    value: 0 as libc::c_int as libc::c_uint,
                };
                init
            },
            rtp: {
                let mut init = srtp_crypto_policy_t {
                    cipher_type: 1 as libc::c_int as srtp_cipher_type_id_t,
                    cipher_key_len: 14 as libc::c_int + 16 as libc::c_int,
                    auth_type: 0 as libc::c_int as srtp_auth_type_id_t,
                    auth_key_len: 0 as libc::c_int,
                    auth_tag_len: 0 as libc::c_int,
                    sec_serv: sec_serv_conf,
                };
                init
            },
            rtcp: {
                let mut init = srtp_crypto_policy_t {
                    cipher_type: 1 as libc::c_int as srtp_cipher_type_id_t,
                    cipher_key_len: 14 as libc::c_int + 16 as libc::c_int,
                    auth_type: 0 as libc::c_int as srtp_auth_type_id_t,
                    auth_key_len: 0 as libc::c_int,
                    auth_tag_len: 0 as libc::c_int,
                    sec_serv: sec_serv_conf,
                };
                init
            },
            key: 0 as *const libc::c_uchar as *mut libc::c_uchar,
            keys: test_keys.as_ptr() as *mut _,
            num_master_keys: 2 as libc::c_int as libc::c_ulong,
            deprecated_ekt: 0 as *const libc::c_void as *mut libc::c_void,
            window_size: 128 as libc::c_int as libc::c_ulong,
            allow_repeat_tx: 0 as libc::c_int,
            enc_xtn_hdr: 0 as *const libc::c_int as *mut libc::c_int,
            enc_xtn_hdr_count: 0 as libc::c_int,
            next: 0 as *const srtp_policy_t as *mut srtp_policy_t,
        };
        init
    }
};
#[no_mangle]
pub static mut hmac_only_policy: srtp_policy_t = unsafe {
    {
        let mut init = srtp_policy_t {
            ssrc: {
                let mut init = srtp_ssrc_t {
                    type_0: ssrc_any_outbound,
                    value: 0 as libc::c_int as libc::c_uint,
                };
                init
            },
            rtp: {
                let mut init = srtp_crypto_policy_t {
                    cipher_type: 0 as libc::c_int as srtp_cipher_type_id_t,
                    cipher_key_len: 14 as libc::c_int + 16 as libc::c_int,
                    auth_type: 3 as libc::c_int as srtp_auth_type_id_t,
                    auth_key_len: 20 as libc::c_int,
                    auth_tag_len: 4 as libc::c_int,
                    sec_serv: sec_serv_auth,
                };
                init
            },
            rtcp: {
                let mut init = srtp_crypto_policy_t {
                    cipher_type: 0 as libc::c_int as srtp_cipher_type_id_t,
                    cipher_key_len: 14 as libc::c_int + 16 as libc::c_int,
                    auth_type: 3 as libc::c_int as srtp_auth_type_id_t,
                    auth_key_len: 20 as libc::c_int,
                    auth_tag_len: 4 as libc::c_int,
                    sec_serv: sec_serv_auth,
                };
                init
            },
            key: 0 as *const libc::c_uchar as *mut libc::c_uchar,
            keys: test_keys.as_ptr() as *mut _,
            num_master_keys: 2 as libc::c_int as libc::c_ulong,
            deprecated_ekt: 0 as *const libc::c_void as *mut libc::c_void,
            window_size: 128 as libc::c_int as libc::c_ulong,
            allow_repeat_tx: 0 as libc::c_int,
            enc_xtn_hdr: 0 as *const libc::c_int as *mut libc::c_int,
            enc_xtn_hdr_count: 0 as libc::c_int,
            next: 0 as *const srtp_policy_t as *mut srtp_policy_t,
        };
        init
    }
};
#[no_mangle]
pub static mut null_policy: srtp_policy_t = unsafe {
    {
        let mut init = srtp_policy_t {
            ssrc: {
                let mut init = srtp_ssrc_t {
                    type_0: ssrc_any_outbound,
                    value: 0 as libc::c_int as libc::c_uint,
                };
                init
            },
            rtp: {
                let mut init = srtp_crypto_policy_t {
                    cipher_type: 0 as libc::c_int as srtp_cipher_type_id_t,
                    cipher_key_len: 12 as libc::c_int + 32 as libc::c_int,
                    auth_type: 0 as libc::c_int as srtp_auth_type_id_t,
                    auth_key_len: 0 as libc::c_int,
                    auth_tag_len: 0 as libc::c_int,
                    sec_serv: sec_serv_none,
                };
                init
            },
            rtcp: {
                let mut init = srtp_crypto_policy_t {
                    cipher_type: 0 as libc::c_int as srtp_cipher_type_id_t,
                    cipher_key_len: 12 as libc::c_int + 32 as libc::c_int,
                    auth_type: 0 as libc::c_int as srtp_auth_type_id_t,
                    auth_key_len: 0 as libc::c_int,
                    auth_tag_len: 0 as libc::c_int,
                    sec_serv: sec_serv_none,
                };
                init
            },
            key: 0 as *const libc::c_uchar as *mut libc::c_uchar,
            keys: test_keys.as_ptr() as *mut _,
            num_master_keys: 2 as libc::c_int as libc::c_ulong,
            deprecated_ekt: 0 as *const libc::c_void as *mut libc::c_void,
            window_size: 128 as libc::c_int as libc::c_ulong,
            allow_repeat_tx: 0 as libc::c_int,
            enc_xtn_hdr: 0 as *const libc::c_int as *mut libc::c_int,
            enc_xtn_hdr_count: 0 as libc::c_int,
            next: 0 as *const srtp_policy_t as *mut srtp_policy_t,
        };
        init
    }
};
#[no_mangle]
pub static mut test_256_key: [libc::c_uchar; 46] = [
    0xf0 as libc::c_int as libc::c_uchar,
    0xf0 as libc::c_int as libc::c_uchar,
    0x49 as libc::c_int as libc::c_uchar,
    0x14 as libc::c_int as libc::c_uchar,
    0xb5 as libc::c_int as libc::c_uchar,
    0x13 as libc::c_int as libc::c_uchar,
    0xf2 as libc::c_int as libc::c_uchar,
    0x76 as libc::c_int as libc::c_uchar,
    0x3a as libc::c_int as libc::c_uchar,
    0x1b as libc::c_int as libc::c_uchar,
    0x1f as libc::c_int as libc::c_uchar,
    0xa1 as libc::c_int as libc::c_uchar,
    0x30 as libc::c_int as libc::c_uchar,
    0xf1 as libc::c_int as libc::c_uchar,
    0xe as libc::c_int as libc::c_uchar,
    0x29 as libc::c_int as libc::c_uchar,
    0x98 as libc::c_int as libc::c_uchar,
    0xf6 as libc::c_int as libc::c_uchar,
    0xf6 as libc::c_int as libc::c_uchar,
    0xe4 as libc::c_int as libc::c_uchar,
    0x3e as libc::c_int as libc::c_uchar,
    0x43 as libc::c_int as libc::c_uchar,
    0x9 as libc::c_int as libc::c_uchar,
    0xd1 as libc::c_int as libc::c_uchar,
    0xe6 as libc::c_int as libc::c_uchar,
    0x22 as libc::c_int as libc::c_uchar,
    0xa0 as libc::c_int as libc::c_uchar,
    0xe3 as libc::c_int as libc::c_uchar,
    0x32 as libc::c_int as libc::c_uchar,
    0xb9 as libc::c_int as libc::c_uchar,
    0xf1 as libc::c_int as libc::c_uchar,
    0xb6 as libc::c_int as libc::c_uchar,
    0x3b as libc::c_int as libc::c_uchar,
    0x4 as libc::c_int as libc::c_uchar,
    0x80 as libc::c_int as libc::c_uchar,
    0x3d as libc::c_int as libc::c_uchar,
    0xe5 as libc::c_int as libc::c_uchar,
    0x1e as libc::c_int as libc::c_uchar,
    0xe7 as libc::c_int as libc::c_uchar,
    0xc9 as libc::c_int as libc::c_uchar,
    0x64 as libc::c_int as libc::c_uchar,
    0x23 as libc::c_int as libc::c_uchar,
    0xab as libc::c_int as libc::c_uchar,
    0x5b as libc::c_int as libc::c_uchar,
    0x78 as libc::c_int as libc::c_uchar,
    0xd2 as libc::c_int as libc::c_uchar,
];
#[no_mangle]
pub static mut test_256_key_2: [libc::c_uchar; 46] = [
    0xe1 as libc::c_int as libc::c_uchar,
    0xf9 as libc::c_int as libc::c_uchar,
    0x7a as libc::c_int as libc::c_uchar,
    0xd as libc::c_int as libc::c_uchar,
    0x3e as libc::c_int as libc::c_uchar,
    0x1 as libc::c_int as libc::c_uchar,
    0x8b as libc::c_int as libc::c_uchar,
    0xe0 as libc::c_int as libc::c_uchar,
    0xd6 as libc::c_int as libc::c_uchar,
    0x4f as libc::c_int as libc::c_uchar,
    0xa3 as libc::c_int as libc::c_uchar,
    0x2c as libc::c_int as libc::c_uchar,
    0x6 as libc::c_int as libc::c_uchar,
    0xde as libc::c_int as libc::c_uchar,
    0x41 as libc::c_int as libc::c_uchar,
    0x39 as libc::c_int as libc::c_uchar,
    0xe as libc::c_int as libc::c_uchar,
    0xc6 as libc::c_int as libc::c_uchar,
    0x75 as libc::c_int as libc::c_uchar,
    0xad as libc::c_int as libc::c_uchar,
    0x49 as libc::c_int as libc::c_uchar,
    0x8a as libc::c_int as libc::c_uchar,
    0xfe as libc::c_int as libc::c_uchar,
    0xeb as libc::c_int as libc::c_uchar,
    0xb6 as libc::c_int as libc::c_uchar,
    0x96 as libc::c_int as libc::c_uchar,
    0xb as libc::c_int as libc::c_uchar,
    0x3a as libc::c_int as libc::c_uchar,
    0xab as libc::c_int as libc::c_uchar,
    0xe6 as libc::c_int as libc::c_uchar,
    0xc1 as libc::c_int as libc::c_uchar,
    0x73 as libc::c_int as libc::c_uchar,
    0x3b as libc::c_int as libc::c_uchar,
    0x4 as libc::c_int as libc::c_uchar,
    0x80 as libc::c_int as libc::c_uchar,
    0x3d as libc::c_int as libc::c_uchar,
    0xe5 as libc::c_int as libc::c_uchar,
    0x1e as libc::c_int as libc::c_uchar,
    0xe7 as libc::c_int as libc::c_uchar,
    0xc9 as libc::c_int as libc::c_uchar,
    0x64 as libc::c_int as libc::c_uchar,
    0x23 as libc::c_int as libc::c_uchar,
    0xab as libc::c_int as libc::c_uchar,
    0x5b as libc::c_int as libc::c_uchar,
    0x78 as libc::c_int as libc::c_uchar,
    0xd2 as libc::c_int as libc::c_uchar,
];
#[no_mangle]
pub static mut master_256_key_1: srtp_master_key_t = unsafe {
    {
        let mut init = srtp_master_key_t {
            key: test_256_key.as_ptr() as *mut _,
            mki_id: test_mki_id.as_ptr() as *mut _,
            mki_size: 4 as libc::c_int as libc::c_uint,
        };
        init
    }
};
#[no_mangle]
pub static mut master_256_key_2: srtp_master_key_t = unsafe {
    {
        let mut init = srtp_master_key_t {
            key: test_256_key_2.as_ptr() as *mut _,
            mki_id: test_mki_id_2.as_ptr() as *mut _,
            mki_size: 4 as libc::c_int as libc::c_uint,
        };
        init
    }
};
#[no_mangle]
pub static mut test_256_keys: [*mut srtp_master_key_t; 2] = unsafe {
    [
        &master_key_1 as *const srtp_master_key_t as *mut srtp_master_key_t,
        &master_key_2 as *const srtp_master_key_t as *mut srtp_master_key_t,
    ]
};
#[no_mangle]
pub static mut aes_256_hmac_policy: srtp_policy_t = unsafe {
    {
        let mut init = srtp_policy_t {
            ssrc: {
                let mut init = srtp_ssrc_t {
                    type_0: ssrc_any_outbound,
                    value: 0 as libc::c_int as libc::c_uint,
                };
                init
            },
            rtp: {
                let mut init = srtp_crypto_policy_t {
                    cipher_type: 5 as libc::c_int as srtp_cipher_type_id_t,
                    cipher_key_len: 14 as libc::c_int + 32 as libc::c_int,
                    auth_type: 3 as libc::c_int as srtp_auth_type_id_t,
                    auth_key_len: 20 as libc::c_int,
                    auth_tag_len: 10 as libc::c_int,
                    sec_serv: sec_serv_conf_and_auth,
                };
                init
            },
            rtcp: {
                let mut init = srtp_crypto_policy_t {
                    cipher_type: 5 as libc::c_int as srtp_cipher_type_id_t,
                    cipher_key_len: 14 as libc::c_int + 32 as libc::c_int,
                    auth_type: 3 as libc::c_int as srtp_auth_type_id_t,
                    auth_key_len: 20 as libc::c_int,
                    auth_tag_len: 10 as libc::c_int,
                    sec_serv: sec_serv_conf_and_auth,
                };
                init
            },
            key: 0 as *const libc::c_uchar as *mut libc::c_uchar,
            keys: test_256_keys.as_ptr() as *mut _,
            num_master_keys: 2 as libc::c_int as libc::c_ulong,
            deprecated_ekt: 0 as *const libc::c_void as *mut libc::c_void,
            window_size: 128 as libc::c_int as libc::c_ulong,
            allow_repeat_tx: 0 as libc::c_int,
            enc_xtn_hdr: 0 as *const libc::c_int as *mut libc::c_int,
            enc_xtn_hdr_count: 0 as libc::c_int,
            next: 0 as *const srtp_policy_t as *mut srtp_policy_t,
        };
        init
    }
};
#[no_mangle]
pub static mut ekt_test_policy: libc::c_char = 'x' as i32 as libc::c_char;
#[no_mangle]
pub static mut hmac_only_with_ekt_policy: srtp_policy_t = unsafe {
    {
        let mut init = srtp_policy_t {
            ssrc: {
                let mut init = srtp_ssrc_t {
                    type_0: ssrc_any_outbound,
                    value: 0 as libc::c_int as libc::c_uint,
                };
                init
            },
            rtp: {
                let mut init = srtp_crypto_policy_t {
                    cipher_type: 0 as libc::c_int as srtp_cipher_type_id_t,
                    cipher_key_len: 0 as libc::c_int,
                    auth_type: 3 as libc::c_int as srtp_auth_type_id_t,
                    auth_key_len: 20 as libc::c_int,
                    auth_tag_len: 4 as libc::c_int,
                    sec_serv: sec_serv_auth,
                };
                init
            },
            rtcp: {
                let mut init = srtp_crypto_policy_t {
                    cipher_type: 0 as libc::c_int as srtp_cipher_type_id_t,
                    cipher_key_len: 0 as libc::c_int,
                    auth_type: 3 as libc::c_int as srtp_auth_type_id_t,
                    auth_key_len: 20 as libc::c_int,
                    auth_tag_len: 4 as libc::c_int,
                    sec_serv: sec_serv_auth,
                };
                init
            },
            key: 0 as *const libc::c_uchar as *mut libc::c_uchar,
            keys: test_keys.as_ptr() as *mut _,
            num_master_keys: 2 as libc::c_int as libc::c_ulong,
            deprecated_ekt: &ekt_test_policy as *const libc::c_char as *mut libc::c_char
                as *mut libc::c_void,
            window_size: 128 as libc::c_int as libc::c_ulong,
            allow_repeat_tx: 0 as libc::c_int,
            enc_xtn_hdr: 0 as *const libc::c_int as *mut libc::c_int,
            enc_xtn_hdr_count: 0 as libc::c_int,
            next: 0 as *const srtp_policy_t as *mut srtp_policy_t,
        };
        init
    }
};
#[no_mangle]
pub static mut policy_array: [*const srtp_policy_t; 6] = unsafe {
    [
        &hmac_only_policy as *const srtp_policy_t,
        &aes_only_policy as *const srtp_policy_t,
        &default_policy as *const srtp_policy_t,
        &null_policy as *const srtp_policy_t,
        &aes_256_hmac_policy as *const srtp_policy_t,
        0 as *const srtp_policy_t,
    ]
};
#[no_mangle]
pub static mut invalid_policy_array: [*const srtp_policy_t; 2] = unsafe {
    [&hmac_only_with_ekt_policy as *const srtp_policy_t, 0 as *const srtp_policy_t]
};
#[no_mangle]
pub static mut wildcard_policy: srtp_policy_t = unsafe {
    {
        let mut init = srtp_policy_t {
            ssrc: {
                let mut init = srtp_ssrc_t {
                    type_0: ssrc_any_outbound,
                    value: 0 as libc::c_int as libc::c_uint,
                };
                init
            },
            rtp: {
                let mut init = srtp_crypto_policy_t {
                    cipher_type: 1 as libc::c_int as srtp_cipher_type_id_t,
                    cipher_key_len: 14 as libc::c_int + 16 as libc::c_int,
                    auth_type: 3 as libc::c_int as srtp_auth_type_id_t,
                    auth_key_len: 16 as libc::c_int,
                    auth_tag_len: 10 as libc::c_int,
                    sec_serv: sec_serv_conf_and_auth,
                };
                init
            },
            rtcp: {
                let mut init = srtp_crypto_policy_t {
                    cipher_type: 1 as libc::c_int as srtp_cipher_type_id_t,
                    cipher_key_len: 14 as libc::c_int + 16 as libc::c_int,
                    auth_type: 3 as libc::c_int as srtp_auth_type_id_t,
                    auth_key_len: 16 as libc::c_int,
                    auth_tag_len: 10 as libc::c_int,
                    sec_serv: sec_serv_conf_and_auth,
                };
                init
            },
            key: test_key.as_ptr() as *mut _,
            keys: 0 as *const *mut srtp_master_key_t as *mut *mut srtp_master_key_t,
            num_master_keys: 0 as libc::c_int as libc::c_ulong,
            deprecated_ekt: 0 as *const libc::c_void as *mut libc::c_void,
            window_size: 128 as libc::c_int as libc::c_ulong,
            allow_repeat_tx: 0 as libc::c_int,
            enc_xtn_hdr: 0 as *const libc::c_int as *mut libc::c_int,
            enc_xtn_hdr_count: 0 as libc::c_int,
            next: 0 as *const srtp_policy_t as *mut srtp_policy_t,
        };
        init
    }
};
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
