#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
use c2rust_bitfields::BitfieldStruct;
use crypto::*;
extern "C" {
    fn srtp_crypto_kernel_load_debug_module(
        new_dm: *mut srtp_debug_module_t,
    ) -> srtp_err_status_t;
    fn srtp_crypto_kernel_init() -> srtp_err_status_t;
    fn srtp_crypto_kernel_shutdown() -> srtp_err_status_t;
    fn srtp_octet_string_hex_string(
        str: *const libc::c_void,
        length: libc::c_int,
    ) -> *mut libc::c_char;
    fn srtp_cipher_encrypt(
        c: *mut srtp_cipher_t,
        buffer: *mut uint8_t,
        num_octets_to_output: *mut uint32_t,
    ) -> srtp_err_status_t;
    fn srtp_cipher_output(
        c: *mut srtp_cipher_t,
        buffer: *mut uint8_t,
        num_octets_to_output: *mut uint32_t,
    ) -> srtp_err_status_t;
    fn srtp_auth_get_prefix_length(a: *const srtp_auth_t) -> libc::c_int;
    fn srtp_cipher_set_iv(
        c: *mut srtp_cipher_t,
        iv: *mut uint8_t,
        direction: libc::c_int,
    ) -> srtp_err_status_t;
    fn srtp_rdbx_add_index(
        rdbx: *mut srtp_rdbx_t,
        delta: libc::c_int,
    ) -> srtp_err_status_t;
    fn srtp_rdbx_check(
        rdbx: *const srtp_rdbx_t,
        difference: libc::c_int,
    ) -> srtp_err_status_t;
    fn srtp_rdbx_set_roc_seq(
        rdbx: *mut srtp_rdbx_t,
        roc: uint32_t,
        seq: uint16_t,
    ) -> srtp_err_status_t;
    fn srtp_rdbx_estimate_index(
        rdbx: *const srtp_rdbx_t,
        guess: *mut srtp_xtd_seq_num_t,
        s: srtp_sequence_number_t,
    ) -> int32_t;
    fn memcpy(
        _: *mut libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn srtp_auth_get_tag_length(a: *const srtp_auth_t) -> libc::c_int;
    fn srtp_key_limit_update(key: srtp_key_limit_t) -> srtp_key_event_t;
    fn srtp_cipher_get_tag(
        c: *mut srtp_cipher_t,
        buffer: *mut uint8_t,
        tag_len: *mut uint32_t,
    ) -> srtp_err_status_t;
    fn srtp_cipher_set_aad(
        c: *mut srtp_cipher_t,
        aad: *const uint8_t,
        aad_len: uint32_t,
    ) -> srtp_err_status_t;
    fn v128_hex_string(x: *mut v128_t) -> *mut libc::c_char;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn srtp_rdb_init(rdb: *mut srtp_rdb_t) -> srtp_err_status_t;
    fn srtp_crypto_free(ptr: *mut libc::c_void);
    fn srtp_rdbx_dealloc(rdbx: *mut srtp_rdbx_t) -> srtp_err_status_t;
    fn octet_string_set_to_zero(s: *mut libc::c_void, len: size_t);
    fn srtp_cipher_dealloc(c: *mut srtp_cipher_t) -> srtp_err_status_t;
    fn srtp_rdbx_get_window_size(rdbx: *const srtp_rdbx_t) -> libc::c_ulong;
    fn srtp_rdbx_init(rdbx: *mut srtp_rdbx_t, ws: libc::c_ulong) -> srtp_err_status_t;
    fn srtp_key_limit_clone(
        original: srtp_key_limit_t,
        new_key: *mut srtp_key_limit_t,
    ) -> srtp_err_status_t;
    fn srtp_crypto_alloc(size: size_t) -> *mut libc::c_void;
    fn srtp_cipher_decrypt(
        c: *mut srtp_cipher_t,
        buffer: *mut uint8_t,
        num_octets_to_output: *mut uint32_t,
    ) -> srtp_err_status_t;
    fn srtp_octet_string_is_eq(
        a: *mut uint8_t,
        b: *mut uint8_t,
        len: libc::c_int,
    ) -> libc::c_int;
    fn memcmp(
        _: *const libc::c_void,
        _: *const libc::c_void,
        _: libc::c_ulong,
    ) -> libc::c_int;
    fn srtp_auth_get_key_length(a: *const srtp_auth_t) -> libc::c_int;
    fn srtp_cipher_init(c: *mut srtp_cipher_t, key: *const uint8_t) -> srtp_err_status_t;
    fn srtp_crypto_kernel_alloc_cipher(
        id: srtp_cipher_type_id_t,
        cp: *mut srtp_cipher_pointer_t,
        key_len: libc::c_int,
        tag_len: libc::c_int,
    ) -> srtp_err_status_t;
    fn srtp_cipher_get_key_length(c: *const srtp_cipher_t) -> libc::c_int;
    fn srtp_key_limit_set(
        key: srtp_key_limit_t,
        s: srtp_xtd_seq_num_t,
    ) -> srtp_err_status_t;
    fn srtp_crypto_kernel_alloc_auth(
        id: srtp_auth_type_id_t,
        ap: *mut srtp_auth_pointer_t,
        key_len: libc::c_int,
        tag_len: libc::c_int,
    ) -> srtp_err_status_t;
    fn srtp_rdb_get_value(rdb: *const srtp_rdb_t) -> uint32_t;
    fn srtp_rdb_increment(rdb: *mut srtp_rdb_t) -> srtp_err_status_t;
    fn srtp_rdb_add_index(
        rdb: *mut srtp_rdb_t,
        rdb_index: uint32_t,
    ) -> srtp_err_status_t;
    fn srtp_rdb_check(rdb: *const srtp_rdb_t, rdb_index: uint32_t) -> srtp_err_status_t;
    fn sscanf(_: *const libc::c_char, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn srtp_crypto_kernel_set_debug_module(
        mod_name: *const libc::c_char,
        v: libc::c_int,
    ) -> srtp_err_status_t;
    fn srtp_crypto_kernel_list_debug_modules() -> srtp_err_status_t;
    fn srtp_install_err_report_handler(
        func: Option::<srtp_err_report_handler_func_t>,
    ) -> srtp_err_status_t;
    fn srtp_rdbx_get_roc(rdbx: *const srtp_rdbx_t) -> uint32_t;
}
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __int32_t = libc::c_int;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type int32_t = __int32_t;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct srtp_hdr_xtnd_t {
    pub profile_specific: uint16_t,
    pub length: uint16_t,
}
pub type srtp_stream_ctx_t = srtp_stream_ctx_t_;
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
pub type srtp_sequence_number_t = uint16_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct srtp_event_data_t {
    pub session: srtp_t,
    pub ssrc: uint32_t,
    pub event: srtp_event_t,
}
pub type srtp_event_t = libc::c_uint;
pub const event_packet_index_limit: srtp_event_t = 3;
pub const event_key_hard_limit: srtp_event_t = 2;
pub const event_key_soft_limit: srtp_event_t = 1;
pub const event_ssrc_collision: srtp_event_t = 0;
pub type srtp_event_handler_func_t = unsafe extern "C" fn(*mut srtp_event_data_t) -> ();
pub const srtp_key_event_hard_limit: srtp_key_event_t = 2;
pub const srtp_key_event_soft_limit: srtp_key_event_t = 1;
pub const srtp_key_event_normal: srtp_key_event_t = 0;
pub type srtp_key_event_t = libc::c_uint;
pub type srtp_key_limit_t = *mut srtp_key_limit_ctx_t;
pub type size_t = libc::c_ulong;
pub type srtp_stream_t = *mut srtp_stream_ctx_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct srtp_kdf_t {
    pub cipher: *mut srtp_cipher_t,
}
pub type srtp_prf_label = libc::c_uint;
pub const label_rtp_header_salt: srtp_prf_label = 7;
pub const label_rtp_header_encryption: srtp_prf_label = 6;
pub const label_rtcp_salt: srtp_prf_label = 5;
pub const label_rtcp_msg_auth: srtp_prf_label = 4;
pub const label_rtcp_encryption: srtp_prf_label = 3;
pub const label_rtp_salt: srtp_prf_label = 2;
pub const label_rtp_msg_auth: srtp_prf_label = 1;
pub const label_rtp_encryption: srtp_prf_label = 0;
pub type srtp_profile_t = libc::c_uint;
pub const srtp_profile_aead_aes_256_gcm: srtp_profile_t = 8;
pub const srtp_profile_aead_aes_128_gcm: srtp_profile_t = 7;
pub const srtp_profile_null_sha1_32: srtp_profile_t = 6;
pub const srtp_profile_null_sha1_80: srtp_profile_t = 5;
pub const srtp_profile_aes128_cm_sha1_32: srtp_profile_t = 2;
pub const srtp_profile_aes128_cm_sha1_80: srtp_profile_t = 1;
pub const srtp_profile_reserved: srtp_profile_t = 0;
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct srtcp_trailer_t {
    #[bitfield(name = "index", ty = "libc::c_uint", bits = "0..=30")]
    #[bitfield(name = "e", ty = "libc::c_uint", bits = "31..=31")]
    pub index_e: [u8; 4],
}
#[derive(Copy, Clone, BitfieldStruct)]
#[repr(C)]
pub struct srtcp_hdr_t {
    #[bitfield(name = "rc", ty = "libc::c_uchar", bits = "0..=4")]
    #[bitfield(name = "p", ty = "libc::c_uchar", bits = "5..=5")]
    #[bitfield(name = "version", ty = "libc::c_uchar", bits = "6..=7")]
    #[bitfield(name = "pt", ty = "libc::c_uchar", bits = "8..=15")]
    pub rc_p_version_pt: [u8; 2],
    pub len: uint16_t,
    pub ssrc: uint32_t,
}
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
pub type srtp_err_report_handler_func_t = unsafe extern "C" fn(
    srtp_err_reporting_level_t,
    *const libc::c_char,
) -> ();
#[inline]
unsafe extern "C" fn __bswap_16(mut __bsx: __uint16_t) -> __uint16_t {
    return (__bsx as libc::c_int >> 8 as libc::c_int & 0xff as libc::c_int
        | (__bsx as libc::c_int & 0xff as libc::c_int) << 8 as libc::c_int)
        as __uint16_t;
}
#[inline]
unsafe extern "C" fn __bswap_64(mut __bsx: __uint64_t) -> __uint64_t {
    return ((__bsx as libc::c_ulonglong & 0xff00000000000000 as libc::c_ulonglong)
        >> 56 as libc::c_int
        | (__bsx as libc::c_ulonglong & 0xff000000000000 as libc::c_ulonglong)
            >> 40 as libc::c_int
        | (__bsx as libc::c_ulonglong & 0xff0000000000 as libc::c_ulonglong)
            >> 24 as libc::c_int
        | (__bsx as libc::c_ulonglong & 0xff00000000 as libc::c_ulonglong)
            >> 8 as libc::c_int
        | (__bsx as libc::c_ulonglong & 0xff000000 as libc::c_ulonglong)
            << 8 as libc::c_int
        | (__bsx as libc::c_ulonglong & 0xff0000 as libc::c_ulonglong)
            << 24 as libc::c_int
        | (__bsx as libc::c_ulonglong & 0xff00 as libc::c_ulonglong) << 40 as libc::c_int
        | (__bsx as libc::c_ulonglong & 0xff as libc::c_ulonglong) << 56 as libc::c_int)
        as __uint64_t;
}
#[inline]
unsafe extern "C" fn __bswap_32(mut __bsx: __uint32_t) -> __uint32_t {
    return (__bsx & 0xff000000 as libc::c_uint) >> 24 as libc::c_int
        | (__bsx & 0xff0000 as libc::c_uint) >> 8 as libc::c_int
        | (__bsx & 0xff00 as libc::c_uint) << 8 as libc::c_int
        | (__bsx & 0xff as libc::c_uint) << 24 as libc::c_int;
}
#[no_mangle]
pub static mut mod_srtp: srtp_debug_module_t = {
    let mut init = srtp_debug_module_t {
        on: 0 as libc::c_int,
        name: b"srtp\0" as *const u8 as *const libc::c_char,
    };
    init
};
unsafe extern "C" fn srtp_validate_rtp_header(
    mut rtp_hdr: *mut libc::c_void,
    mut pkt_octet_len: *mut libc::c_int,
) -> srtp_err_status_t {
    let mut hdr: *mut srtp_hdr_t = rtp_hdr as *mut srtp_hdr_t;
    let mut rtp_header_len: libc::c_int = 0;
    if *pkt_octet_len < 12 as libc::c_int {
        return srtp_err_status_bad_param;
    }
    rtp_header_len = 12 as libc::c_int + 4 as libc::c_int * (*hdr).cc() as libc::c_int;
    if (*hdr).x() as libc::c_int == 1 as libc::c_int {
        rtp_header_len += 4 as libc::c_int;
    }
    if *pkt_octet_len < rtp_header_len {
        return srtp_err_status_bad_param;
    }
    if (*hdr).x() as libc::c_int == 1 as libc::c_int {
        let mut xtn_hdr: *mut srtp_hdr_xtnd_t = (hdr as *mut uint32_t)
            .offset(3 as libc::c_int as isize)
            .offset((*hdr).cc() as libc::c_int as isize) as *mut srtp_hdr_xtnd_t;
        let mut profile_len: libc::c_int = __bswap_16((*xtn_hdr).length) as libc::c_int;
        rtp_header_len += profile_len * 4 as libc::c_int;
        if *pkt_octet_len < rtp_header_len {
            return srtp_err_status_bad_param;
        }
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_get_version_string() -> *const libc::c_char {
    return b"libsrtp2 2.5.0-pre\0" as *const u8 as *const libc::c_char;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_get_version() -> libc::c_uint {
    let mut major: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut minor: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut micro: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut rv: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut parse_rv: libc::c_int = 0;
    parse_rv = sscanf(
        b"2.5.0-pre\0" as *const u8 as *const libc::c_char,
        b"%u.%u.%u\0" as *const u8 as *const libc::c_char,
        &mut major as *mut libc::c_uint,
        &mut minor as *mut libc::c_uint,
        &mut micro as *mut libc::c_uint,
    );
    if parse_rv != 3 as libc::c_int {
        return 0 as libc::c_int as libc::c_uint;
    }
    rv |= (major & 0xff as libc::c_int as libc::c_uint) << 24 as libc::c_int;
    rv |= (minor & 0xff as libc::c_int as libc::c_uint) << 16 as libc::c_int;
    rv |= micro & 0xff as libc::c_int as libc::c_uint;
    return rv;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_stream_dealloc(
    mut stream: *mut srtp_stream_ctx_t,
    mut stream_template: *const srtp_stream_ctx_t,
) -> srtp_err_status_t {
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut session_keys: *mut srtp_session_keys_t = 0 as *mut srtp_session_keys_t;
    let mut template_session_keys: *mut srtp_session_keys_t = 0
        as *mut srtp_session_keys_t;
    if !((*stream).session_keys).is_null() {
        i = 0 as libc::c_int as libc::c_uint;
        while i < (*stream).num_master_keys {
            session_keys = &mut *((*stream).session_keys).offset(i as isize)
                as *mut srtp_session_keys_t;
            if !stream_template.is_null()
                && (*stream).num_master_keys == (*stream_template).num_master_keys
            {
                template_session_keys = &mut *((*stream_template).session_keys)
                    .offset(i as isize) as *mut srtp_session_keys_t;
            } else {
                template_session_keys = 0 as *mut srtp_session_keys_t;
            }
            if !(!template_session_keys.is_null()
                && (*session_keys).rtp_cipher == (*template_session_keys).rtp_cipher)
            {
                if !((*session_keys).rtp_cipher).is_null() {
                    status = srtp_cipher_dealloc((*session_keys).rtp_cipher);
                    if status as u64 != 0 {
                        return status;
                    }
                }
            }
            if !(!template_session_keys.is_null()
                && (*session_keys).rtp_auth == (*template_session_keys).rtp_auth)
            {
                if !((*session_keys).rtp_auth).is_null() {
                    status = ((*(*(*session_keys).rtp_auth).type_0).dealloc)
                        .expect("non-null function pointer")((*session_keys).rtp_auth);
                    if status as u64 != 0 {
                        return status;
                    }
                }
            }
            if !(!template_session_keys.is_null()
                && (*session_keys).rtp_xtn_hdr_cipher
                    == (*template_session_keys).rtp_xtn_hdr_cipher)
            {
                if !((*session_keys).rtp_xtn_hdr_cipher).is_null() {
                    status = srtp_cipher_dealloc((*session_keys).rtp_xtn_hdr_cipher);
                    if status as u64 != 0 {
                        return status;
                    }
                }
            }
            if !(!template_session_keys.is_null()
                && (*session_keys).rtcp_cipher == (*template_session_keys).rtcp_cipher)
            {
                if !((*session_keys).rtcp_cipher).is_null() {
                    status = srtp_cipher_dealloc((*session_keys).rtcp_cipher);
                    if status as u64 != 0 {
                        return status;
                    }
                }
            }
            if !(!template_session_keys.is_null()
                && (*session_keys).rtcp_auth == (*template_session_keys).rtcp_auth)
            {
                if !((*session_keys).rtcp_auth).is_null() {
                    status = ((*(*(*session_keys).rtcp_auth).type_0).dealloc)
                        .expect("non-null function pointer")((*session_keys).rtcp_auth);
                    if status as u64 != 0 {
                        return status;
                    }
                }
            }
            octet_string_set_to_zero(
                ((*session_keys).salt).as_mut_ptr() as *mut libc::c_void,
                12 as libc::c_int as size_t,
            );
            octet_string_set_to_zero(
                ((*session_keys).c_salt).as_mut_ptr() as *mut libc::c_void,
                12 as libc::c_int as size_t,
            );
            if !((*session_keys).mki_id).is_null() {
                octet_string_set_to_zero(
                    (*session_keys).mki_id as *mut libc::c_void,
                    (*session_keys).mki_size as size_t,
                );
                srtp_crypto_free((*session_keys).mki_id as *mut libc::c_void);
                (*session_keys).mki_id = 0 as *mut uint8_t;
            }
            if !(!template_session_keys.is_null()
                && (*session_keys).limit == (*template_session_keys).limit)
            {
                if !((*session_keys).limit).is_null() {
                    srtp_crypto_free((*session_keys).limit as *mut libc::c_void);
                }
            }
            i = i.wrapping_add(1);
        }
        srtp_crypto_free((*stream).session_keys as *mut libc::c_void);
    }
    status = srtp_rdbx_dealloc(&mut (*stream).rtp_rdbx);
    if status as u64 != 0 {
        return status;
    }
    if !(!stream_template.is_null()
        && (*stream).enc_xtn_hdr == (*stream_template).enc_xtn_hdr)
    {
        if !((*stream).enc_xtn_hdr).is_null() {
            srtp_crypto_free((*stream).enc_xtn_hdr as *mut libc::c_void);
        }
    }
    srtp_crypto_free(stream as *mut libc::c_void);
    return srtp_err_status_ok;
}
unsafe extern "C" fn srtp_valid_policy(
    mut p: *const srtp_policy_t,
) -> srtp_err_status_t {
    if !p.is_null() && !((*p).deprecated_ekt).is_null() {
        return srtp_err_status_bad_param;
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_stream_alloc(
    mut str_ptr: *mut *mut srtp_stream_ctx_t,
    mut p: *const srtp_policy_t,
) -> srtp_err_status_t {
    let mut str: *mut srtp_stream_ctx_t = 0 as *mut srtp_stream_ctx_t;
    let mut stat: srtp_err_status_t = srtp_err_status_ok;
    let mut i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut session_keys: *mut srtp_session_keys_t = 0 as *mut srtp_session_keys_t;
    stat = srtp_valid_policy(p);
    if stat as libc::c_uint != srtp_err_status_ok as libc::c_int as libc::c_uint {
        return stat;
    }
    str = srtp_crypto_alloc(::core::mem::size_of::<srtp_stream_ctx_t>() as libc::c_ulong)
        as *mut srtp_stream_ctx_t;
    if str.is_null() {
        return srtp_err_status_alloc_fail;
    }
    *str_ptr = str;
    if !((*p).key).is_null() {
        (*str).num_master_keys = 1 as libc::c_int as libc::c_uint;
    } else {
        (*str).num_master_keys = (*p).num_master_keys as libc::c_uint;
    }
    (*str)
        .session_keys = srtp_crypto_alloc(
        (::core::mem::size_of::<srtp_session_keys_t>() as libc::c_ulong)
            .wrapping_mul((*str).num_master_keys as libc::c_ulong),
    ) as *mut srtp_session_keys_t;
    if ((*str).session_keys).is_null() {
        srtp_stream_dealloc(str, 0 as *const srtp_stream_ctx_t);
        return srtp_err_status_alloc_fail;
    }
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*str).num_master_keys {
        session_keys = &mut *((*str).session_keys).offset(i as isize)
            as *mut srtp_session_keys_t;
        stat = srtp_crypto_kernel_alloc_cipher(
            (*p).rtp.cipher_type,
            &mut (*session_keys).rtp_cipher,
            (*p).rtp.cipher_key_len,
            (*p).rtp.auth_tag_len,
        );
        if stat as u64 != 0 {
            srtp_stream_dealloc(str, 0 as *const srtp_stream_ctx_t);
            return stat;
        }
        stat = srtp_crypto_kernel_alloc_auth(
            (*p).rtp.auth_type,
            &mut (*session_keys).rtp_auth,
            (*p).rtp.auth_key_len,
            (*p).rtp.auth_tag_len,
        );
        if stat as u64 != 0 {
            srtp_stream_dealloc(str, 0 as *const srtp_stream_ctx_t);
            return stat;
        }
        stat = srtp_crypto_kernel_alloc_cipher(
            (*p).rtcp.cipher_type,
            &mut (*session_keys).rtcp_cipher,
            (*p).rtcp.cipher_key_len,
            (*p).rtcp.auth_tag_len,
        );
        if stat as u64 != 0 {
            srtp_stream_dealloc(str, 0 as *const srtp_stream_ctx_t);
            return stat;
        }
        stat = srtp_crypto_kernel_alloc_auth(
            (*p).rtcp.auth_type,
            &mut (*session_keys).rtcp_auth,
            (*p).rtcp.auth_key_len,
            (*p).rtcp.auth_tag_len,
        );
        if stat as u64 != 0 {
            srtp_stream_dealloc(str, 0 as *const srtp_stream_ctx_t);
            return stat;
        }
        (*session_keys).mki_id = 0 as *mut uint8_t;
        (*session_keys)
            .limit = srtp_crypto_alloc(
            ::core::mem::size_of::<srtp_key_limit_ctx_t>() as libc::c_ulong,
        ) as *mut srtp_key_limit_ctx_t;
        if ((*session_keys).limit).is_null() {
            srtp_stream_dealloc(str, 0 as *const srtp_stream_ctx_t);
            return srtp_err_status_alloc_fail;
        }
        i = i.wrapping_add(1);
    }
    if !((*p).enc_xtn_hdr).is_null() && (*p).enc_xtn_hdr_count > 0 as libc::c_int {
        let mut enc_xtn_hdr_cipher_type: srtp_cipher_type_id_t = 0;
        let mut enc_xtn_hdr_cipher_key_len: libc::c_int = 0;
        (*str)
            .enc_xtn_hdr = srtp_crypto_alloc(
            ((*p).enc_xtn_hdr_count as libc::c_ulong)
                .wrapping_mul(::core::mem::size_of::<libc::c_int>() as libc::c_ulong),
        ) as *mut libc::c_int;
        if ((*str).enc_xtn_hdr).is_null() {
            srtp_stream_dealloc(str, 0 as *const srtp_stream_ctx_t);
            return srtp_err_status_alloc_fail;
        }
        memcpy(
            (*str).enc_xtn_hdr as *mut libc::c_void,
            (*p).enc_xtn_hdr as *const libc::c_void,
            ((*p).enc_xtn_hdr_count as libc::c_ulong)
                .wrapping_mul(::core::mem::size_of::<libc::c_int>() as libc::c_ulong),
        );
        (*str).enc_xtn_hdr_count = (*p).enc_xtn_hdr_count;
        match (*p).rtp.cipher_type {
            6 => {
                enc_xtn_hdr_cipher_type = 1 as libc::c_int as srtp_cipher_type_id_t;
                enc_xtn_hdr_cipher_key_len = 14 as libc::c_int + 16 as libc::c_int;
            }
            7 => {
                enc_xtn_hdr_cipher_type = 5 as libc::c_int as srtp_cipher_type_id_t;
                enc_xtn_hdr_cipher_key_len = 14 as libc::c_int + 32 as libc::c_int;
            }
            _ => {
                enc_xtn_hdr_cipher_type = (*p).rtp.cipher_type;
                enc_xtn_hdr_cipher_key_len = (*p).rtp.cipher_key_len;
            }
        }
        i = 0 as libc::c_int as libc::c_uint;
        while i < (*str).num_master_keys {
            session_keys = &mut *((*str).session_keys).offset(i as isize)
                as *mut srtp_session_keys_t;
            stat = srtp_crypto_kernel_alloc_cipher(
                enc_xtn_hdr_cipher_type,
                &mut (*session_keys).rtp_xtn_hdr_cipher,
                enc_xtn_hdr_cipher_key_len,
                0 as libc::c_int,
            );
            if stat as u64 != 0 {
                srtp_stream_dealloc(str, 0 as *const srtp_stream_ctx_t);
                return stat;
            }
            i = i.wrapping_add(1);
        }
    } else {
        i = 0 as libc::c_int as libc::c_uint;
        while i < (*str).num_master_keys {
            session_keys = &mut *((*str).session_keys).offset(i as isize)
                as *mut srtp_session_keys_t;
            (*session_keys).rtp_xtn_hdr_cipher = 0 as *mut srtp_cipher_t;
            i = i.wrapping_add(1);
        }
        (*str).enc_xtn_hdr = 0 as *mut libc::c_int;
        (*str).enc_xtn_hdr_count = 0 as libc::c_int;
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_stream_clone(
    mut stream_template: *const srtp_stream_ctx_t,
    mut ssrc: uint32_t,
    mut str_ptr: *mut *mut srtp_stream_ctx_t,
) -> srtp_err_status_t {
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut str: *mut srtp_stream_ctx_t = 0 as *mut srtp_stream_ctx_t;
    let mut i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut session_keys: *mut srtp_session_keys_t = 0 as *mut srtp_session_keys_t;
    let mut template_session_keys: *const srtp_session_keys_t = 0
        as *const srtp_session_keys_t;
    if mod_srtp.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: cloning stream (SSRC: 0x%08x)\n\0" as *const u8 as *const libc::c_char,
            mod_srtp.name,
            __bswap_32(ssrc),
        );
    }
    str = srtp_crypto_alloc(::core::mem::size_of::<srtp_stream_ctx_t>() as libc::c_ulong)
        as *mut srtp_stream_ctx_t;
    if str.is_null() {
        return srtp_err_status_alloc_fail;
    }
    *str_ptr = str;
    (*str).num_master_keys = (*stream_template).num_master_keys;
    (*str)
        .session_keys = srtp_crypto_alloc(
        (::core::mem::size_of::<srtp_session_keys_t>() as libc::c_ulong)
            .wrapping_mul((*str).num_master_keys as libc::c_ulong),
    ) as *mut srtp_session_keys_t;
    if ((*str).session_keys).is_null() {
        srtp_stream_dealloc(*str_ptr, stream_template);
        *str_ptr = 0 as *mut srtp_stream_ctx_t;
        return srtp_err_status_alloc_fail;
    }
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*stream_template).num_master_keys {
        session_keys = &mut *((*str).session_keys).offset(i as isize)
            as *mut srtp_session_keys_t;
        template_session_keys = &mut *((*stream_template).session_keys)
            .offset(i as isize) as *mut srtp_session_keys_t;
        (*session_keys).rtp_cipher = (*template_session_keys).rtp_cipher;
        (*session_keys).rtp_auth = (*template_session_keys).rtp_auth;
        (*session_keys).rtp_xtn_hdr_cipher = (*template_session_keys).rtp_xtn_hdr_cipher;
        (*session_keys).rtcp_cipher = (*template_session_keys).rtcp_cipher;
        (*session_keys).rtcp_auth = (*template_session_keys).rtcp_auth;
        (*session_keys).mki_size = (*template_session_keys).mki_size;
        if (*template_session_keys).mki_size == 0 as libc::c_int as libc::c_uint {
            (*session_keys).mki_id = 0 as *mut uint8_t;
        } else {
            (*session_keys)
                .mki_id = srtp_crypto_alloc((*template_session_keys).mki_size as size_t)
                as *mut uint8_t;
            if ((*session_keys).mki_id).is_null() {
                srtp_stream_dealloc(*str_ptr, stream_template);
                *str_ptr = 0 as *mut srtp_stream_ctx_t;
                return srtp_err_status_init_fail;
            }
            memcpy(
                (*session_keys).mki_id as *mut libc::c_void,
                (*template_session_keys).mki_id as *const libc::c_void,
                (*session_keys).mki_size as libc::c_ulong,
            );
        }
        memcpy(
            ((*session_keys).salt).as_mut_ptr() as *mut libc::c_void,
            ((*template_session_keys).salt).as_ptr() as *const libc::c_void,
            12 as libc::c_int as libc::c_ulong,
        );
        memcpy(
            ((*session_keys).c_salt).as_mut_ptr() as *mut libc::c_void,
            ((*template_session_keys).c_salt).as_ptr() as *const libc::c_void,
            12 as libc::c_int as libc::c_ulong,
        );
        status = srtp_key_limit_clone(
            (*template_session_keys).limit,
            &mut (*session_keys).limit,
        );
        if status as u64 != 0 {
            srtp_stream_dealloc(*str_ptr, stream_template);
            *str_ptr = 0 as *mut srtp_stream_ctx_t;
            return status;
        }
        i = i.wrapping_add(1);
    }
    status = srtp_rdbx_init(
        &mut (*str).rtp_rdbx,
        srtp_rdbx_get_window_size(&(*stream_template).rtp_rdbx),
    );
    if status as u64 != 0 {
        srtp_stream_dealloc(*str_ptr, stream_template);
        *str_ptr = 0 as *mut srtp_stream_ctx_t;
        return status;
    }
    srtp_rdb_init(&mut (*str).rtcp_rdb);
    (*str).allow_repeat_tx = (*stream_template).allow_repeat_tx;
    (*str).ssrc = ssrc;
    (*str).pending_roc = 0 as libc::c_int as uint32_t;
    (*str).direction = (*stream_template).direction;
    (*str).rtp_services = (*stream_template).rtp_services;
    (*str).rtcp_services = (*stream_template).rtcp_services;
    (*str).enc_xtn_hdr = (*stream_template).enc_xtn_hdr;
    (*str).enc_xtn_hdr_count = (*stream_template).enc_xtn_hdr_count;
    (*str).next = 0 as *mut srtp_stream_ctx_t_;
    return srtp_err_status_ok;
}
unsafe extern "C" fn srtp_kdf_init(
    mut kdf: *mut srtp_kdf_t,
    mut key: *const uint8_t,
    mut key_len: libc::c_int,
) -> srtp_err_status_t {
    let mut cipher_id: srtp_cipher_type_id_t = 0;
    let mut stat: srtp_err_status_t = srtp_err_status_ok;
    match key_len {
        46 => {
            cipher_id = 5 as libc::c_int as srtp_cipher_type_id_t;
        }
        38 => {
            cipher_id = 4 as libc::c_int as srtp_cipher_type_id_t;
        }
        30 => {
            cipher_id = 1 as libc::c_int as srtp_cipher_type_id_t;
        }
        _ => return srtp_err_status_bad_param,
    }
    stat = srtp_crypto_kernel_alloc_cipher(
        cipher_id,
        &mut (*kdf).cipher,
        key_len,
        0 as libc::c_int,
    );
    if stat as u64 != 0 {
        return stat;
    }
    stat = srtp_cipher_init((*kdf).cipher, key);
    if stat as u64 != 0 {
        srtp_cipher_dealloc((*kdf).cipher);
        return stat;
    }
    return srtp_err_status_ok;
}
unsafe extern "C" fn srtp_kdf_generate(
    mut kdf: *mut srtp_kdf_t,
    mut label: srtp_prf_label,
    mut key: *mut uint8_t,
    mut length: libc::c_uint,
) -> srtp_err_status_t {
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut nonce: v128_t = v128_t { v8: [0; 16] };
    nonce.v32[0 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    nonce.v32[1 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    nonce.v32[2 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    nonce.v32[3 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    nonce.v8[7 as libc::c_int as usize] = label as uint8_t;
    status = srtp_cipher_set_iv(
        (*kdf).cipher,
        &mut nonce as *mut v128_t as *mut uint8_t,
        srtp_direction_encrypt as libc::c_int,
    );
    if status as u64 != 0 {
        return status;
    }
    octet_string_set_to_zero(key as *mut libc::c_void, length as size_t);
    status = srtp_cipher_encrypt((*kdf).cipher, key, &mut length);
    if status as u64 != 0 {
        return status;
    }
    return srtp_err_status_ok;
}
unsafe extern "C" fn srtp_kdf_clear(mut kdf: *mut srtp_kdf_t) -> srtp_err_status_t {
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    status = srtp_cipher_dealloc((*kdf).cipher);
    if status as u64 != 0 {
        return status;
    }
    (*kdf).cipher = 0 as *mut srtp_cipher_t;
    return srtp_err_status_ok;
}
#[inline]
unsafe extern "C" fn base_key_length(
    mut cipher: *const srtp_cipher_type_t,
    mut key_length: libc::c_int,
) -> libc::c_int {
    match (*cipher).id {
        0 => return 0 as libc::c_int,
        1 | 4 | 5 => return key_length - 14 as libc::c_int,
        6 => return key_length - 12 as libc::c_int,
        7 => return key_length - 12 as libc::c_int,
        _ => return key_length,
    };
}
#[inline]
unsafe extern "C" fn full_key_length(
    mut cipher: *const srtp_cipher_type_t,
) -> libc::c_int {
    match (*cipher).id {
        0 | 1 => return 14 as libc::c_int + 16 as libc::c_int,
        4 => return 14 as libc::c_int + 24 as libc::c_int,
        5 => return 14 as libc::c_int + 32 as libc::c_int,
        6 => return 12 as libc::c_int + 16 as libc::c_int,
        7 => return 12 as libc::c_int + 32 as libc::c_int,
        _ => return 0 as libc::c_int,
    };
}
#[no_mangle]
pub unsafe extern "C" fn srtp_validate_policy_master_keys(
    mut policy: *const srtp_policy_t,
) -> libc::c_uint {
    let mut i: libc::c_ulong = 0 as libc::c_int as libc::c_ulong;
    if ((*policy).key).is_null() {
        if (*policy).num_master_keys <= 0 as libc::c_int as libc::c_ulong {
            return 0 as libc::c_int as libc::c_uint;
        }
        if (*policy).num_master_keys > 16 as libc::c_int as libc::c_ulong {
            return 0 as libc::c_int as libc::c_uint;
        }
        i = 0 as libc::c_int as libc::c_ulong;
        while i < (*policy).num_master_keys {
            if ((**((*policy).keys).offset(i as isize)).key).is_null() {
                return 0 as libc::c_int as libc::c_uint;
            }
            if (**((*policy).keys).offset(i as isize)).mki_size
                > 128 as libc::c_int as libc::c_uint
            {
                return 0 as libc::c_int as libc::c_uint;
            }
            i = i.wrapping_add(1);
        }
    }
    return 1 as libc::c_int as libc::c_uint;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_get_session_keys_with_mki_index(
    mut stream: *mut srtp_stream_ctx_t,
    mut use_mki: libc::c_uint,
    mut mki_index: libc::c_uint,
) -> *mut srtp_session_keys_t {
    if use_mki != 0 {
        if mki_index >= (*stream).num_master_keys {
            return 0 as *mut srtp_session_keys_t;
        }
        return &mut *((*stream).session_keys).offset(mki_index as isize)
            as *mut srtp_session_keys_t;
    }
    return &mut *((*stream).session_keys).offset(0 as libc::c_int as isize)
        as *mut srtp_session_keys_t;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_inject_mki(
    mut mki_tag_location: *mut uint8_t,
    mut session_keys: *mut srtp_session_keys_t,
    mut use_mki: libc::c_uint,
) -> libc::c_uint {
    let mut mki_size: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    if use_mki != 0 {
        mki_size = (*session_keys).mki_size;
        if mki_size != 0 as libc::c_int as libc::c_uint {
            memcpy(
                mki_tag_location as *mut libc::c_void,
                (*session_keys).mki_id as *const libc::c_void,
                mki_size as libc::c_ulong,
            );
        }
    }
    return mki_size;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_stream_init_all_master_keys(
    mut srtp: *mut srtp_stream_ctx_t,
    mut key: *mut libc::c_uchar,
    mut keys: *mut *mut srtp_master_key_t,
    max_master_keys: libc::c_uint,
) -> srtp_err_status_t {
    let mut i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut single_master_key: srtp_master_key_t = srtp_master_key_t {
        key: 0 as *mut libc::c_uchar,
        mki_id: 0 as *mut libc::c_uchar,
        mki_size: 0,
    };
    if !key.is_null() {
        (*srtp).num_master_keys = 1 as libc::c_int as libc::c_uint;
        single_master_key.key = key;
        single_master_key.mki_id = 0 as *mut libc::c_uchar;
        single_master_key.mki_size = 0 as libc::c_int as libc::c_uint;
        status = srtp_stream_init_keys(
            srtp,
            &mut single_master_key,
            0 as libc::c_int as libc::c_uint,
        );
    } else {
        (*srtp).num_master_keys = max_master_keys;
        i = 0 as libc::c_int as libc::c_uint;
        while i < (*srtp).num_master_keys && i < 16 as libc::c_int as libc::c_uint {
            status = srtp_stream_init_keys(srtp, *keys.offset(i as isize), i);
            if status as u64 != 0 {
                return status;
            }
            i = i.wrapping_add(1);
        }
    }
    return status;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_stream_init_keys(
    mut srtp: *mut srtp_stream_ctx_t,
    mut master_key: *mut srtp_master_key_t,
    current_mki_index: libc::c_uint,
) -> srtp_err_status_t {
    let mut stat: srtp_err_status_t = srtp_err_status_ok;
    let mut kdf: srtp_kdf_t = srtp_kdf_t {
        cipher: 0 as *mut srtp_cipher_t,
    };
    let mut tmp_key: [uint8_t; 256] = [0; 256];
    let mut input_keylen: libc::c_int = 0;
    let mut input_keylen_rtcp: libc::c_int = 0;
    let mut kdf_keylen: libc::c_int = 30 as libc::c_int;
    let mut rtp_keylen: libc::c_int = 0;
    let mut rtcp_keylen: libc::c_int = 0;
    let mut rtp_base_key_len: libc::c_int = 0;
    let mut rtp_salt_len: libc::c_int = 0;
    let mut rtcp_base_key_len: libc::c_int = 0;
    let mut rtcp_salt_len: libc::c_int = 0;
    let mut session_keys: *mut srtp_session_keys_t = 0 as *mut srtp_session_keys_t;
    let mut key: *mut libc::c_uchar = (*master_key).key;
    session_keys = &mut *((*srtp).session_keys).offset(current_mki_index as isize)
        as *mut srtp_session_keys_t;
    srtp_key_limit_set(
        (*session_keys).limit,
        0xffffffffffff as libc::c_longlong as srtp_xtd_seq_num_t,
    );
    if (*master_key).mki_size != 0 as libc::c_int as libc::c_uint {
        (*session_keys)
            .mki_id = srtp_crypto_alloc((*master_key).mki_size as size_t)
            as *mut uint8_t;
        if ((*session_keys).mki_id).is_null() {
            return srtp_err_status_init_fail;
        }
        memcpy(
            (*session_keys).mki_id as *mut libc::c_void,
            (*master_key).mki_id as *const libc::c_void,
            (*master_key).mki_size as libc::c_ulong,
        );
    } else {
        (*session_keys).mki_id = 0 as *mut uint8_t;
    }
    (*session_keys).mki_size = (*master_key).mki_size;
    input_keylen = full_key_length((*(*session_keys).rtp_cipher).type_0);
    input_keylen_rtcp = full_key_length((*(*session_keys).rtcp_cipher).type_0);
    if input_keylen_rtcp > input_keylen {
        input_keylen = input_keylen_rtcp;
    }
    rtp_keylen = srtp_cipher_get_key_length((*session_keys).rtp_cipher);
    rtcp_keylen = srtp_cipher_get_key_length((*session_keys).rtcp_cipher);
    rtp_base_key_len = base_key_length((*(*session_keys).rtp_cipher).type_0, rtp_keylen);
    rtp_salt_len = rtp_keylen - rtp_base_key_len;
    if rtp_keylen < input_keylen && rtcp_keylen < input_keylen {
        return srtp_err_status_bad_param;
    }
    if rtp_keylen > kdf_keylen {
        kdf_keylen = 46 as libc::c_int;
    }
    if rtcp_keylen > kdf_keylen {
        kdf_keylen = 46 as libc::c_int;
    }
    if input_keylen > kdf_keylen {
        kdf_keylen = 46 as libc::c_int;
    }
    if mod_srtp.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: input key len: %d\n\0" as *const u8 as *const libc::c_char,
            mod_srtp.name,
            input_keylen,
        );
    }
    if mod_srtp.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: srtp key len: %d\n\0" as *const u8 as *const libc::c_char,
            mod_srtp.name,
            rtp_keylen,
        );
    }
    if mod_srtp.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: srtcp key len: %d\n\0" as *const u8 as *const libc::c_char,
            mod_srtp.name,
            rtcp_keylen,
        );
    }
    if mod_srtp.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: base key len: %d\n\0" as *const u8 as *const libc::c_char,
            mod_srtp.name,
            rtp_base_key_len,
        );
    }
    if mod_srtp.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: kdf key len: %d\n\0" as *const u8 as *const libc::c_char,
            mod_srtp.name,
            kdf_keylen,
        );
    }
    if mod_srtp.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: rtp salt len: %d\n\0" as *const u8 as *const libc::c_char,
            mod_srtp.name,
            rtp_salt_len,
        );
    }
    memset(
        tmp_key.as_mut_ptr() as *mut libc::c_void,
        0 as libc::c_int,
        256 as libc::c_int as libc::c_ulong,
    );
    memcpy(
        tmp_key.as_mut_ptr() as *mut libc::c_void,
        key as *const libc::c_void,
        input_keylen as libc::c_ulong,
    );
    stat = srtp_kdf_init(&mut kdf, tmp_key.as_mut_ptr() as *const uint8_t, kdf_keylen);
    if stat as u64 != 0 {
        octet_string_set_to_zero(
            tmp_key.as_mut_ptr() as *mut libc::c_void,
            256 as libc::c_int as size_t,
        );
        return srtp_err_status_init_fail;
    }
    stat = srtp_kdf_generate(
        &mut kdf,
        label_rtp_encryption,
        tmp_key.as_mut_ptr(),
        rtp_base_key_len as libc::c_uint,
    );
    if stat as u64 != 0 {
        octet_string_set_to_zero(
            tmp_key.as_mut_ptr() as *mut libc::c_void,
            256 as libc::c_int as size_t,
        );
        return srtp_err_status_init_fail;
    }
    if mod_srtp.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: cipher key: %s\n\0" as *const u8 as *const libc::c_char,
            mod_srtp.name,
            srtp_octet_string_hex_string(
                tmp_key.as_mut_ptr() as *const libc::c_void,
                rtp_base_key_len,
            ),
        );
    }
    if rtp_salt_len > 0 as libc::c_int {
        if mod_srtp.on != 0 {
            srtp_err_report(
                srtp_err_level_debug,
                b"%s: found rtp_salt_len > 0, generating salt\n\0" as *const u8
                    as *const libc::c_char,
                mod_srtp.name,
            );
        }
        stat = srtp_kdf_generate(
            &mut kdf,
            label_rtp_salt,
            tmp_key.as_mut_ptr().offset(rtp_base_key_len as isize),
            rtp_salt_len as libc::c_uint,
        );
        if stat as u64 != 0 {
            octet_string_set_to_zero(
                tmp_key.as_mut_ptr() as *mut libc::c_void,
                256 as libc::c_int as size_t,
            );
            return srtp_err_status_init_fail;
        }
        memcpy(
            ((*session_keys).salt).as_mut_ptr() as *mut libc::c_void,
            tmp_key.as_mut_ptr().offset(rtp_base_key_len as isize)
                as *const libc::c_void,
            12 as libc::c_int as libc::c_ulong,
        );
    }
    if rtp_salt_len > 0 as libc::c_int {
        if mod_srtp.on != 0 {
            srtp_err_report(
                srtp_err_level_debug,
                b"%s: cipher salt: %s\n\0" as *const u8 as *const libc::c_char,
                mod_srtp.name,
                srtp_octet_string_hex_string(
                    tmp_key.as_mut_ptr().offset(rtp_base_key_len as isize)
                        as *const libc::c_void,
                    rtp_salt_len,
                ),
            );
        }
    }
    stat = srtp_cipher_init((*session_keys).rtp_cipher, tmp_key.as_mut_ptr());
    if stat as u64 != 0 {
        octet_string_set_to_zero(
            tmp_key.as_mut_ptr() as *mut libc::c_void,
            256 as libc::c_int as size_t,
        );
        return srtp_err_status_init_fail;
    }
    if !((*session_keys).rtp_xtn_hdr_cipher).is_null() {
        let mut rtp_xtn_hdr_keylen: libc::c_int = 0;
        let mut rtp_xtn_hdr_base_key_len: libc::c_int = 0;
        let mut rtp_xtn_hdr_salt_len: libc::c_int = 0;
        let mut tmp_kdf: srtp_kdf_t = srtp_kdf_t {
            cipher: 0 as *mut srtp_cipher_t,
        };
        let mut xtn_hdr_kdf: *mut srtp_kdf_t = 0 as *mut srtp_kdf_t;
        if (*(*session_keys).rtp_xtn_hdr_cipher).type_0
            != (*(*session_keys).rtp_cipher).type_0
        {
            let mut tmp_xtn_hdr_key: [uint8_t; 256] = [0; 256];
            rtp_xtn_hdr_keylen = srtp_cipher_get_key_length(
                (*session_keys).rtp_xtn_hdr_cipher,
            );
            rtp_xtn_hdr_base_key_len = base_key_length(
                (*(*session_keys).rtp_xtn_hdr_cipher).type_0,
                rtp_xtn_hdr_keylen,
            );
            rtp_xtn_hdr_salt_len = rtp_xtn_hdr_keylen - rtp_xtn_hdr_base_key_len;
            if rtp_xtn_hdr_salt_len > rtp_salt_len {
                match (*(*(*session_keys).rtp_cipher).type_0).id {
                    6 | 7 => {
                        rtp_xtn_hdr_salt_len = rtp_salt_len;
                    }
                    _ => {
                        octet_string_set_to_zero(
                            tmp_key.as_mut_ptr() as *mut libc::c_void,
                            256 as libc::c_int as size_t,
                        );
                        return srtp_err_status_bad_param;
                    }
                }
            }
            memset(
                tmp_xtn_hdr_key.as_mut_ptr() as *mut libc::c_void,
                0 as libc::c_int,
                256 as libc::c_int as libc::c_ulong,
            );
            memcpy(
                tmp_xtn_hdr_key.as_mut_ptr() as *mut libc::c_void,
                key as *const libc::c_void,
                (rtp_xtn_hdr_base_key_len + rtp_xtn_hdr_salt_len) as libc::c_ulong,
            );
            xtn_hdr_kdf = &mut tmp_kdf;
            stat = srtp_kdf_init(
                xtn_hdr_kdf,
                tmp_xtn_hdr_key.as_mut_ptr() as *const uint8_t,
                kdf_keylen,
            );
            octet_string_set_to_zero(
                tmp_xtn_hdr_key.as_mut_ptr() as *mut libc::c_void,
                256 as libc::c_int as size_t,
            );
            if stat as u64 != 0 {
                octet_string_set_to_zero(
                    tmp_key.as_mut_ptr() as *mut libc::c_void,
                    256 as libc::c_int as size_t,
                );
                return srtp_err_status_init_fail;
            }
        } else {
            rtp_xtn_hdr_keylen = rtp_keylen;
            rtp_xtn_hdr_base_key_len = rtp_base_key_len;
            rtp_xtn_hdr_salt_len = rtp_salt_len;
            xtn_hdr_kdf = &mut kdf;
        }
        stat = srtp_kdf_generate(
            xtn_hdr_kdf,
            label_rtp_header_encryption,
            tmp_key.as_mut_ptr(),
            rtp_xtn_hdr_base_key_len as libc::c_uint,
        );
        if stat as u64 != 0 {
            octet_string_set_to_zero(
                tmp_key.as_mut_ptr() as *mut libc::c_void,
                256 as libc::c_int as size_t,
            );
            return srtp_err_status_init_fail;
        }
        if mod_srtp.on != 0 {
            srtp_err_report(
                srtp_err_level_debug,
                b"%s: extensions cipher key: %s\n\0" as *const u8 as *const libc::c_char,
                mod_srtp.name,
                srtp_octet_string_hex_string(
                    tmp_key.as_mut_ptr() as *const libc::c_void,
                    rtp_xtn_hdr_base_key_len,
                ),
            );
        }
        if rtp_xtn_hdr_salt_len > 0 as libc::c_int {
            if mod_srtp.on != 0 {
                srtp_err_report(
                    srtp_err_level_debug,
                    b"%s: found rtp_xtn_hdr_salt_len > 0, generating salt\n\0"
                        as *const u8 as *const libc::c_char,
                    mod_srtp.name,
                );
            }
            stat = srtp_kdf_generate(
                xtn_hdr_kdf,
                label_rtp_header_salt,
                tmp_key.as_mut_ptr().offset(rtp_xtn_hdr_base_key_len as isize),
                rtp_xtn_hdr_salt_len as libc::c_uint,
            );
            if stat as u64 != 0 {
                octet_string_set_to_zero(
                    tmp_key.as_mut_ptr() as *mut libc::c_void,
                    256 as libc::c_int as size_t,
                );
                return srtp_err_status_init_fail;
            }
        }
        if rtp_xtn_hdr_salt_len > 0 as libc::c_int {
            if mod_srtp.on != 0 {
                srtp_err_report(
                    srtp_err_level_debug,
                    b"%s: extensions cipher salt: %s\n\0" as *const u8
                        as *const libc::c_char,
                    mod_srtp.name,
                    srtp_octet_string_hex_string(
                        tmp_key.as_mut_ptr().offset(rtp_xtn_hdr_base_key_len as isize)
                            as *const libc::c_void,
                        rtp_xtn_hdr_salt_len,
                    ),
                );
            }
        }
        stat = srtp_cipher_init(
            (*session_keys).rtp_xtn_hdr_cipher,
            tmp_key.as_mut_ptr(),
        );
        if stat as u64 != 0 {
            octet_string_set_to_zero(
                tmp_key.as_mut_ptr() as *mut libc::c_void,
                256 as libc::c_int as size_t,
            );
            return srtp_err_status_init_fail;
        }
        if xtn_hdr_kdf != &mut kdf as *mut srtp_kdf_t {
            stat = srtp_kdf_clear(xtn_hdr_kdf);
            if stat as u64 != 0 {
                octet_string_set_to_zero(
                    tmp_key.as_mut_ptr() as *mut libc::c_void,
                    256 as libc::c_int as size_t,
                );
                return srtp_err_status_init_fail;
            }
        }
    }
    stat = srtp_kdf_generate(
        &mut kdf,
        label_rtp_msg_auth,
        tmp_key.as_mut_ptr(),
        srtp_auth_get_key_length((*session_keys).rtp_auth) as libc::c_uint,
    );
    if stat as u64 != 0 {
        octet_string_set_to_zero(
            tmp_key.as_mut_ptr() as *mut libc::c_void,
            256 as libc::c_int as size_t,
        );
        return srtp_err_status_init_fail;
    }
    if mod_srtp.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: auth key:   %s\n\0" as *const u8 as *const libc::c_char,
            mod_srtp.name,
            srtp_octet_string_hex_string(
                tmp_key.as_mut_ptr() as *const libc::c_void,
                srtp_auth_get_key_length((*session_keys).rtp_auth),
            ),
        );
    }
    stat = ((*(*(*session_keys).rtp_auth).type_0).init)
        .expect(
            "non-null function pointer",
        )(
        (*(*session_keys).rtp_auth).state,
        tmp_key.as_mut_ptr(),
        (*(*session_keys).rtp_auth).key_len,
    );
    if stat as u64 != 0 {
        octet_string_set_to_zero(
            tmp_key.as_mut_ptr() as *mut libc::c_void,
            256 as libc::c_int as size_t,
        );
        return srtp_err_status_init_fail;
    }
    rtcp_base_key_len = base_key_length(
        (*(*session_keys).rtcp_cipher).type_0,
        rtcp_keylen,
    );
    rtcp_salt_len = rtcp_keylen - rtcp_base_key_len;
    if mod_srtp.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: rtcp salt len: %d\n\0" as *const u8 as *const libc::c_char,
            mod_srtp.name,
            rtcp_salt_len,
        );
    }
    stat = srtp_kdf_generate(
        &mut kdf,
        label_rtcp_encryption,
        tmp_key.as_mut_ptr(),
        rtcp_base_key_len as libc::c_uint,
    );
    if stat as u64 != 0 {
        octet_string_set_to_zero(
            tmp_key.as_mut_ptr() as *mut libc::c_void,
            256 as libc::c_int as size_t,
        );
        return srtp_err_status_init_fail;
    }
    if rtcp_salt_len > 0 as libc::c_int {
        if mod_srtp.on != 0 {
            srtp_err_report(
                srtp_err_level_debug,
                b"%s: found rtcp_salt_len > 0, generating rtcp salt\n\0" as *const u8
                    as *const libc::c_char,
                mod_srtp.name,
            );
        }
        stat = srtp_kdf_generate(
            &mut kdf,
            label_rtcp_salt,
            tmp_key.as_mut_ptr().offset(rtcp_base_key_len as isize),
            rtcp_salt_len as libc::c_uint,
        );
        if stat as u64 != 0 {
            octet_string_set_to_zero(
                tmp_key.as_mut_ptr() as *mut libc::c_void,
                256 as libc::c_int as size_t,
            );
            return srtp_err_status_init_fail;
        }
        memcpy(
            ((*session_keys).c_salt).as_mut_ptr() as *mut libc::c_void,
            tmp_key.as_mut_ptr().offset(rtcp_base_key_len as isize)
                as *const libc::c_void,
            12 as libc::c_int as libc::c_ulong,
        );
    }
    if mod_srtp.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: rtcp cipher key: %s\n\0" as *const u8 as *const libc::c_char,
            mod_srtp.name,
            srtp_octet_string_hex_string(
                tmp_key.as_mut_ptr() as *const libc::c_void,
                rtcp_base_key_len,
            ),
        );
    }
    if rtcp_salt_len > 0 as libc::c_int {
        if mod_srtp.on != 0 {
            srtp_err_report(
                srtp_err_level_debug,
                b"%s: rtcp cipher salt: %s\n\0" as *const u8 as *const libc::c_char,
                mod_srtp.name,
                srtp_octet_string_hex_string(
                    tmp_key.as_mut_ptr().offset(rtcp_base_key_len as isize)
                        as *const libc::c_void,
                    rtcp_salt_len,
                ),
            );
        }
    }
    stat = srtp_cipher_init((*session_keys).rtcp_cipher, tmp_key.as_mut_ptr());
    if stat as u64 != 0 {
        octet_string_set_to_zero(
            tmp_key.as_mut_ptr() as *mut libc::c_void,
            256 as libc::c_int as size_t,
        );
        return srtp_err_status_init_fail;
    }
    stat = srtp_kdf_generate(
        &mut kdf,
        label_rtcp_msg_auth,
        tmp_key.as_mut_ptr(),
        srtp_auth_get_key_length((*session_keys).rtcp_auth) as libc::c_uint,
    );
    if stat as u64 != 0 {
        octet_string_set_to_zero(
            tmp_key.as_mut_ptr() as *mut libc::c_void,
            256 as libc::c_int as size_t,
        );
        return srtp_err_status_init_fail;
    }
    if mod_srtp.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: rtcp auth key:   %s\n\0" as *const u8 as *const libc::c_char,
            mod_srtp.name,
            srtp_octet_string_hex_string(
                tmp_key.as_mut_ptr() as *const libc::c_void,
                srtp_auth_get_key_length((*session_keys).rtcp_auth),
            ),
        );
    }
    stat = ((*(*(*session_keys).rtcp_auth).type_0).init)
        .expect(
            "non-null function pointer",
        )(
        (*(*session_keys).rtcp_auth).state,
        tmp_key.as_mut_ptr(),
        (*(*session_keys).rtcp_auth).key_len,
    );
    if stat as u64 != 0 {
        octet_string_set_to_zero(
            tmp_key.as_mut_ptr() as *mut libc::c_void,
            256 as libc::c_int as size_t,
        );
        return srtp_err_status_init_fail;
    }
    stat = srtp_kdf_clear(&mut kdf);
    octet_string_set_to_zero(
        tmp_key.as_mut_ptr() as *mut libc::c_void,
        256 as libc::c_int as size_t,
    );
    if stat as u64 != 0 {
        return srtp_err_status_init_fail;
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_stream_init(
    mut srtp: *mut srtp_stream_ctx_t,
    mut p: *const srtp_policy_t,
) -> srtp_err_status_t {
    let mut err: srtp_err_status_t = srtp_err_status_ok;
    err = srtp_valid_policy(p);
    if err as libc::c_uint != srtp_err_status_ok as libc::c_int as libc::c_uint {
        return err;
    }
    if mod_srtp.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: initializing stream (SSRC: 0x%08x)\n\0" as *const u8
                as *const libc::c_char,
            mod_srtp.name,
            (*p).ssrc.value,
        );
    }
    if (*p).window_size != 0 as libc::c_int as libc::c_ulong
        && ((*p).window_size < 64 as libc::c_int as libc::c_ulong
            || (*p).window_size >= 0x8000 as libc::c_int as libc::c_ulong)
    {
        return srtp_err_status_bad_param;
    }
    if (*p).window_size != 0 as libc::c_int as libc::c_ulong {
        err = srtp_rdbx_init(&mut (*srtp).rtp_rdbx, (*p).window_size);
    } else {
        err = srtp_rdbx_init(&mut (*srtp).rtp_rdbx, 128 as libc::c_int as libc::c_ulong);
    }
    if err as u64 != 0 {
        return err;
    }
    (*srtp).ssrc = __bswap_32((*p).ssrc.value);
    (*srtp).pending_roc = 0 as libc::c_int as uint32_t;
    (*srtp).rtp_services = (*p).rtp.sec_serv;
    (*srtp).rtcp_services = (*p).rtcp.sec_serv;
    (*srtp).direction = dir_unknown;
    srtp_rdb_init(&mut (*srtp).rtcp_rdb);
    if (*p).allow_repeat_tx != 0 as libc::c_int
        && (*p).allow_repeat_tx != 1 as libc::c_int
    {
        srtp_rdbx_dealloc(&mut (*srtp).rtp_rdbx);
        return srtp_err_status_bad_param;
    }
    (*srtp).allow_repeat_tx = (*p).allow_repeat_tx;
    err = srtp_stream_init_all_master_keys(
        srtp,
        (*p).key,
        (*p).keys,
        (*p).num_master_keys as libc::c_uint,
    );
    if err as u64 != 0 {
        srtp_rdbx_dealloc(&mut (*srtp).rtp_rdbx);
        return err;
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_event_reporter(mut data: *mut srtp_event_data_t) {
    srtp_err_report(
        srtp_err_level_warning,
        b"srtp: in stream 0x%x: \0" as *const u8 as *const libc::c_char,
        (*data).ssrc,
    );
    match (*data).event as libc::c_uint {
        0 => {
            srtp_err_report(
                srtp_err_level_warning,
                b"\tSSRC collision\n\0" as *const u8 as *const libc::c_char,
            );
        }
        1 => {
            srtp_err_report(
                srtp_err_level_warning,
                b"\tkey usage soft limit reached\n\0" as *const u8 as *const libc::c_char,
            );
        }
        2 => {
            srtp_err_report(
                srtp_err_level_warning,
                b"\tkey usage hard limit reached\n\0" as *const u8 as *const libc::c_char,
            );
        }
        3 => {
            srtp_err_report(
                srtp_err_level_warning,
                b"\tpacket index limit reached\n\0" as *const u8 as *const libc::c_char,
            );
        }
        _ => {
            srtp_err_report(
                srtp_err_level_warning,
                b"\tunknown event reported to handler\n\0" as *const u8
                    as *const libc::c_char,
            );
        }
    };
}
static mut srtp_event_handler: Option::<srtp_event_handler_func_t> =
    Some(srtp_event_reporter as unsafe extern "C" fn(*mut srtp_event_data_t) -> ());
#[no_mangle]
pub unsafe extern "C" fn srtp_install_event_handler(
    mut func: Option::<srtp_event_handler_func_t>,
) -> srtp_err_status_t {
    srtp_event_handler = func;
    return srtp_err_status_ok;
}
unsafe extern "C" fn srtp_protect_extension_header(
    mut stream: *mut srtp_stream_ctx_t,
    mut id: libc::c_int,
) -> libc::c_int {
    let mut enc_xtn_hdr: *mut libc::c_int = (*stream).enc_xtn_hdr;
    let mut count: libc::c_int = (*stream).enc_xtn_hdr_count;
    if enc_xtn_hdr.is_null() || count <= 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    while count > 0 as libc::c_int {
        if *enc_xtn_hdr == id {
            return 1 as libc::c_int;
        }
        enc_xtn_hdr = enc_xtn_hdr.offset(1);
        count -= 1;
    }
    return 0 as libc::c_int;
}
unsafe extern "C" fn srtp_process_header_encryption(
    mut stream: *mut srtp_stream_ctx_t,
    mut xtn_hdr: *mut srtp_hdr_xtnd_t,
    mut session_keys: *mut srtp_session_keys_t,
) -> srtp_err_status_t {
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut keystream: [uint8_t; 257] = [0; 257];
    let mut keystream_pos: libc::c_int = 0;
    let mut xtn_hdr_data: *mut uint8_t = (xtn_hdr as *mut uint8_t)
        .offset(4 as libc::c_int as isize);
    let mut xtn_hdr_end: *mut uint8_t = xtn_hdr_data
        .offset(
            (__bswap_16((*xtn_hdr).length) as libc::c_ulong)
                .wrapping_mul(::core::mem::size_of::<uint32_t>() as libc::c_ulong)
                as isize,
        );
    if __bswap_16((*xtn_hdr).profile_specific) as libc::c_int == 0xbede as libc::c_int {
        while xtn_hdr_data < xtn_hdr_end {
            let mut xid: uint8_t = ((*xtn_hdr_data as libc::c_int & 0xf0 as libc::c_int)
                >> 4 as libc::c_int) as uint8_t;
            let mut xlen: libc::c_uint = ((*xtn_hdr_data as libc::c_int
                & 0xf as libc::c_int) + 1 as libc::c_int) as libc::c_uint;
            let mut xlen_with_header: uint32_t = (1 as libc::c_int as libc::c_uint)
                .wrapping_add(xlen);
            xtn_hdr_data = xtn_hdr_data.offset(1);
            if xtn_hdr_data.offset(xlen as isize) > xtn_hdr_end {
                return srtp_err_status_parse_err;
            }
            if xid as libc::c_int == 15 as libc::c_int {
                break;
            }
            status = srtp_cipher_output(
                (*session_keys).rtp_xtn_hdr_cipher,
                keystream.as_mut_ptr(),
                &mut xlen_with_header,
            );
            if status as u64 != 0 {
                return srtp_err_status_cipher_fail;
            }
            if srtp_protect_extension_header(stream, xid as libc::c_int) != 0 {
                keystream_pos = 1 as libc::c_int;
                while xlen > 0 as libc::c_int as libc::c_uint {
                    let fresh0 = keystream_pos;
                    keystream_pos = keystream_pos + 1;
                    *xtn_hdr_data = (*xtn_hdr_data as libc::c_int
                        ^ keystream[fresh0 as usize] as libc::c_int) as uint8_t;
                    xtn_hdr_data = xtn_hdr_data.offset(1);
                    xlen = xlen.wrapping_sub(1);
                }
            } else {
                xtn_hdr_data = xtn_hdr_data.offset(xlen as isize);
            }
            while xtn_hdr_data < xtn_hdr_end
                && *xtn_hdr_data as libc::c_int == 0 as libc::c_int
            {
                xtn_hdr_data = xtn_hdr_data.offset(1);
            }
        }
    } else if __bswap_16((*xtn_hdr).profile_specific) as libc::c_int
            & 0xfff0 as libc::c_int == 0x1000 as libc::c_int
        {
        while xtn_hdr_data.offset(1 as libc::c_int as isize) < xtn_hdr_end {
            let mut xid_0: uint8_t = *xtn_hdr_data;
            let mut xlen_0: libc::c_uint = *xtn_hdr_data
                .offset(1 as libc::c_int as isize) as libc::c_uint;
            let mut xlen_with_header_0: uint32_t = (2 as libc::c_int as libc::c_uint)
                .wrapping_add(xlen_0);
            xtn_hdr_data = xtn_hdr_data.offset(2 as libc::c_int as isize);
            if xtn_hdr_data.offset(xlen_0 as isize) > xtn_hdr_end {
                return srtp_err_status_parse_err;
            }
            status = srtp_cipher_output(
                (*session_keys).rtp_xtn_hdr_cipher,
                keystream.as_mut_ptr(),
                &mut xlen_with_header_0,
            );
            if status as u64 != 0 {
                return srtp_err_status_cipher_fail;
            }
            if xlen_0 > 0 as libc::c_int as libc::c_uint
                && srtp_protect_extension_header(stream, xid_0 as libc::c_int) != 0
            {
                keystream_pos = 2 as libc::c_int;
                while xlen_0 > 0 as libc::c_int as libc::c_uint {
                    let fresh1 = keystream_pos;
                    keystream_pos = keystream_pos + 1;
                    *xtn_hdr_data = (*xtn_hdr_data as libc::c_int
                        ^ keystream[fresh1 as usize] as libc::c_int) as uint8_t;
                    xtn_hdr_data = xtn_hdr_data.offset(1);
                    xlen_0 = xlen_0.wrapping_sub(1);
                }
            } else {
                xtn_hdr_data = xtn_hdr_data.offset(xlen_0 as isize);
            }
            while xtn_hdr_data < xtn_hdr_end
                && *xtn_hdr_data as libc::c_int == 0 as libc::c_int
            {
                xtn_hdr_data = xtn_hdr_data.offset(1);
            }
        }
    } else {
        return srtp_err_status_parse_err
    }
    return srtp_err_status_ok;
}
unsafe extern "C" fn srtp_calc_aead_iv(
    mut session_keys: *mut srtp_session_keys_t,
    mut iv: *mut v128_t,
    mut seq: *mut srtp_xtd_seq_num_t,
    mut hdr: *mut srtp_hdr_t,
) {
    let mut in_0: v128_t = v128_t { v8: [0; 16] };
    let mut salt: v128_t = v128_t { v8: [0; 16] };
    let mut local_roc: uint32_t = (*seq >> 16 as libc::c_int) as uint32_t;
    let mut local_seq: uint16_t = *seq as uint16_t;
    memset(
        &mut in_0 as *mut v128_t as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<v128_t>() as libc::c_ulong,
    );
    memset(
        &mut salt as *mut v128_t as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<v128_t>() as libc::c_ulong,
    );
    in_0.v16[5 as libc::c_int as usize] = __bswap_16(local_seq);
    local_roc = __bswap_32(local_roc);
    memcpy(
        &mut *(in_0.v16).as_mut_ptr().offset(3 as libc::c_int as isize) as *mut uint16_t
            as *mut libc::c_void,
        &mut local_roc as *mut uint32_t as *const libc::c_void,
        ::core::mem::size_of::<uint32_t>() as libc::c_ulong,
    );
    memcpy(
        &mut *(in_0.v8).as_mut_ptr().offset(2 as libc::c_int as isize) as *mut uint8_t
            as *mut libc::c_void,
        &mut (*hdr).ssrc as *mut uint32_t as *const libc::c_void,
        4 as libc::c_int as libc::c_ulong,
    );
    if mod_srtp.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: Pre-salted RTP IV = %s\n\n\0" as *const u8 as *const libc::c_char,
            mod_srtp.name,
            v128_hex_string(&mut in_0),
        );
    }
    memcpy(
        (salt.v8).as_mut_ptr() as *mut libc::c_void,
        ((*session_keys).salt).as_mut_ptr() as *const libc::c_void,
        12 as libc::c_int as libc::c_ulong,
    );
    if mod_srtp.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: RTP SALT = %s\n\n\0" as *const u8 as *const libc::c_char,
            mod_srtp.name,
            v128_hex_string(&mut salt),
        );
    }
    (*iv)
        .v32[0 as libc::c_int
        as usize] = in_0.v32[0 as libc::c_int as usize]
        ^ salt.v32[0 as libc::c_int as usize];
    (*iv)
        .v32[1 as libc::c_int
        as usize] = in_0.v32[1 as libc::c_int as usize]
        ^ salt.v32[1 as libc::c_int as usize];
    (*iv)
        .v32[2 as libc::c_int
        as usize] = in_0.v32[2 as libc::c_int as usize]
        ^ salt.v32[2 as libc::c_int as usize];
    (*iv)
        .v32[3 as libc::c_int
        as usize] = in_0.v32[3 as libc::c_int as usize]
        ^ salt.v32[3 as libc::c_int as usize];
}
#[no_mangle]
pub unsafe extern "C" fn srtp_get_session_keys(
    mut stream: *mut srtp_stream_ctx_t,
    mut hdr: *mut uint8_t,
    mut pkt_octet_len: *const libc::c_uint,
    mut mki_size: *mut libc::c_uint,
) -> *mut srtp_session_keys_t {
    let mut base_mki_start_location: libc::c_uint = *pkt_octet_len;
    let mut mki_start_location: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut tag_len: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut i: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    if (*(*((*stream).session_keys).offset(0 as libc::c_int as isize)).rtp_cipher)
        .algorithm == 6 as libc::c_int
        || (*(*((*stream).session_keys).offset(0 as libc::c_int as isize)).rtp_cipher)
            .algorithm == 7 as libc::c_int
    {
        tag_len = 0 as libc::c_int as libc::c_uint;
    } else {
        tag_len = srtp_auth_get_tag_length(
            (*((*stream).session_keys).offset(0 as libc::c_int as isize)).rtp_auth,
        ) as libc::c_uint;
    }
    if tag_len > base_mki_start_location {
        *mki_size = 0 as libc::c_int as libc::c_uint;
        return 0 as *mut srtp_session_keys_t;
    }
    base_mki_start_location = base_mki_start_location.wrapping_sub(tag_len);
    i = 0 as libc::c_int as libc::c_uint;
    while i < (*stream).num_master_keys {
        if (*((*stream).session_keys).offset(i as isize)).mki_size
            != 0 as libc::c_int as libc::c_uint
            && (*((*stream).session_keys).offset(i as isize)).mki_size
                <= base_mki_start_location
        {
            *mki_size = (*((*stream).session_keys).offset(i as isize)).mki_size;
            mki_start_location = base_mki_start_location.wrapping_sub(*mki_size);
            if memcmp(
                hdr.offset(mki_start_location as isize) as *const libc::c_void,
                (*((*stream).session_keys).offset(i as isize)).mki_id
                    as *const libc::c_void,
                *mki_size as libc::c_ulong,
            ) == 0 as libc::c_int
            {
                return &mut *((*stream).session_keys).offset(i as isize)
                    as *mut srtp_session_keys_t;
            }
        }
        i = i.wrapping_add(1);
    }
    *mki_size = 0 as libc::c_int as libc::c_uint;
    return 0 as *mut srtp_session_keys_t;
}
unsafe extern "C" fn srtp_estimate_index(
    mut rdbx: *mut srtp_rdbx_t,
    mut roc: uint32_t,
    mut est: *mut srtp_xtd_seq_num_t,
    mut seq: srtp_sequence_number_t,
    mut delta: *mut libc::c_int,
) -> srtp_err_status_t {
    *est = (roc as uint64_t) << 16 as libc::c_int | seq as libc::c_ulong;
    *delta = (*est).wrapping_sub((*rdbx).index) as libc::c_int;
    if *est > (*rdbx).index {
        if (*est).wrapping_sub((*rdbx).index)
            > ((1 as libc::c_int)
                << (8 as libc::c_int as libc::c_ulong)
                    .wrapping_mul(
                        ::core::mem::size_of::<srtp_sequence_number_t>() as libc::c_ulong,
                    )
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong)) as libc::c_ulong
        {
            *delta = 0 as libc::c_int;
            return srtp_err_status_pkt_idx_adv;
        }
    } else if *est < (*rdbx).index {
        if ((*rdbx).index).wrapping_sub(*est)
            > ((1 as libc::c_int)
                << (8 as libc::c_int as libc::c_ulong)
                    .wrapping_mul(
                        ::core::mem::size_of::<srtp_sequence_number_t>() as libc::c_ulong,
                    )
                    .wrapping_sub(1 as libc::c_int as libc::c_ulong)) as libc::c_ulong
        {
            *delta = 0 as libc::c_int;
            return srtp_err_status_pkt_idx_old;
        }
    }
    return srtp_err_status_ok;
}
unsafe extern "C" fn srtp_get_est_pkt_index(
    mut hdr: *mut srtp_hdr_t,
    mut stream: *mut srtp_stream_ctx_t,
    mut est: *mut srtp_xtd_seq_num_t,
    mut delta: *mut libc::c_int,
) -> srtp_err_status_t {
    let mut result: srtp_err_status_t = srtp_err_status_ok;
    if (*stream).pending_roc != 0 {
        result = srtp_estimate_index(
            &mut (*stream).rtp_rdbx,
            (*stream).pending_roc,
            est,
            __bswap_16((*hdr).seq),
            delta,
        );
    } else {
        *delta = srtp_rdbx_estimate_index(
            &mut (*stream).rtp_rdbx,
            est,
            __bswap_16((*hdr).seq),
        );
    }
    if mod_srtp.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: estimated u_packet index: %016lx\n\0" as *const u8
                as *const libc::c_char,
            mod_srtp.name,
            *est,
        );
    }
    return result;
}
unsafe extern "C" fn srtp_protect_aead(
    mut ctx: *mut srtp_ctx_t,
    mut stream: *mut srtp_stream_ctx_t,
    mut rtp_hdr: *mut libc::c_void,
    mut pkt_octet_len: *mut libc::c_uint,
    mut session_keys: *mut srtp_session_keys_t,
    mut use_mki: libc::c_uint,
) -> srtp_err_status_t {
    let mut hdr: *mut srtp_hdr_t = rtp_hdr as *mut srtp_hdr_t;
    let mut enc_start: *mut uint32_t = 0 as *mut uint32_t;
    let mut enc_octet_len: libc::c_int = 0 as libc::c_int;
    let mut est: srtp_xtd_seq_num_t = 0;
    let mut delta: libc::c_int = 0;
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut tag_len: uint32_t = 0;
    let mut iv: v128_t = v128_t { v8: [0; 16] };
    let mut aad_len: libc::c_uint = 0;
    let mut xtn_hdr: *mut srtp_hdr_xtnd_t = 0 as *mut srtp_hdr_xtnd_t;
    let mut mki_size: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut mki_location: *mut uint8_t = 0 as *mut uint8_t;
    if mod_srtp.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: function srtp_protect_aead\n\0" as *const u8 as *const libc::c_char,
            mod_srtp.name,
        );
    }
    match srtp_key_limit_update((*session_keys).limit) as libc::c_uint {
        0 => {}
        2 => {
            if srtp_event_handler.is_some() {
                let mut data: srtp_event_data_t = srtp_event_data_t {
                    session: 0 as *mut srtp_ctx_t,
                    ssrc: 0,
                    event: event_ssrc_collision,
                };
                data.session = ctx;
                data.ssrc = __bswap_32((*stream).ssrc);
                data.event = event_key_hard_limit;
                srtp_event_handler.expect("non-null function pointer")(&mut data);
            }
            return srtp_err_status_key_expired;
        }
        1 | _ => {
            if srtp_event_handler.is_some() {
                let mut data_0: srtp_event_data_t = srtp_event_data_t {
                    session: 0 as *mut srtp_ctx_t,
                    ssrc: 0,
                    event: event_ssrc_collision,
                };
                data_0.session = ctx;
                data_0.ssrc = __bswap_32((*stream).ssrc);
                data_0.event = event_key_soft_limit;
                srtp_event_handler.expect("non-null function pointer")(&mut data_0);
            }
        }
    }
    tag_len = srtp_auth_get_tag_length((*session_keys).rtp_auth) as uint32_t;
    enc_start = (hdr as *mut uint32_t)
        .offset(3 as libc::c_int as isize)
        .offset((*hdr).cc() as libc::c_int as isize);
    if (*hdr).x() as libc::c_int == 1 as libc::c_int {
        xtn_hdr = enc_start as *mut srtp_hdr_xtnd_t;
        enc_start = enc_start
            .offset(
                (__bswap_16((*xtn_hdr).length) as libc::c_int + 1 as libc::c_int)
                    as isize,
            );
    }
    if !(enc_start as *mut uint8_t
        <= (hdr as *mut uint8_t).offset(*pkt_octet_len as isize))
    {
        return srtp_err_status_parse_err;
    }
    enc_octet_len = (*pkt_octet_len as libc::c_long
        - (enc_start as *mut uint8_t).offset_from(hdr as *mut uint8_t) as libc::c_long)
        as libc::c_int;
    if enc_octet_len < 0 as libc::c_int {
        return srtp_err_status_parse_err;
    }
    status = srtp_get_est_pkt_index(hdr, stream, &mut est, &mut delta);
    if status as libc::c_uint != 0
        && status as libc::c_uint
            != srtp_err_status_pkt_idx_adv as libc::c_int as libc::c_uint
    {
        return status;
    }
    if status as libc::c_uint
        == srtp_err_status_pkt_idx_adv as libc::c_int as libc::c_uint
    {
        srtp_rdbx_set_roc_seq(
            &mut (*stream).rtp_rdbx,
            (est >> 16 as libc::c_int) as uint32_t,
            (est & 0xffff as libc::c_int as libc::c_ulong) as uint16_t,
        );
        (*stream).pending_roc = 0 as libc::c_int as uint32_t;
        srtp_rdbx_add_index(&mut (*stream).rtp_rdbx, 0 as libc::c_int);
    } else {
        status = srtp_rdbx_check(&mut (*stream).rtp_rdbx, delta);
        if status as u64 != 0 {
            if status as libc::c_uint
                != srtp_err_status_replay_fail as libc::c_int as libc::c_uint
                || (*stream).allow_repeat_tx == 0
            {
                return status;
            }
        }
        srtp_rdbx_add_index(&mut (*stream).rtp_rdbx, delta);
    }
    if mod_srtp.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: estimated packet index: %016lx\n\0" as *const u8
                as *const libc::c_char,
            mod_srtp.name,
            est,
        );
    }
    srtp_calc_aead_iv(session_keys, &mut iv, &mut est, hdr);
    est = __bswap_64(est << 16 as libc::c_int);
    status = srtp_cipher_set_iv(
        (*session_keys).rtp_cipher,
        &mut iv as *mut v128_t as *mut uint8_t,
        srtp_direction_encrypt as libc::c_int,
    );
    if status as u64 == 0 && !((*session_keys).rtp_xtn_hdr_cipher).is_null() {
        iv.v32[0 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
        iv.v32[1 as libc::c_int as usize] = (*hdr).ssrc;
        iv.v64[1 as libc::c_int as usize] = est;
        status = srtp_cipher_set_iv(
            (*session_keys).rtp_xtn_hdr_cipher,
            &mut iv as *mut v128_t as *mut uint8_t,
            srtp_direction_encrypt as libc::c_int,
        );
    }
    if status as u64 != 0 {
        return srtp_err_status_cipher_fail;
    }
    if !xtn_hdr.is_null() && !((*session_keys).rtp_xtn_hdr_cipher).is_null() {
        status = srtp_process_header_encryption(stream, xtn_hdr, session_keys);
        if status as u64 != 0 {
            return status;
        }
    }
    aad_len = (enc_start as *mut uint8_t).offset_from(hdr as *mut uint8_t)
        as libc::c_long as uint32_t;
    status = srtp_cipher_set_aad(
        (*session_keys).rtp_cipher,
        hdr as *mut uint8_t,
        aad_len,
    );
    if status as u64 != 0 {
        return srtp_err_status_cipher_fail;
    }
    status = srtp_cipher_encrypt(
        (*session_keys).rtp_cipher,
        enc_start as *mut uint8_t,
        &mut enc_octet_len as *mut libc::c_int as *mut libc::c_uint,
    );
    if status as u64 != 0 {
        return srtp_err_status_cipher_fail;
    }
    status = srtp_cipher_get_tag(
        (*session_keys).rtp_cipher,
        (enc_start as *mut uint8_t).offset(enc_octet_len as isize),
        &mut tag_len,
    );
    if status as u64 != 0 {
        return srtp_err_status_cipher_fail;
    }
    mki_location = (hdr as *mut uint8_t)
        .offset(*pkt_octet_len as isize)
        .offset(tag_len as isize);
    mki_size = srtp_inject_mki(mki_location, session_keys, use_mki);
    *pkt_octet_len = (*pkt_octet_len).wrapping_add(tag_len);
    *pkt_octet_len = (*pkt_octet_len).wrapping_add(mki_size);
    return srtp_err_status_ok;
}
unsafe extern "C" fn srtp_unprotect_aead(
    mut ctx: *mut srtp_ctx_t,
    mut stream: *mut srtp_stream_ctx_t,
    mut delta: libc::c_int,
    mut est: srtp_xtd_seq_num_t,
    mut srtp_hdr: *mut libc::c_void,
    mut pkt_octet_len: *mut libc::c_uint,
    mut session_keys: *mut srtp_session_keys_t,
    mut mki_size: libc::c_uint,
    mut advance_packet_index: libc::c_int,
) -> srtp_err_status_t {
    let mut hdr: *mut srtp_hdr_t = srtp_hdr as *mut srtp_hdr_t;
    let mut enc_start: *mut uint32_t = 0 as *mut uint32_t;
    let mut enc_octet_len: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut iv: v128_t = v128_t { v8: [0; 16] };
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut tag_len: libc::c_int = 0;
    let mut aad_len: libc::c_uint = 0;
    let mut xtn_hdr: *mut srtp_hdr_xtnd_t = 0 as *mut srtp_hdr_xtnd_t;
    if mod_srtp.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: function srtp_unprotect_aead\n\0" as *const u8 as *const libc::c_char,
            mod_srtp.name,
        );
    }
    if mod_srtp.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: estimated u_packet index: %016lx\n\0" as *const u8
                as *const libc::c_char,
            mod_srtp.name,
            est,
        );
    }
    tag_len = srtp_auth_get_tag_length((*session_keys).rtp_auth);
    srtp_calc_aead_iv(session_keys, &mut iv, &mut est, hdr);
    status = srtp_cipher_set_iv(
        (*session_keys).rtp_cipher,
        &mut iv as *mut v128_t as *mut uint8_t,
        srtp_direction_decrypt as libc::c_int,
    );
    if status as u64 == 0 && !((*session_keys).rtp_xtn_hdr_cipher).is_null() {
        iv.v32[0 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
        iv.v32[1 as libc::c_int as usize] = (*hdr).ssrc;
        iv.v64[1 as libc::c_int as usize] = __bswap_64(est << 16 as libc::c_int);
        status = srtp_cipher_set_iv(
            (*session_keys).rtp_xtn_hdr_cipher,
            &mut iv as *mut v128_t as *mut uint8_t,
            srtp_direction_encrypt as libc::c_int,
        );
    }
    if status as u64 != 0 {
        return srtp_err_status_cipher_fail;
    }
    enc_start = (hdr as *mut uint32_t)
        .offset(3 as libc::c_int as isize)
        .offset((*hdr).cc() as libc::c_int as isize);
    if (*hdr).x() as libc::c_int == 1 as libc::c_int {
        xtn_hdr = enc_start as *mut srtp_hdr_xtnd_t;
        enc_start = enc_start
            .offset(
                (__bswap_16((*xtn_hdr).length) as libc::c_int + 1 as libc::c_int)
                    as isize,
            );
    }
    if !(enc_start as *mut uint8_t
        <= (hdr as *mut uint8_t)
            .offset(
                (*pkt_octet_len)
                    .wrapping_sub(tag_len as libc::c_uint)
                    .wrapping_sub(mki_size) as isize,
            ))
    {
        return srtp_err_status_parse_err;
    }
    enc_octet_len = ((*pkt_octet_len).wrapping_sub(mki_size) as libc::c_long
        - (enc_start as *mut uint8_t).offset_from(hdr as *mut uint8_t) as libc::c_long)
        as libc::c_uint;
    if enc_octet_len < tag_len as libc::c_uint {
        return srtp_err_status_cipher_fail;
    }
    match srtp_key_limit_update((*session_keys).limit) as libc::c_uint {
        1 => {
            if srtp_event_handler.is_some() {
                let mut data: srtp_event_data_t = srtp_event_data_t {
                    session: 0 as *mut srtp_ctx_t,
                    ssrc: 0,
                    event: event_ssrc_collision,
                };
                data.session = ctx;
                data.ssrc = __bswap_32((*stream).ssrc);
                data.event = event_key_soft_limit;
                srtp_event_handler.expect("non-null function pointer")(&mut data);
            }
        }
        2 => {
            if srtp_event_handler.is_some() {
                let mut data_0: srtp_event_data_t = srtp_event_data_t {
                    session: 0 as *mut srtp_ctx_t,
                    ssrc: 0,
                    event: event_ssrc_collision,
                };
                data_0.session = ctx;
                data_0.ssrc = __bswap_32((*stream).ssrc);
                data_0.event = event_key_hard_limit;
                srtp_event_handler.expect("non-null function pointer")(&mut data_0);
            }
            return srtp_err_status_key_expired;
        }
        0 | _ => {}
    }
    aad_len = (enc_start as *mut uint8_t).offset_from(hdr as *mut uint8_t)
        as libc::c_long as uint32_t;
    status = srtp_cipher_set_aad(
        (*session_keys).rtp_cipher,
        hdr as *mut uint8_t,
        aad_len,
    );
    if status as u64 != 0 {
        return srtp_err_status_cipher_fail;
    }
    status = srtp_cipher_decrypt(
        (*session_keys).rtp_cipher,
        enc_start as *mut uint8_t,
        &mut enc_octet_len,
    );
    if status as u64 != 0 {
        return status;
    }
    if !xtn_hdr.is_null() && !((*session_keys).rtp_xtn_hdr_cipher).is_null() {
        status = srtp_process_header_encryption(stream, xtn_hdr, session_keys);
        if status as u64 != 0 {
            return status;
        }
    }
    if (*stream).direction as libc::c_uint
        != dir_srtp_receiver as libc::c_int as libc::c_uint
    {
        if (*stream).direction as libc::c_uint
            == dir_unknown as libc::c_int as libc::c_uint
        {
            (*stream).direction = dir_srtp_receiver;
        } else if srtp_event_handler.is_some() {
            let mut data_1: srtp_event_data_t = srtp_event_data_t {
                session: 0 as *mut srtp_ctx_t,
                ssrc: 0,
                event: event_ssrc_collision,
            };
            data_1.session = ctx;
            data_1.ssrc = __bswap_32((*stream).ssrc);
            data_1.event = event_ssrc_collision;
            srtp_event_handler.expect("non-null function pointer")(&mut data_1);
        }
    }
    if stream == (*ctx).stream_template {
        let mut new_stream: *mut srtp_stream_ctx_t = 0 as *mut srtp_stream_ctx_t;
        status = srtp_stream_clone((*ctx).stream_template, (*hdr).ssrc, &mut new_stream);
        if status as u64 != 0 {
            return status;
        }
        (*new_stream).next = (*ctx).stream_list;
        (*ctx).stream_list = new_stream;
        stream = new_stream;
    }
    if advance_packet_index != 0 {
        let mut roc_to_set: uint32_t = (est >> 16 as libc::c_int) as uint32_t;
        let mut seq_to_set: uint16_t = (est & 0xffff as libc::c_int as libc::c_ulong)
            as uint16_t;
        srtp_rdbx_set_roc_seq(&mut (*stream).rtp_rdbx, roc_to_set, seq_to_set);
        (*stream).pending_roc = 0 as libc::c_int as uint32_t;
        srtp_rdbx_add_index(&mut (*stream).rtp_rdbx, 0 as libc::c_int);
    } else {
        srtp_rdbx_add_index(&mut (*stream).rtp_rdbx, delta);
    }
    *pkt_octet_len = (*pkt_octet_len).wrapping_sub(tag_len as libc::c_uint);
    *pkt_octet_len = (*pkt_octet_len).wrapping_sub(mki_size);
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_protect(
    mut ctx: *mut srtp_ctx_t,
    mut rtp_hdr: *mut libc::c_void,
    mut pkt_octet_len: *mut libc::c_int,
) -> srtp_err_status_t {
    return srtp_protect_mki(
        ctx,
        rtp_hdr,
        pkt_octet_len,
        0 as libc::c_int as libc::c_uint,
        0 as libc::c_int as libc::c_uint,
    );
}
#[no_mangle]
pub unsafe extern "C" fn srtp_protect_mki(
    mut ctx: *mut srtp_ctx_t,
    mut rtp_hdr: *mut libc::c_void,
    mut pkt_octet_len: *mut libc::c_int,
    mut use_mki: libc::c_uint,
    mut mki_index: libc::c_uint,
) -> srtp_err_status_t {
    let mut hdr: *mut srtp_hdr_t = rtp_hdr as *mut srtp_hdr_t;
    let mut enc_start: *mut uint32_t = 0 as *mut uint32_t;
    let mut auth_start: *mut uint32_t = 0 as *mut uint32_t;
    let mut enc_octet_len: libc::c_int = 0 as libc::c_int;
    let mut est: srtp_xtd_seq_num_t = 0;
    let mut delta: libc::c_int = 0;
    let mut auth_tag: *mut uint8_t = 0 as *mut uint8_t;
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut tag_len: libc::c_int = 0;
    let mut stream: *mut srtp_stream_ctx_t = 0 as *mut srtp_stream_ctx_t;
    let mut prefix_len: uint32_t = 0;
    let mut xtn_hdr: *mut srtp_hdr_xtnd_t = 0 as *mut srtp_hdr_xtnd_t;
    let mut mki_size: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut session_keys: *mut srtp_session_keys_t = 0 as *mut srtp_session_keys_t;
    let mut mki_location: *mut uint8_t = 0 as *mut uint8_t;
    if mod_srtp.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: function srtp_protect\n\0" as *const u8 as *const libc::c_char,
            mod_srtp.name,
        );
    }
    status = srtp_validate_rtp_header(rtp_hdr, pkt_octet_len);
    if status as u64 != 0 {
        return status;
    }
    if *pkt_octet_len < 12 as libc::c_int {
        return srtp_err_status_bad_param;
    }
    stream = srtp_get_stream(ctx, (*hdr).ssrc);
    if stream.is_null() {
        if !((*ctx).stream_template).is_null() {
            let mut new_stream: *mut srtp_stream_ctx_t = 0 as *mut srtp_stream_ctx_t;
            status = srtp_stream_clone(
                (*ctx).stream_template,
                (*hdr).ssrc,
                &mut new_stream,
            );
            if status as u64 != 0 {
                return status;
            }
            (*new_stream).next = (*ctx).stream_list;
            (*ctx).stream_list = new_stream;
            (*new_stream).direction = dir_srtp_sender;
            stream = new_stream;
        } else {
            return srtp_err_status_no_ctx
        }
    }
    if (*stream).direction as libc::c_uint
        != dir_srtp_sender as libc::c_int as libc::c_uint
    {
        if (*stream).direction as libc::c_uint
            == dir_unknown as libc::c_int as libc::c_uint
        {
            (*stream).direction = dir_srtp_sender;
        } else if srtp_event_handler.is_some() {
            let mut data: srtp_event_data_t = srtp_event_data_t {
                session: 0 as *mut srtp_ctx_t,
                ssrc: 0,
                event: event_ssrc_collision,
            };
            data.session = ctx;
            data.ssrc = __bswap_32((*stream).ssrc);
            data.event = event_ssrc_collision;
            srtp_event_handler.expect("non-null function pointer")(&mut data);
        }
    }
    session_keys = srtp_get_session_keys_with_mki_index(stream, use_mki, mki_index);
    if session_keys.is_null() {
        return srtp_err_status_bad_mki;
    }
    if (*(*session_keys).rtp_cipher).algorithm == 6 as libc::c_int
        || (*(*session_keys).rtp_cipher).algorithm == 7 as libc::c_int
    {
        return srtp_protect_aead(
            ctx,
            stream,
            rtp_hdr,
            pkt_octet_len as *mut libc::c_uint,
            session_keys,
            use_mki,
        );
    }
    match srtp_key_limit_update((*session_keys).limit) as libc::c_uint {
        1 => {
            if srtp_event_handler.is_some() {
                let mut data_0: srtp_event_data_t = srtp_event_data_t {
                    session: 0 as *mut srtp_ctx_t,
                    ssrc: 0,
                    event: event_ssrc_collision,
                };
                data_0.session = ctx;
                data_0.ssrc = __bswap_32((*stream).ssrc);
                data_0.event = event_key_soft_limit;
                srtp_event_handler.expect("non-null function pointer")(&mut data_0);
            }
        }
        2 => {
            if srtp_event_handler.is_some() {
                let mut data_1: srtp_event_data_t = srtp_event_data_t {
                    session: 0 as *mut srtp_ctx_t,
                    ssrc: 0,
                    event: event_ssrc_collision,
                };
                data_1.session = ctx;
                data_1.ssrc = __bswap_32((*stream).ssrc);
                data_1.event = event_key_hard_limit;
                srtp_event_handler.expect("non-null function pointer")(&mut data_1);
            }
            return srtp_err_status_key_expired;
        }
        0 | _ => {}
    }
    tag_len = srtp_auth_get_tag_length((*session_keys).rtp_auth);
    if (*stream).rtp_services as libc::c_uint
        & sec_serv_conf as libc::c_int as libc::c_uint != 0
    {
        enc_start = (hdr as *mut uint32_t)
            .offset(3 as libc::c_int as isize)
            .offset((*hdr).cc() as libc::c_int as isize);
        if (*hdr).x() as libc::c_int == 1 as libc::c_int {
            xtn_hdr = enc_start as *mut srtp_hdr_xtnd_t;
            enc_start = enc_start
                .offset(
                    (__bswap_16((*xtn_hdr).length) as libc::c_int + 1 as libc::c_int)
                        as isize,
                );
        }
        if !(enc_start as *mut uint8_t
            <= (hdr as *mut uint8_t).offset(*pkt_octet_len as isize))
        {
            return srtp_err_status_parse_err;
        }
        enc_octet_len = (*pkt_octet_len as libc::c_long
            - (enc_start as *mut uint8_t).offset_from(hdr as *mut uint8_t)
                as libc::c_long) as libc::c_int;
        if enc_octet_len < 0 as libc::c_int {
            return srtp_err_status_parse_err;
        }
    } else {
        enc_start = 0 as *mut uint32_t;
    }
    mki_location = (hdr as *mut uint8_t).offset(*pkt_octet_len as isize);
    mki_size = srtp_inject_mki(mki_location, session_keys, use_mki);
    if (*stream).rtp_services as libc::c_uint
        & sec_serv_auth as libc::c_int as libc::c_uint != 0
    {
        auth_start = hdr as *mut uint32_t;
        auth_tag = (hdr as *mut uint8_t)
            .offset(*pkt_octet_len as isize)
            .offset(mki_size as isize);
    } else {
        auth_start = 0 as *mut uint32_t;
        auth_tag = 0 as *mut uint8_t;
    }
    status = srtp_get_est_pkt_index(hdr, stream, &mut est, &mut delta);
    if status as libc::c_uint != 0
        && status as libc::c_uint
            != srtp_err_status_pkt_idx_adv as libc::c_int as libc::c_uint
    {
        return status;
    }
    if status as libc::c_uint
        == srtp_err_status_pkt_idx_adv as libc::c_int as libc::c_uint
    {
        srtp_rdbx_set_roc_seq(
            &mut (*stream).rtp_rdbx,
            (est >> 16 as libc::c_int) as uint32_t,
            (est & 0xffff as libc::c_int as libc::c_ulong) as uint16_t,
        );
        (*stream).pending_roc = 0 as libc::c_int as uint32_t;
        srtp_rdbx_add_index(&mut (*stream).rtp_rdbx, 0 as libc::c_int);
    } else {
        status = srtp_rdbx_check(&mut (*stream).rtp_rdbx, delta);
        if status as u64 != 0 {
            if status as libc::c_uint
                != srtp_err_status_replay_fail as libc::c_int as libc::c_uint
                || (*stream).allow_repeat_tx == 0
            {
                return status;
            }
        }
        srtp_rdbx_add_index(&mut (*stream).rtp_rdbx, delta);
    }
    if mod_srtp.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: estimated packet index: %016lx\n\0" as *const u8
                as *const libc::c_char,
            mod_srtp.name,
            est,
        );
    }
    if (*(*(*session_keys).rtp_cipher).type_0).id == 1 as libc::c_int as libc::c_uint
        || (*(*(*session_keys).rtp_cipher).type_0).id == 4 as libc::c_int as libc::c_uint
        || (*(*(*session_keys).rtp_cipher).type_0).id == 5 as libc::c_int as libc::c_uint
    {
        let mut iv: v128_t = v128_t { v8: [0; 16] };
        iv.v32[0 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
        iv.v32[1 as libc::c_int as usize] = (*hdr).ssrc;
        iv.v64[1 as libc::c_int as usize] = __bswap_64(est << 16 as libc::c_int);
        status = srtp_cipher_set_iv(
            (*session_keys).rtp_cipher,
            &mut iv as *mut v128_t as *mut uint8_t,
            srtp_direction_encrypt as libc::c_int,
        );
        if status as u64 == 0 && !((*session_keys).rtp_xtn_hdr_cipher).is_null() {
            status = srtp_cipher_set_iv(
                (*session_keys).rtp_xtn_hdr_cipher,
                &mut iv as *mut v128_t as *mut uint8_t,
                srtp_direction_encrypt as libc::c_int,
            );
        }
    } else {
        let mut iv_0: v128_t = v128_t { v8: [0; 16] };
        iv_0.v64[0 as libc::c_int as usize] = 0 as libc::c_int as uint64_t;
        iv_0.v64[1 as libc::c_int as usize] = __bswap_64(est);
        status = srtp_cipher_set_iv(
            (*session_keys).rtp_cipher,
            &mut iv_0 as *mut v128_t as *mut uint8_t,
            srtp_direction_encrypt as libc::c_int,
        );
        if status as u64 == 0 && !((*session_keys).rtp_xtn_hdr_cipher).is_null() {
            status = srtp_cipher_set_iv(
                (*session_keys).rtp_xtn_hdr_cipher,
                &mut iv_0 as *mut v128_t as *mut uint8_t,
                srtp_direction_encrypt as libc::c_int,
            );
        }
    }
    if status as u64 != 0 {
        return srtp_err_status_cipher_fail;
    }
    est = __bswap_64(est << 16 as libc::c_int);
    if !auth_start.is_null() {
        prefix_len = srtp_auth_get_prefix_length((*session_keys).rtp_auth) as uint32_t;
        if prefix_len != 0 {
            status = srtp_cipher_output(
                (*session_keys).rtp_cipher,
                auth_tag,
                &mut prefix_len,
            );
            if status as u64 != 0 {
                return srtp_err_status_cipher_fail;
            }
            if mod_srtp.on != 0 {
                srtp_err_report(
                    srtp_err_level_debug,
                    b"%s: keystream prefix: %s\n\0" as *const u8 as *const libc::c_char,
                    mod_srtp.name,
                    srtp_octet_string_hex_string(
                        auth_tag as *const libc::c_void,
                        prefix_len as libc::c_int,
                    ),
                );
            }
        }
    }
    if !xtn_hdr.is_null() && !((*session_keys).rtp_xtn_hdr_cipher).is_null() {
        status = srtp_process_header_encryption(stream, xtn_hdr, session_keys);
        if status as u64 != 0 {
            return status;
        }
    }
    if !enc_start.is_null() {
        status = srtp_cipher_encrypt(
            (*session_keys).rtp_cipher,
            enc_start as *mut uint8_t,
            &mut enc_octet_len as *mut libc::c_int as *mut libc::c_uint,
        );
        if status as u64 != 0 {
            return srtp_err_status_cipher_fail;
        }
    }
    if !auth_start.is_null() {
        status = ((*(*(*session_keys).rtp_auth).type_0).start)
            .expect("non-null function pointer")((*(*session_keys).rtp_auth).state);
        if status as u64 != 0 {
            return status;
        }
        status = ((*(*(*session_keys).rtp_auth).type_0).update)
            .expect(
                "non-null function pointer",
            )(
            (*(*session_keys).rtp_auth).state,
            auth_start as *mut uint8_t,
            *pkt_octet_len,
        );
        if status as u64 != 0 {
            return status;
        }
        if mod_srtp.on != 0 {
            srtp_err_report(
                srtp_err_level_debug,
                b"%s: estimated packet index: %016lx\n\0" as *const u8
                    as *const libc::c_char,
                mod_srtp.name,
                est,
            );
        }
        status = ((*(*(*session_keys).rtp_auth).type_0).compute)
            .expect(
                "non-null function pointer",
            )(
            (*(*session_keys).rtp_auth).state,
            &mut est as *mut srtp_xtd_seq_num_t as *mut uint8_t,
            4 as libc::c_int,
            (*(*session_keys).rtp_auth).out_len,
            auth_tag,
        );
        if mod_srtp.on != 0 {
            srtp_err_report(
                srtp_err_level_debug,
                b"%s: srtp auth tag:    %s\n\0" as *const u8 as *const libc::c_char,
                mod_srtp.name,
                srtp_octet_string_hex_string(auth_tag as *const libc::c_void, tag_len),
            );
        }
        if status as u64 != 0 {
            return srtp_err_status_auth_fail;
        }
    }
    if !auth_tag.is_null() {
        *pkt_octet_len += tag_len;
    }
    if use_mki != 0 {
        *pkt_octet_len = (*pkt_octet_len as libc::c_uint).wrapping_add(mki_size)
            as libc::c_int as libc::c_int;
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_unprotect(
    mut ctx: *mut srtp_ctx_t,
    mut srtp_hdr: *mut libc::c_void,
    mut pkt_octet_len: *mut libc::c_int,
) -> srtp_err_status_t {
    return srtp_unprotect_mki(
        ctx,
        srtp_hdr,
        pkt_octet_len,
        0 as libc::c_int as libc::c_uint,
    );
}
#[no_mangle]
pub unsafe extern "C" fn srtp_unprotect_mki(
    mut ctx: *mut srtp_ctx_t,
    mut srtp_hdr: *mut libc::c_void,
    mut pkt_octet_len: *mut libc::c_int,
    mut use_mki: libc::c_uint,
) -> srtp_err_status_t {
    let mut hdr: *mut srtp_hdr_t = srtp_hdr as *mut srtp_hdr_t;
    let mut enc_start: *mut uint32_t = 0 as *mut uint32_t;
    let mut auth_start: *mut uint32_t = 0 as *mut uint32_t;
    let mut enc_octet_len: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut auth_tag: *mut uint8_t = 0 as *mut uint8_t;
    let mut est: srtp_xtd_seq_num_t = 0;
    let mut delta: libc::c_int = 0;
    let mut iv: v128_t = v128_t { v8: [0; 16] };
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut stream: *mut srtp_stream_ctx_t = 0 as *mut srtp_stream_ctx_t;
    let mut tmp_tag: [uint8_t; 16] = [0; 16];
    let mut tag_len: uint32_t = 0;
    let mut prefix_len: uint32_t = 0;
    let mut xtn_hdr: *mut srtp_hdr_xtnd_t = 0 as *mut srtp_hdr_xtnd_t;
    let mut mki_size: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut session_keys: *mut srtp_session_keys_t = 0 as *mut srtp_session_keys_t;
    let mut advance_packet_index: libc::c_int = 0 as libc::c_int;
    let mut roc_to_set: uint32_t = 0 as libc::c_int as uint32_t;
    let mut seq_to_set: uint16_t = 0 as libc::c_int as uint16_t;
    if mod_srtp.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: function srtp_unprotect\n\0" as *const u8 as *const libc::c_char,
            mod_srtp.name,
        );
    }
    status = srtp_validate_rtp_header(srtp_hdr, pkt_octet_len);
    if status as u64 != 0 {
        return status;
    }
    if *pkt_octet_len < 12 as libc::c_int {
        return srtp_err_status_bad_param;
    }
    stream = srtp_get_stream(ctx, (*hdr).ssrc);
    if stream.is_null() {
        if !((*ctx).stream_template).is_null() {
            stream = (*ctx).stream_template;
            if mod_srtp.on != 0 {
                srtp_err_report(
                    srtp_err_level_debug,
                    b"%s: using provisional stream (SSRC: 0x%08x)\n\0" as *const u8
                        as *const libc::c_char,
                    mod_srtp.name,
                    __bswap_32((*hdr).ssrc),
                );
            }
            est = __bswap_16((*hdr).seq) as srtp_xtd_seq_num_t;
            delta = est as libc::c_int;
        } else {
            return srtp_err_status_no_ctx
        }
    } else {
        status = srtp_get_est_pkt_index(hdr, stream, &mut est, &mut delta);
        if status as libc::c_uint != 0
            && status as libc::c_uint
                != srtp_err_status_pkt_idx_adv as libc::c_int as libc::c_uint
        {
            return status;
        }
        if status as libc::c_uint
            == srtp_err_status_pkt_idx_adv as libc::c_int as libc::c_uint
        {
            advance_packet_index = 1 as libc::c_int;
            roc_to_set = (est >> 16 as libc::c_int) as uint32_t;
            seq_to_set = (est & 0xffff as libc::c_int as libc::c_ulong) as uint16_t;
        }
        if advance_packet_index == 0 {
            status = srtp_rdbx_check(&mut (*stream).rtp_rdbx, delta);
            if status as u64 != 0 {
                return status;
            }
        }
    }
    if mod_srtp.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: estimated u_packet index: %016lx\n\0" as *const u8
                as *const libc::c_char,
            mod_srtp.name,
            est,
        );
    }
    if use_mki != 0 {
        session_keys = srtp_get_session_keys(
            stream,
            hdr as *mut uint8_t,
            pkt_octet_len as *const libc::c_uint,
            &mut mki_size,
        );
        if session_keys.is_null() {
            return srtp_err_status_bad_mki;
        }
    } else {
        session_keys = &mut *((*stream).session_keys).offset(0 as libc::c_int as isize)
            as *mut srtp_session_keys_t;
    }
    if (*(*session_keys).rtp_cipher).algorithm == 6 as libc::c_int
        || (*(*session_keys).rtp_cipher).algorithm == 7 as libc::c_int
    {
        return srtp_unprotect_aead(
            ctx,
            stream,
            delta,
            est,
            srtp_hdr,
            pkt_octet_len as *mut libc::c_uint,
            session_keys,
            mki_size,
            advance_packet_index,
        );
    }
    tag_len = srtp_auth_get_tag_length((*session_keys).rtp_auth) as uint32_t;
    if (*(*(*session_keys).rtp_cipher).type_0).id == 1 as libc::c_int as libc::c_uint
        || (*(*(*session_keys).rtp_cipher).type_0).id == 4 as libc::c_int as libc::c_uint
        || (*(*(*session_keys).rtp_cipher).type_0).id == 5 as libc::c_int as libc::c_uint
    {
        iv.v32[0 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
        iv.v32[1 as libc::c_int as usize] = (*hdr).ssrc;
        iv.v64[1 as libc::c_int as usize] = __bswap_64(est << 16 as libc::c_int);
        status = srtp_cipher_set_iv(
            (*session_keys).rtp_cipher,
            &mut iv as *mut v128_t as *mut uint8_t,
            srtp_direction_decrypt as libc::c_int,
        );
        if status as u64 == 0 && !((*session_keys).rtp_xtn_hdr_cipher).is_null() {
            status = srtp_cipher_set_iv(
                (*session_keys).rtp_xtn_hdr_cipher,
                &mut iv as *mut v128_t as *mut uint8_t,
                srtp_direction_decrypt as libc::c_int,
            );
        }
    } else {
        iv.v64[0 as libc::c_int as usize] = 0 as libc::c_int as uint64_t;
        iv.v64[1 as libc::c_int as usize] = __bswap_64(est);
        status = srtp_cipher_set_iv(
            (*session_keys).rtp_cipher,
            &mut iv as *mut v128_t as *mut uint8_t,
            srtp_direction_decrypt as libc::c_int,
        );
        if status as u64 == 0 && !((*session_keys).rtp_xtn_hdr_cipher).is_null() {
            status = srtp_cipher_set_iv(
                (*session_keys).rtp_xtn_hdr_cipher,
                &mut iv as *mut v128_t as *mut uint8_t,
                srtp_direction_decrypt as libc::c_int,
            );
        }
    }
    if status as u64 != 0 {
        return srtp_err_status_cipher_fail;
    }
    est = __bswap_64(est << 16 as libc::c_int);
    if (*stream).rtp_services as libc::c_uint
        & sec_serv_conf as libc::c_int as libc::c_uint != 0
    {
        enc_start = (hdr as *mut uint32_t)
            .offset(3 as libc::c_int as isize)
            .offset((*hdr).cc() as libc::c_int as isize);
        if (*hdr).x() as libc::c_int == 1 as libc::c_int {
            xtn_hdr = enc_start as *mut srtp_hdr_xtnd_t;
            enc_start = enc_start
                .offset(
                    (__bswap_16((*xtn_hdr).length) as libc::c_int + 1 as libc::c_int)
                        as isize,
                );
        }
        if !(enc_start as *mut uint8_t
            <= (hdr as *mut uint8_t)
                .offset(
                    (*pkt_octet_len as libc::c_uint)
                        .wrapping_sub(tag_len)
                        .wrapping_sub(mki_size) as isize,
                ))
        {
            return srtp_err_status_parse_err;
        }
        enc_octet_len = ((*pkt_octet_len as libc::c_uint)
            .wrapping_sub(tag_len)
            .wrapping_sub(mki_size) as libc::c_long
            - (enc_start as *mut uint8_t).offset_from(hdr as *mut uint8_t)
                as libc::c_long) as uint32_t;
    } else {
        enc_start = 0 as *mut uint32_t;
    }
    if (*stream).rtp_services as libc::c_uint
        & sec_serv_auth as libc::c_int as libc::c_uint != 0
    {
        auth_start = hdr as *mut uint32_t;
        auth_tag = (hdr as *mut uint8_t)
            .offset(*pkt_octet_len as isize)
            .offset(-(tag_len as isize));
    } else {
        auth_start = 0 as *mut uint32_t;
        auth_tag = 0 as *mut uint8_t;
    }
    if !auth_start.is_null() {
        if (*(*session_keys).rtp_auth).prefix_len != 0 as libc::c_int {
            prefix_len = srtp_auth_get_prefix_length((*session_keys).rtp_auth)
                as uint32_t;
            status = srtp_cipher_output(
                (*session_keys).rtp_cipher,
                tmp_tag.as_mut_ptr(),
                &mut prefix_len,
            );
            if mod_srtp.on != 0 {
                srtp_err_report(
                    srtp_err_level_debug,
                    b"%s: keystream prefix: %s\n\0" as *const u8 as *const libc::c_char,
                    mod_srtp.name,
                    srtp_octet_string_hex_string(
                        tmp_tag.as_mut_ptr() as *const libc::c_void,
                        prefix_len as libc::c_int,
                    ),
                );
            }
            if status as u64 != 0 {
                return srtp_err_status_cipher_fail;
            }
        }
        status = ((*(*(*session_keys).rtp_auth).type_0).start)
            .expect("non-null function pointer")((*(*session_keys).rtp_auth).state);
        if status as u64 != 0 {
            return status;
        }
        status = ((*(*(*session_keys).rtp_auth).type_0).update)
            .expect(
                "non-null function pointer",
            )(
            (*(*session_keys).rtp_auth).state,
            auth_start as *mut uint8_t,
            (*pkt_octet_len as libc::c_uint).wrapping_sub(tag_len).wrapping_sub(mki_size)
                as libc::c_int,
        );
        if status as u64 != 0 {
            return status;
        }
        status = ((*(*(*session_keys).rtp_auth).type_0).compute)
            .expect(
                "non-null function pointer",
            )(
            (*(*session_keys).rtp_auth).state,
            &mut est as *mut srtp_xtd_seq_num_t as *mut uint8_t,
            4 as libc::c_int,
            (*(*session_keys).rtp_auth).out_len,
            tmp_tag.as_mut_ptr(),
        );
        if mod_srtp.on != 0 {
            srtp_err_report(
                srtp_err_level_debug,
                b"%s: computed auth tag:    %s\n\0" as *const u8 as *const libc::c_char,
                mod_srtp.name,
                srtp_octet_string_hex_string(
                    tmp_tag.as_mut_ptr() as *const libc::c_void,
                    tag_len as libc::c_int,
                ),
            );
        }
        if mod_srtp.on != 0 {
            srtp_err_report(
                srtp_err_level_debug,
                b"%s: packet auth tag:      %s\n\0" as *const u8 as *const libc::c_char,
                mod_srtp.name,
                srtp_octet_string_hex_string(
                    auth_tag as *const libc::c_void,
                    tag_len as libc::c_int,
                ),
            );
        }
        if status as u64 != 0 {
            return srtp_err_status_auth_fail;
        }
        if srtp_octet_string_is_eq(
            tmp_tag.as_mut_ptr(),
            auth_tag,
            tag_len as libc::c_int,
        ) != 0
        {
            return srtp_err_status_auth_fail;
        }
    }
    match srtp_key_limit_update((*session_keys).limit) as libc::c_uint {
        1 => {
            if srtp_event_handler.is_some() {
                let mut data: srtp_event_data_t = srtp_event_data_t {
                    session: 0 as *mut srtp_ctx_t,
                    ssrc: 0,
                    event: event_ssrc_collision,
                };
                data.session = ctx;
                data.ssrc = __bswap_32((*stream).ssrc);
                data.event = event_key_soft_limit;
                srtp_event_handler.expect("non-null function pointer")(&mut data);
            }
        }
        2 => {
            if srtp_event_handler.is_some() {
                let mut data_0: srtp_event_data_t = srtp_event_data_t {
                    session: 0 as *mut srtp_ctx_t,
                    ssrc: 0,
                    event: event_ssrc_collision,
                };
                data_0.session = ctx;
                data_0.ssrc = __bswap_32((*stream).ssrc);
                data_0.event = event_key_hard_limit;
                srtp_event_handler.expect("non-null function pointer")(&mut data_0);
            }
            return srtp_err_status_key_expired;
        }
        0 | _ => {}
    }
    if !xtn_hdr.is_null() && !((*session_keys).rtp_xtn_hdr_cipher).is_null() {
        status = srtp_process_header_encryption(stream, xtn_hdr, session_keys);
        if status as u64 != 0 {
            return status;
        }
    }
    if !enc_start.is_null() {
        status = srtp_cipher_decrypt(
            (*session_keys).rtp_cipher,
            enc_start as *mut uint8_t,
            &mut enc_octet_len,
        );
        if status as u64 != 0 {
            return srtp_err_status_cipher_fail;
        }
    }
    if (*stream).direction as libc::c_uint
        != dir_srtp_receiver as libc::c_int as libc::c_uint
    {
        if (*stream).direction as libc::c_uint
            == dir_unknown as libc::c_int as libc::c_uint
        {
            (*stream).direction = dir_srtp_receiver;
        } else if srtp_event_handler.is_some() {
            let mut data_1: srtp_event_data_t = srtp_event_data_t {
                session: 0 as *mut srtp_ctx_t,
                ssrc: 0,
                event: event_ssrc_collision,
            };
            data_1.session = ctx;
            data_1.ssrc = __bswap_32((*stream).ssrc);
            data_1.event = event_ssrc_collision;
            srtp_event_handler.expect("non-null function pointer")(&mut data_1);
        }
    }
    if stream == (*ctx).stream_template {
        let mut new_stream: *mut srtp_stream_ctx_t = 0 as *mut srtp_stream_ctx_t;
        status = srtp_stream_clone((*ctx).stream_template, (*hdr).ssrc, &mut new_stream);
        if status as u64 != 0 {
            return status;
        }
        (*new_stream).next = (*ctx).stream_list;
        (*ctx).stream_list = new_stream;
        stream = new_stream;
    }
    if advance_packet_index != 0 {
        srtp_rdbx_set_roc_seq(&mut (*stream).rtp_rdbx, roc_to_set, seq_to_set);
        (*stream).pending_roc = 0 as libc::c_int as uint32_t;
        srtp_rdbx_add_index(&mut (*stream).rtp_rdbx, 0 as libc::c_int);
    } else {
        srtp_rdbx_add_index(&mut (*stream).rtp_rdbx, delta);
    }
    *pkt_octet_len = (*pkt_octet_len as libc::c_uint).wrapping_sub(tag_len)
        as libc::c_int as libc::c_int;
    *pkt_octet_len = (*pkt_octet_len as libc::c_uint).wrapping_sub(mki_size)
        as libc::c_int as libc::c_int;
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_init() -> srtp_err_status_t {
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    status = srtp_crypto_kernel_init();
    if status as u64 != 0 {
        return status;
    }
    status = srtp_crypto_kernel_load_debug_module(&mut mod_srtp);
    if status as u64 != 0 {
        return status;
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_shutdown() -> srtp_err_status_t {
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    status = srtp_crypto_kernel_shutdown();
    if status as u64 != 0 {
        return status;
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_get_stream(
    mut srtp: srtp_t,
    mut ssrc: uint32_t,
) -> srtp_stream_t {
    let mut stream: *mut srtp_stream_ctx_t = 0 as *mut srtp_stream_ctx_t;
    stream = (*srtp).stream_list;
    while !stream.is_null() {
        if (*stream).ssrc == ssrc {
            return stream;
        }
        stream = (*stream).next;
    }
    return 0 as srtp_stream_t;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_dealloc(mut session: srtp_t) -> srtp_err_status_t {
    let mut stream: *mut srtp_stream_ctx_t = 0 as *mut srtp_stream_ctx_t;
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    stream = (*session).stream_list;
    while !stream.is_null() {
        let mut next: srtp_stream_t = (*stream).next;
        status = srtp_stream_dealloc(stream, (*session).stream_template);
        if status as u64 != 0 {
            return status;
        }
        stream = next;
    }
    if !((*session).stream_template).is_null() {
        status = srtp_stream_dealloc(
            (*session).stream_template,
            0 as *const srtp_stream_ctx_t,
        );
        if status as u64 != 0 {
            return status;
        }
    }
    srtp_crypto_free(session as *mut libc::c_void);
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_add_stream(
    mut session: srtp_t,
    mut policy: *const srtp_policy_t,
) -> srtp_err_status_t {
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut tmp: srtp_stream_t = 0 as *mut srtp_stream_ctx_t;
    status = srtp_valid_policy(policy);
    if status as libc::c_uint != srtp_err_status_ok as libc::c_int as libc::c_uint {
        return status;
    }
    if session.is_null() || policy.is_null()
        || srtp_validate_policy_master_keys(policy) == 0
    {
        return srtp_err_status_bad_param;
    }
    status = srtp_stream_alloc(&mut tmp, policy);
    if status as u64 != 0 {
        return status;
    }
    status = srtp_stream_init(tmp, policy);
    if status as u64 != 0 {
        srtp_stream_dealloc(tmp, 0 as *const srtp_stream_ctx_t);
        return status;
    }
    match (*policy).ssrc.type_0 as libc::c_uint {
        3 => {
            if !((*session).stream_template).is_null() {
                srtp_stream_dealloc(tmp, 0 as *const srtp_stream_ctx_t);
                return srtp_err_status_bad_param;
            }
            (*session).stream_template = tmp;
            (*(*session).stream_template).direction = dir_srtp_sender;
        }
        2 => {
            if !((*session).stream_template).is_null() {
                srtp_stream_dealloc(tmp, 0 as *const srtp_stream_ctx_t);
                return srtp_err_status_bad_param;
            }
            (*session).stream_template = tmp;
            (*(*session).stream_template).direction = dir_srtp_receiver;
        }
        1 => {
            (*tmp).next = (*session).stream_list;
            (*session).stream_list = tmp;
        }
        0 | _ => {
            srtp_stream_dealloc(tmp, 0 as *const srtp_stream_ctx_t);
            return srtp_err_status_bad_param;
        }
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_create(
    mut session: *mut srtp_t,
    mut policy: *const srtp_policy_t,
) -> srtp_err_status_t {
    let mut stat: srtp_err_status_t = srtp_err_status_ok;
    let mut ctx: *mut srtp_ctx_t = 0 as *mut srtp_ctx_t;
    stat = srtp_valid_policy(policy);
    if stat as libc::c_uint != srtp_err_status_ok as libc::c_int as libc::c_uint {
        return stat;
    }
    if session.is_null() {
        return srtp_err_status_bad_param;
    }
    ctx = srtp_crypto_alloc(::core::mem::size_of::<srtp_ctx_t>() as libc::c_ulong)
        as *mut srtp_ctx_t;
    if ctx.is_null() {
        return srtp_err_status_alloc_fail;
    }
    *session = ctx;
    (*ctx).stream_template = 0 as *mut srtp_stream_ctx_t_;
    (*ctx).stream_list = 0 as *mut srtp_stream_ctx_t_;
    (*ctx).user_data = 0 as *mut libc::c_void;
    while !policy.is_null() {
        stat = srtp_add_stream(ctx, policy);
        if stat as u64 != 0 {
            srtp_dealloc(*session);
            *session = 0 as srtp_t;
            return stat;
        }
        policy = (*policy).next;
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_remove_stream(
    mut session: srtp_t,
    mut ssrc: uint32_t,
) -> srtp_err_status_t {
    let mut stream: *mut srtp_stream_ctx_t = 0 as *mut srtp_stream_ctx_t;
    let mut last_stream: *mut srtp_stream_ctx_t = 0 as *mut srtp_stream_ctx_t;
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    if session.is_null() {
        return srtp_err_status_bad_param;
    }
    stream = (*session).stream_list;
    last_stream = stream;
    while !stream.is_null() && ssrc != (*stream).ssrc {
        last_stream = stream;
        stream = (*stream).next;
    }
    if stream.is_null() {
        return srtp_err_status_no_ctx;
    }
    if last_stream == stream {
        (*session).stream_list = (*stream).next;
    } else {
        (*last_stream).next = (*stream).next;
    }
    status = srtp_stream_dealloc(stream, (*session).stream_template);
    if status as u64 != 0 {
        return status;
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_update(
    mut session: srtp_t,
    mut policy: *const srtp_policy_t,
) -> srtp_err_status_t {
    let mut stat: srtp_err_status_t = srtp_err_status_ok;
    stat = srtp_valid_policy(policy);
    if stat as libc::c_uint != srtp_err_status_ok as libc::c_int as libc::c_uint {
        return stat;
    }
    if session.is_null() || policy.is_null()
        || srtp_validate_policy_master_keys(policy) == 0
    {
        return srtp_err_status_bad_param;
    }
    while !policy.is_null() {
        stat = srtp_update_stream(session, policy);
        if stat as u64 != 0 {
            return stat;
        }
        policy = (*policy).next;
    }
    return srtp_err_status_ok;
}
unsafe extern "C" fn update_template_streams(
    mut session: srtp_t,
    mut policy: *const srtp_policy_t,
) -> srtp_err_status_t {
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut new_stream_template: srtp_stream_t = 0 as *mut srtp_stream_ctx_t;
    let mut new_stream_list: srtp_stream_t = 0 as srtp_stream_t;
    status = srtp_valid_policy(policy);
    if status as libc::c_uint != srtp_err_status_ok as libc::c_int as libc::c_uint {
        return status;
    }
    if ((*session).stream_template).is_null() {
        return srtp_err_status_bad_param;
    }
    status = srtp_stream_alloc(&mut new_stream_template, policy);
    if status as u64 != 0 {
        return status;
    }
    status = srtp_stream_init(new_stream_template, policy);
    if status as u64 != 0 {
        srtp_crypto_free(new_stream_template as *mut libc::c_void);
        return status;
    }
    loop {
        let mut stream: srtp_stream_t = 0 as *mut srtp_stream_ctx_t;
        let mut ssrc: uint32_t = 0;
        let mut old_index: srtp_xtd_seq_num_t = 0;
        let mut old_rtcp_rdb: srtp_rdb_t = srtp_rdb_t {
            window_start: 0,
            bitmask: v128_t { v8: [0; 16] },
        };
        stream = (*session).stream_list;
        while !stream.is_null()
            && (*((*stream).session_keys).offset(0 as libc::c_int as isize)).rtp_auth
                != (*((*(*session).stream_template).session_keys)
                    .offset(0 as libc::c_int as isize))
                    .rtp_auth
        {
            stream = (*stream).next;
        }
        if stream.is_null() {
            break;
        }
        ssrc = (*stream).ssrc;
        old_index = (*stream).rtp_rdbx.index;
        old_rtcp_rdb = (*stream).rtcp_rdb;
        status = srtp_remove_stream(session, ssrc);
        if status as u64 != 0 {
            while !new_stream_list.is_null() {
                let mut next: srtp_stream_t = (*new_stream_list).next;
                srtp_stream_dealloc(
                    new_stream_list,
                    new_stream_template as *const srtp_stream_ctx_t,
                );
                new_stream_list = next;
            }
            srtp_stream_dealloc(new_stream_template, 0 as *const srtp_stream_ctx_t);
            return status;
        }
        status = srtp_stream_clone(
            new_stream_template as *const srtp_stream_ctx_t,
            ssrc,
            &mut stream,
        );
        if status as u64 != 0 {
            while !new_stream_list.is_null() {
                let mut next_0: srtp_stream_t = (*new_stream_list).next;
                srtp_stream_dealloc(
                    new_stream_list,
                    new_stream_template as *const srtp_stream_ctx_t,
                );
                new_stream_list = next_0;
            }
            srtp_stream_dealloc(new_stream_template, 0 as *const srtp_stream_ctx_t);
            return status;
        }
        (*stream).next = new_stream_list;
        new_stream_list = stream;
        (*stream).rtp_rdbx.index = old_index;
        (*stream).rtcp_rdb = old_rtcp_rdb;
    }
    srtp_stream_dealloc((*session).stream_template, 0 as *const srtp_stream_ctx_t);
    (*session).stream_template = new_stream_template;
    if !new_stream_list.is_null() {
        let mut tail: srtp_stream_t = new_stream_list;
        while !((*tail).next).is_null() {
            tail = (*tail).next;
        }
        (*tail).next = (*session).stream_list;
        (*session).stream_list = new_stream_list;
    }
    return status;
}
unsafe extern "C" fn update_stream(
    mut session: srtp_t,
    mut policy: *const srtp_policy_t,
) -> srtp_err_status_t {
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut old_index: srtp_xtd_seq_num_t = 0;
    let mut old_rtcp_rdb: srtp_rdb_t = srtp_rdb_t {
        window_start: 0,
        bitmask: v128_t { v8: [0; 16] },
    };
    let mut stream: srtp_stream_t = 0 as *mut srtp_stream_ctx_t;
    status = srtp_valid_policy(policy);
    if status as libc::c_uint != srtp_err_status_ok as libc::c_int as libc::c_uint {
        return status;
    }
    stream = srtp_get_stream(session, __bswap_32((*policy).ssrc.value));
    if stream.is_null() {
        return srtp_err_status_bad_param;
    }
    old_index = (*stream).rtp_rdbx.index;
    old_rtcp_rdb = (*stream).rtcp_rdb;
    status = srtp_remove_stream(session, __bswap_32((*policy).ssrc.value));
    if status as u64 != 0 {
        return status;
    }
    status = srtp_add_stream(session, policy);
    if status as u64 != 0 {
        return status;
    }
    stream = srtp_get_stream(session, __bswap_32((*policy).ssrc.value));
    if stream.is_null() {
        return srtp_err_status_fail;
    }
    (*stream).rtp_rdbx.index = old_index;
    (*stream).rtcp_rdb = old_rtcp_rdb;
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_update_stream(
    mut session: srtp_t,
    mut policy: *const srtp_policy_t,
) -> srtp_err_status_t {
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    status = srtp_valid_policy(policy);
    if status as libc::c_uint != srtp_err_status_ok as libc::c_int as libc::c_uint {
        return status;
    }
    if session.is_null() || policy.is_null()
        || srtp_validate_policy_master_keys(policy) == 0
    {
        return srtp_err_status_bad_param;
    }
    match (*policy).ssrc.type_0 as libc::c_uint {
        3 | 2 => {
            status = update_template_streams(session, policy);
        }
        1 => {
            status = update_stream(session, policy);
        }
        0 | _ => return srtp_err_status_bad_param,
    }
    return status;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_crypto_policy_set_rtp_default(
    mut p: *mut srtp_crypto_policy_t,
) {
    (*p).cipher_type = 1 as libc::c_int as srtp_cipher_type_id_t;
    (*p).cipher_key_len = 14 as libc::c_int + 16 as libc::c_int;
    (*p).auth_type = 3 as libc::c_int as srtp_auth_type_id_t;
    (*p).auth_key_len = 20 as libc::c_int;
    (*p).auth_tag_len = 10 as libc::c_int;
    (*p).sec_serv = sec_serv_conf_and_auth;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_crypto_policy_set_rtcp_default(
    mut p: *mut srtp_crypto_policy_t,
) {
    (*p).cipher_type = 1 as libc::c_int as srtp_cipher_type_id_t;
    (*p).cipher_key_len = 14 as libc::c_int + 16 as libc::c_int;
    (*p).auth_type = 3 as libc::c_int as srtp_auth_type_id_t;
    (*p).auth_key_len = 20 as libc::c_int;
    (*p).auth_tag_len = 10 as libc::c_int;
    (*p).sec_serv = sec_serv_conf_and_auth;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(
    mut p: *mut srtp_crypto_policy_t,
) {
    (*p).cipher_type = 1 as libc::c_int as srtp_cipher_type_id_t;
    (*p).cipher_key_len = 14 as libc::c_int + 16 as libc::c_int;
    (*p).auth_type = 3 as libc::c_int as srtp_auth_type_id_t;
    (*p).auth_key_len = 20 as libc::c_int;
    (*p).auth_tag_len = 4 as libc::c_int;
    (*p).sec_serv = sec_serv_conf_and_auth;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_crypto_policy_set_aes_cm_128_null_auth(
    mut p: *mut srtp_crypto_policy_t,
) {
    (*p).cipher_type = 1 as libc::c_int as srtp_cipher_type_id_t;
    (*p).cipher_key_len = 14 as libc::c_int + 16 as libc::c_int;
    (*p).auth_type = 0 as libc::c_int as srtp_auth_type_id_t;
    (*p).auth_key_len = 0 as libc::c_int;
    (*p).auth_tag_len = 0 as libc::c_int;
    (*p).sec_serv = sec_serv_conf;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_crypto_policy_set_null_cipher_hmac_sha1_80(
    mut p: *mut srtp_crypto_policy_t,
) {
    (*p).cipher_type = 0 as libc::c_int as srtp_cipher_type_id_t;
    (*p).cipher_key_len = 14 as libc::c_int + 16 as libc::c_int;
    (*p).auth_type = 3 as libc::c_int as srtp_auth_type_id_t;
    (*p).auth_key_len = 20 as libc::c_int;
    (*p).auth_tag_len = 10 as libc::c_int;
    (*p).sec_serv = sec_serv_auth;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_crypto_policy_set_null_cipher_hmac_null(
    mut p: *mut srtp_crypto_policy_t,
) {
    (*p).cipher_type = 0 as libc::c_int as srtp_cipher_type_id_t;
    (*p).cipher_key_len = 14 as libc::c_int + 16 as libc::c_int;
    (*p).auth_type = 0 as libc::c_int as srtp_auth_type_id_t;
    (*p).auth_key_len = 0 as libc::c_int;
    (*p).auth_tag_len = 0 as libc::c_int;
    (*p).sec_serv = sec_serv_none;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80(
    mut p: *mut srtp_crypto_policy_t,
) {
    (*p).cipher_type = 5 as libc::c_int as srtp_cipher_type_id_t;
    (*p).cipher_key_len = 14 as libc::c_int + 32 as libc::c_int;
    (*p).auth_type = 3 as libc::c_int as srtp_auth_type_id_t;
    (*p).auth_key_len = 20 as libc::c_int;
    (*p).auth_tag_len = 10 as libc::c_int;
    (*p).sec_serv = sec_serv_conf_and_auth;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_crypto_policy_set_aes_cm_256_hmac_sha1_32(
    mut p: *mut srtp_crypto_policy_t,
) {
    (*p).cipher_type = 5 as libc::c_int as srtp_cipher_type_id_t;
    (*p).cipher_key_len = 14 as libc::c_int + 32 as libc::c_int;
    (*p).auth_type = 3 as libc::c_int as srtp_auth_type_id_t;
    (*p).auth_key_len = 20 as libc::c_int;
    (*p).auth_tag_len = 4 as libc::c_int;
    (*p).sec_serv = sec_serv_conf_and_auth;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_crypto_policy_set_aes_cm_256_null_auth(
    mut p: *mut srtp_crypto_policy_t,
) {
    (*p).cipher_type = 5 as libc::c_int as srtp_cipher_type_id_t;
    (*p).cipher_key_len = 14 as libc::c_int + 32 as libc::c_int;
    (*p).auth_type = 0 as libc::c_int as srtp_auth_type_id_t;
    (*p).auth_key_len = 0 as libc::c_int;
    (*p).auth_tag_len = 0 as libc::c_int;
    (*p).sec_serv = sec_serv_conf;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_crypto_policy_set_aes_cm_192_hmac_sha1_80(
    mut p: *mut srtp_crypto_policy_t,
) {
    (*p).cipher_type = 4 as libc::c_int as srtp_cipher_type_id_t;
    (*p).cipher_key_len = 14 as libc::c_int + 24 as libc::c_int;
    (*p).auth_type = 3 as libc::c_int as srtp_auth_type_id_t;
    (*p).auth_key_len = 20 as libc::c_int;
    (*p).auth_tag_len = 10 as libc::c_int;
    (*p).sec_serv = sec_serv_conf_and_auth;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_crypto_policy_set_aes_cm_192_hmac_sha1_32(
    mut p: *mut srtp_crypto_policy_t,
) {
    (*p).cipher_type = 4 as libc::c_int as srtp_cipher_type_id_t;
    (*p).cipher_key_len = 14 as libc::c_int + 24 as libc::c_int;
    (*p).auth_type = 3 as libc::c_int as srtp_auth_type_id_t;
    (*p).auth_key_len = 20 as libc::c_int;
    (*p).auth_tag_len = 4 as libc::c_int;
    (*p).sec_serv = sec_serv_conf_and_auth;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_crypto_policy_set_aes_cm_192_null_auth(
    mut p: *mut srtp_crypto_policy_t,
) {
    (*p).cipher_type = 4 as libc::c_int as srtp_cipher_type_id_t;
    (*p).cipher_key_len = 14 as libc::c_int + 24 as libc::c_int;
    (*p).auth_type = 0 as libc::c_int as srtp_auth_type_id_t;
    (*p).auth_key_len = 0 as libc::c_int;
    (*p).auth_tag_len = 0 as libc::c_int;
    (*p).sec_serv = sec_serv_conf;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_crypto_policy_set_aes_gcm_128_8_auth(
    mut p: *mut srtp_crypto_policy_t,
) {
    (*p).cipher_type = 6 as libc::c_int as srtp_cipher_type_id_t;
    (*p).cipher_key_len = 12 as libc::c_int + 16 as libc::c_int;
    (*p).auth_type = 0 as libc::c_int as srtp_auth_type_id_t;
    (*p).auth_key_len = 0 as libc::c_int;
    (*p).auth_tag_len = 8 as libc::c_int;
    (*p).sec_serv = sec_serv_conf_and_auth;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_crypto_policy_set_aes_gcm_256_8_auth(
    mut p: *mut srtp_crypto_policy_t,
) {
    (*p).cipher_type = 7 as libc::c_int as srtp_cipher_type_id_t;
    (*p).cipher_key_len = 12 as libc::c_int + 32 as libc::c_int;
    (*p).auth_type = 0 as libc::c_int as srtp_auth_type_id_t;
    (*p).auth_key_len = 0 as libc::c_int;
    (*p).auth_tag_len = 8 as libc::c_int;
    (*p).sec_serv = sec_serv_conf_and_auth;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_crypto_policy_set_aes_gcm_128_8_only_auth(
    mut p: *mut srtp_crypto_policy_t,
) {
    (*p).cipher_type = 6 as libc::c_int as srtp_cipher_type_id_t;
    (*p).cipher_key_len = 12 as libc::c_int + 16 as libc::c_int;
    (*p).auth_type = 0 as libc::c_int as srtp_auth_type_id_t;
    (*p).auth_key_len = 0 as libc::c_int;
    (*p).auth_tag_len = 8 as libc::c_int;
    (*p).sec_serv = sec_serv_auth;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_crypto_policy_set_aes_gcm_256_8_only_auth(
    mut p: *mut srtp_crypto_policy_t,
) {
    (*p).cipher_type = 7 as libc::c_int as srtp_cipher_type_id_t;
    (*p).cipher_key_len = 12 as libc::c_int + 32 as libc::c_int;
    (*p).auth_type = 0 as libc::c_int as srtp_auth_type_id_t;
    (*p).auth_key_len = 0 as libc::c_int;
    (*p).auth_tag_len = 8 as libc::c_int;
    (*p).sec_serv = sec_serv_auth;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_crypto_policy_set_aes_gcm_128_16_auth(
    mut p: *mut srtp_crypto_policy_t,
) {
    (*p).cipher_type = 6 as libc::c_int as srtp_cipher_type_id_t;
    (*p).cipher_key_len = 12 as libc::c_int + 16 as libc::c_int;
    (*p).auth_type = 0 as libc::c_int as srtp_auth_type_id_t;
    (*p).auth_key_len = 0 as libc::c_int;
    (*p).auth_tag_len = 16 as libc::c_int;
    (*p).sec_serv = sec_serv_conf_and_auth;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_crypto_policy_set_aes_gcm_256_16_auth(
    mut p: *mut srtp_crypto_policy_t,
) {
    (*p).cipher_type = 7 as libc::c_int as srtp_cipher_type_id_t;
    (*p).cipher_key_len = 12 as libc::c_int + 32 as libc::c_int;
    (*p).auth_type = 0 as libc::c_int as srtp_auth_type_id_t;
    (*p).auth_key_len = 0 as libc::c_int;
    (*p).auth_tag_len = 16 as libc::c_int;
    (*p).sec_serv = sec_serv_conf_and_auth;
}
unsafe extern "C" fn srtp_calc_aead_iv_srtcp(
    mut session_keys: *mut srtp_session_keys_t,
    mut iv: *mut v128_t,
    mut seq_num: uint32_t,
    mut hdr: *mut srtcp_hdr_t,
) -> srtp_err_status_t {
    let mut in_0: v128_t = v128_t { v8: [0; 16] };
    let mut salt: v128_t = v128_t { v8: [0; 16] };
    memset(
        &mut in_0 as *mut v128_t as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<v128_t>() as libc::c_ulong,
    );
    memset(
        &mut salt as *mut v128_t as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<v128_t>() as libc::c_ulong,
    );
    in_0.v16[0 as libc::c_int as usize] = 0 as libc::c_int as uint16_t;
    memcpy(
        &mut *(in_0.v16).as_mut_ptr().offset(1 as libc::c_int as isize) as *mut uint16_t
            as *mut libc::c_void,
        &mut (*hdr).ssrc as *mut uint32_t as *const libc::c_void,
        4 as libc::c_int as libc::c_ulong,
    );
    in_0.v16[3 as libc::c_int as usize] = 0 as libc::c_int as uint16_t;
    if seq_num as libc::c_ulong & 0x80000000 as libc::c_ulong != 0 {
        return srtp_err_status_bad_param;
    }
    in_0.v32[2 as libc::c_int as usize] = __bswap_32(seq_num);
    if mod_srtp.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: Pre-salted RTCP IV = %s\n\n\0" as *const u8 as *const libc::c_char,
            mod_srtp.name,
            v128_hex_string(&mut in_0),
        );
    }
    memcpy(
        (salt.v8).as_mut_ptr() as *mut libc::c_void,
        ((*session_keys).c_salt).as_mut_ptr() as *const libc::c_void,
        12 as libc::c_int as libc::c_ulong,
    );
    if mod_srtp.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: RTCP SALT = %s\n\n\0" as *const u8 as *const libc::c_char,
            mod_srtp.name,
            v128_hex_string(&mut salt),
        );
    }
    (*iv)
        .v32[0 as libc::c_int
        as usize] = in_0.v32[0 as libc::c_int as usize]
        ^ salt.v32[0 as libc::c_int as usize];
    (*iv)
        .v32[1 as libc::c_int
        as usize] = in_0.v32[1 as libc::c_int as usize]
        ^ salt.v32[1 as libc::c_int as usize];
    (*iv)
        .v32[2 as libc::c_int
        as usize] = in_0.v32[2 as libc::c_int as usize]
        ^ salt.v32[2 as libc::c_int as usize];
    (*iv)
        .v32[3 as libc::c_int
        as usize] = in_0.v32[3 as libc::c_int as usize]
        ^ salt.v32[3 as libc::c_int as usize];
    return srtp_err_status_ok;
}
unsafe extern "C" fn srtp_protect_rtcp_aead(
    mut stream: *mut srtp_stream_ctx_t,
    mut rtcp_hdr: *mut libc::c_void,
    mut pkt_octet_len: *mut libc::c_uint,
    mut session_keys: *mut srtp_session_keys_t,
    mut use_mki: libc::c_uint,
) -> srtp_err_status_t {
    let mut hdr: *mut srtcp_hdr_t = rtcp_hdr as *mut srtcp_hdr_t;
    let mut enc_start: *mut uint32_t = 0 as *mut uint32_t;
    let mut trailer_p: *mut uint32_t = 0 as *mut uint32_t;
    let mut trailer: uint32_t = 0;
    let mut enc_octet_len: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut auth_tag: *mut uint8_t = 0 as *mut uint8_t;
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut tag_len: uint32_t = 0;
    let mut seq_num: uint32_t = 0;
    let mut iv: v128_t = v128_t { v8: [0; 16] };
    let mut tseq: uint32_t = 0;
    let mut mki_size: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    tag_len = srtp_auth_get_tag_length((*session_keys).rtcp_auth) as uint32_t;
    enc_start = (hdr as *mut uint32_t).offset(2 as libc::c_int as isize);
    enc_octet_len = (*pkt_octet_len).wrapping_sub(8 as libc::c_int as libc::c_uint);
    trailer_p = (enc_start as *mut libc::c_char)
        .offset(enc_octet_len as isize)
        .offset(tag_len as isize) as *mut uint32_t;
    if (*stream).rtcp_services as libc::c_uint
        & sec_serv_conf as libc::c_int as libc::c_uint != 0
    {
        trailer = __bswap_32(0x80000000 as libc::c_uint);
    } else {
        enc_start = 0 as *mut uint32_t;
        enc_octet_len = 0 as libc::c_int as libc::c_uint;
        trailer = 0 as libc::c_int as uint32_t;
    }
    mki_size = srtp_inject_mki(
        (hdr as *mut uint8_t)
            .offset(*pkt_octet_len as isize)
            .offset(tag_len as isize)
            .offset(::core::mem::size_of::<srtcp_trailer_t>() as libc::c_ulong as isize),
        session_keys,
        use_mki,
    );
    auth_tag = (hdr as *mut uint8_t).offset(*pkt_octet_len as isize);
    status = srtp_rdb_increment(&mut (*stream).rtcp_rdb);
    if status as u64 != 0 {
        return status;
    }
    seq_num = srtp_rdb_get_value(&mut (*stream).rtcp_rdb);
    trailer |= __bswap_32(seq_num);
    if mod_srtp.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: srtcp index: %x\n\0" as *const u8 as *const libc::c_char,
            mod_srtp.name,
            seq_num,
        );
    }
    memcpy(
        trailer_p as *mut libc::c_void,
        &mut trailer as *mut uint32_t as *const libc::c_void,
        ::core::mem::size_of::<uint32_t>() as libc::c_ulong,
    );
    status = srtp_calc_aead_iv_srtcp(session_keys, &mut iv, seq_num, hdr);
    if status as u64 != 0 {
        return srtp_err_status_cipher_fail;
    }
    status = srtp_cipher_set_iv(
        (*session_keys).rtcp_cipher,
        &mut iv as *mut v128_t as *mut uint8_t,
        srtp_direction_encrypt as libc::c_int,
    );
    if status as u64 != 0 {
        return srtp_err_status_cipher_fail;
    }
    if !enc_start.is_null() {
        status = srtp_cipher_set_aad(
            (*session_keys).rtcp_cipher,
            hdr as *mut uint8_t,
            8 as libc::c_int as uint32_t,
        );
        if status as u64 != 0 {
            return srtp_err_status_cipher_fail;
        }
    } else {
        status = srtp_cipher_set_aad(
            (*session_keys).rtcp_cipher,
            hdr as *mut uint8_t,
            *pkt_octet_len,
        );
        if status as u64 != 0 {
            return srtp_err_status_cipher_fail;
        }
    }
    tseq = trailer;
    status = srtp_cipher_set_aad(
        (*session_keys).rtcp_cipher,
        &mut tseq as *mut uint32_t as *mut uint8_t,
        ::core::mem::size_of::<srtcp_trailer_t>() as libc::c_ulong as uint32_t,
    );
    if status as u64 != 0 {
        return srtp_err_status_cipher_fail;
    }
    if !enc_start.is_null() {
        status = srtp_cipher_encrypt(
            (*session_keys).rtcp_cipher,
            enc_start as *mut uint8_t,
            &mut enc_octet_len,
        );
        if status as u64 != 0 {
            return srtp_err_status_cipher_fail;
        }
        status = srtp_cipher_get_tag(
            (*session_keys).rtcp_cipher,
            auth_tag,
            &mut tag_len,
        );
        if status as u64 != 0 {
            return srtp_err_status_cipher_fail;
        }
        enc_octet_len = enc_octet_len.wrapping_add(tag_len);
    } else {
        let mut nolen: libc::c_uint = 0 as libc::c_int as libc::c_uint;
        status = srtp_cipher_encrypt(
            (*session_keys).rtcp_cipher,
            0 as *mut uint8_t,
            &mut nolen,
        );
        if status as u64 != 0 {
            return srtp_err_status_cipher_fail;
        }
        status = srtp_cipher_get_tag(
            (*session_keys).rtcp_cipher,
            auth_tag,
            &mut tag_len,
        );
        if status as u64 != 0 {
            return srtp_err_status_cipher_fail;
        }
        enc_octet_len = enc_octet_len.wrapping_add(tag_len);
    }
    *pkt_octet_len = (*pkt_octet_len as libc::c_ulong)
        .wrapping_add(
            (tag_len as libc::c_ulong)
                .wrapping_add(::core::mem::size_of::<srtcp_trailer_t>() as libc::c_ulong),
        ) as libc::c_uint as libc::c_uint;
    *pkt_octet_len = (*pkt_octet_len).wrapping_add(mki_size);
    return srtp_err_status_ok;
}
unsafe extern "C" fn srtp_unprotect_rtcp_aead(
    mut ctx: srtp_t,
    mut stream: *mut srtp_stream_ctx_t,
    mut srtcp_hdr: *mut libc::c_void,
    mut pkt_octet_len: *mut libc::c_uint,
    mut session_keys: *mut srtp_session_keys_t,
    mut use_mki: libc::c_uint,
) -> srtp_err_status_t {
    let mut hdr: *mut srtcp_hdr_t = srtcp_hdr as *mut srtcp_hdr_t;
    let mut enc_start: *mut uint32_t = 0 as *mut uint32_t;
    let mut trailer_p: *mut uint32_t = 0 as *mut uint32_t;
    let mut trailer: uint32_t = 0;
    let mut enc_octet_len: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut auth_tag: *mut uint8_t = 0 as *mut uint8_t;
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut tag_len: libc::c_int = 0;
    let mut tmp_len: libc::c_uint = 0;
    let mut seq_num: uint32_t = 0;
    let mut iv: v128_t = v128_t { v8: [0; 16] };
    let mut tseq: uint32_t = 0;
    let mut mki_size: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    tag_len = srtp_auth_get_tag_length((*session_keys).rtcp_auth);
    if use_mki != 0 {
        mki_size = (*session_keys).mki_size;
    }
    trailer_p = (hdr as *mut libc::c_char)
        .offset(*pkt_octet_len as isize)
        .offset(-(::core::mem::size_of::<srtcp_trailer_t>() as libc::c_ulong as isize))
        .offset(-(mki_size as isize)) as *mut uint32_t;
    memcpy(
        &mut trailer as *mut uint32_t as *mut libc::c_void,
        trailer_p as *const libc::c_void,
        ::core::mem::size_of::<uint32_t>() as libc::c_ulong,
    );
    enc_octet_len = (*pkt_octet_len as libc::c_ulong)
        .wrapping_sub(
            (8 as libc::c_int as libc::c_ulong)
                .wrapping_add(::core::mem::size_of::<srtcp_trailer_t>() as libc::c_ulong)
                .wrapping_add(mki_size as libc::c_ulong),
        ) as libc::c_uint;
    auth_tag = (hdr as *mut uint8_t)
        .offset(*pkt_octet_len as isize)
        .offset(-(tag_len as isize))
        .offset(-(mki_size as isize))
        .offset(-(::core::mem::size_of::<srtcp_trailer_t>() as libc::c_ulong as isize));
    if *(trailer_p as *mut libc::c_uchar) as libc::c_int & 0x80 as libc::c_int != 0 {
        enc_start = (hdr as *mut uint32_t).offset(2 as libc::c_int as isize);
    } else {
        enc_octet_len = 0 as libc::c_int as libc::c_uint;
        enc_start = 0 as *mut uint32_t;
    }
    seq_num = __bswap_32(trailer) & 0x7fffffff as libc::c_int as libc::c_uint;
    if mod_srtp.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: srtcp index: %x\n\0" as *const u8 as *const libc::c_char,
            mod_srtp.name,
            seq_num,
        );
    }
    status = srtp_rdb_check(&mut (*stream).rtcp_rdb, seq_num);
    if status as u64 != 0 {
        return status;
    }
    status = srtp_calc_aead_iv_srtcp(session_keys, &mut iv, seq_num, hdr);
    if status as u64 != 0 {
        return srtp_err_status_cipher_fail;
    }
    status = srtp_cipher_set_iv(
        (*session_keys).rtcp_cipher,
        &mut iv as *mut v128_t as *mut uint8_t,
        srtp_direction_decrypt as libc::c_int,
    );
    if status as u64 != 0 {
        return srtp_err_status_cipher_fail;
    }
    if !enc_start.is_null() {
        status = srtp_cipher_set_aad(
            (*session_keys).rtcp_cipher,
            hdr as *mut uint8_t,
            8 as libc::c_int as uint32_t,
        );
        if status as u64 != 0 {
            return srtp_err_status_cipher_fail;
        }
    } else {
        status = srtp_cipher_set_aad(
            (*session_keys).rtcp_cipher,
            hdr as *mut uint8_t,
            ((*pkt_octet_len).wrapping_sub(tag_len as libc::c_uint) as libc::c_ulong)
                .wrapping_sub(::core::mem::size_of::<srtcp_trailer_t>() as libc::c_ulong)
                .wrapping_sub(mki_size as libc::c_ulong) as uint32_t,
        );
        if status as u64 != 0 {
            return srtp_err_status_cipher_fail;
        }
    }
    tseq = trailer;
    status = srtp_cipher_set_aad(
        (*session_keys).rtcp_cipher,
        &mut tseq as *mut uint32_t as *mut uint8_t,
        ::core::mem::size_of::<srtcp_trailer_t>() as libc::c_ulong as uint32_t,
    );
    if status as u64 != 0 {
        return srtp_err_status_cipher_fail;
    }
    if !enc_start.is_null() {
        status = srtp_cipher_decrypt(
            (*session_keys).rtcp_cipher,
            enc_start as *mut uint8_t,
            &mut enc_octet_len,
        );
        if status as u64 != 0 {
            return status;
        }
    } else {
        tmp_len = tag_len as libc::c_uint;
        status = srtp_cipher_decrypt(
            (*session_keys).rtcp_cipher,
            auth_tag,
            &mut tmp_len,
        );
        if status as u64 != 0 {
            return status;
        }
    }
    *pkt_octet_len = (*pkt_octet_len as libc::c_ulong)
        .wrapping_sub(
            (tag_len as libc::c_ulong)
                .wrapping_add(::core::mem::size_of::<srtcp_trailer_t>() as libc::c_ulong)
                .wrapping_add(mki_size as libc::c_ulong),
        ) as libc::c_uint as libc::c_uint;
    if (*stream).direction as libc::c_uint
        != dir_srtp_receiver as libc::c_int as libc::c_uint
    {
        if (*stream).direction as libc::c_uint
            == dir_unknown as libc::c_int as libc::c_uint
        {
            (*stream).direction = dir_srtp_receiver;
        } else if srtp_event_handler.is_some() {
            let mut data: srtp_event_data_t = srtp_event_data_t {
                session: 0 as *mut srtp_ctx_t,
                ssrc: 0,
                event: event_ssrc_collision,
            };
            data.session = ctx;
            data.ssrc = __bswap_32((*stream).ssrc);
            data.event = event_ssrc_collision;
            srtp_event_handler.expect("non-null function pointer")(&mut data);
        }
    }
    if stream == (*ctx).stream_template {
        let mut new_stream: *mut srtp_stream_ctx_t = 0 as *mut srtp_stream_ctx_t;
        status = srtp_stream_clone((*ctx).stream_template, (*hdr).ssrc, &mut new_stream);
        if status as u64 != 0 {
            return status;
        }
        (*new_stream).next = (*ctx).stream_list;
        (*ctx).stream_list = new_stream;
        stream = new_stream;
    }
    srtp_rdb_add_index(&mut (*stream).rtcp_rdb, seq_num);
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_protect_rtcp(
    mut ctx: srtp_t,
    mut rtcp_hdr: *mut libc::c_void,
    mut pkt_octet_len: *mut libc::c_int,
) -> srtp_err_status_t {
    return srtp_protect_rtcp_mki(
        ctx,
        rtcp_hdr,
        pkt_octet_len,
        0 as libc::c_int as libc::c_uint,
        0 as libc::c_int as libc::c_uint,
    );
}
#[no_mangle]
pub unsafe extern "C" fn srtp_protect_rtcp_mki(
    mut ctx: srtp_t,
    mut rtcp_hdr: *mut libc::c_void,
    mut pkt_octet_len: *mut libc::c_int,
    mut use_mki: libc::c_uint,
    mut mki_index: libc::c_uint,
) -> srtp_err_status_t {
    let mut hdr: *mut srtcp_hdr_t = rtcp_hdr as *mut srtcp_hdr_t;
    let mut enc_start: *mut uint32_t = 0 as *mut uint32_t;
    let mut auth_start: *mut uint32_t = 0 as *mut uint32_t;
    let mut trailer_p: *mut uint32_t = 0 as *mut uint32_t;
    let mut trailer: uint32_t = 0;
    let mut enc_octet_len: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut auth_tag: *mut uint8_t = 0 as *mut uint8_t;
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut tag_len: libc::c_int = 0;
    let mut stream: *mut srtp_stream_ctx_t = 0 as *mut srtp_stream_ctx_t;
    let mut prefix_len: uint32_t = 0;
    let mut seq_num: uint32_t = 0;
    let mut mki_size: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut session_keys: *mut srtp_session_keys_t = 0 as *mut srtp_session_keys_t;
    if *pkt_octet_len < 8 as libc::c_int {
        return srtp_err_status_bad_param;
    }
    stream = srtp_get_stream(ctx, (*hdr).ssrc);
    if stream.is_null() {
        if !((*ctx).stream_template).is_null() {
            let mut new_stream: *mut srtp_stream_ctx_t = 0 as *mut srtp_stream_ctx_t;
            status = srtp_stream_clone(
                (*ctx).stream_template,
                (*hdr).ssrc,
                &mut new_stream,
            );
            if status as u64 != 0 {
                return status;
            }
            (*new_stream).next = (*ctx).stream_list;
            (*ctx).stream_list = new_stream;
            stream = new_stream;
        } else {
            return srtp_err_status_no_ctx
        }
    }
    if (*stream).direction as libc::c_uint
        != dir_srtp_sender as libc::c_int as libc::c_uint
    {
        if (*stream).direction as libc::c_uint
            == dir_unknown as libc::c_int as libc::c_uint
        {
            (*stream).direction = dir_srtp_sender;
        } else if srtp_event_handler.is_some() {
            let mut data: srtp_event_data_t = srtp_event_data_t {
                session: 0 as *mut srtp_ctx_t,
                ssrc: 0,
                event: event_ssrc_collision,
            };
            data.session = ctx;
            data.ssrc = __bswap_32((*stream).ssrc);
            data.event = event_ssrc_collision;
            srtp_event_handler.expect("non-null function pointer")(&mut data);
        }
    }
    session_keys = srtp_get_session_keys_with_mki_index(stream, use_mki, mki_index);
    if session_keys.is_null() {
        return srtp_err_status_bad_mki;
    }
    if (*(*session_keys).rtp_cipher).algorithm == 6 as libc::c_int
        || (*(*session_keys).rtp_cipher).algorithm == 7 as libc::c_int
    {
        return srtp_protect_rtcp_aead(
            stream,
            rtcp_hdr,
            pkt_octet_len as *mut libc::c_uint,
            session_keys,
            use_mki,
        );
    }
    tag_len = srtp_auth_get_tag_length((*session_keys).rtcp_auth);
    enc_start = (hdr as *mut uint32_t).offset(2 as libc::c_int as isize);
    enc_octet_len = (*pkt_octet_len - 8 as libc::c_int) as libc::c_uint;
    trailer_p = (enc_start as *mut libc::c_char).offset(enc_octet_len as isize)
        as *mut uint32_t;
    if (*stream).rtcp_services as libc::c_uint
        & sec_serv_conf as libc::c_int as libc::c_uint != 0
    {
        trailer = __bswap_32(0x80000000 as libc::c_uint);
    } else {
        enc_start = 0 as *mut uint32_t;
        enc_octet_len = 0 as libc::c_int as libc::c_uint;
        trailer = 0 as libc::c_int as uint32_t;
    }
    mki_size = srtp_inject_mki(
        (hdr as *mut uint8_t)
            .offset(*pkt_octet_len as isize)
            .offset(::core::mem::size_of::<srtcp_trailer_t>() as libc::c_ulong as isize),
        session_keys,
        use_mki,
    );
    auth_start = hdr as *mut uint32_t;
    auth_tag = (hdr as *mut uint8_t)
        .offset(*pkt_octet_len as isize)
        .offset(::core::mem::size_of::<srtcp_trailer_t>() as libc::c_ulong as isize)
        .offset(mki_size as isize);
    status = srtp_rdb_increment(&mut (*stream).rtcp_rdb);
    if status as u64 != 0 {
        return status;
    }
    seq_num = srtp_rdb_get_value(&mut (*stream).rtcp_rdb);
    trailer |= __bswap_32(seq_num);
    if mod_srtp.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: srtcp index: %x\n\0" as *const u8 as *const libc::c_char,
            mod_srtp.name,
            seq_num,
        );
    }
    memcpy(
        trailer_p as *mut libc::c_void,
        &mut trailer as *mut uint32_t as *const libc::c_void,
        ::core::mem::size_of::<uint32_t>() as libc::c_ulong,
    );
    if (*(*(*session_keys).rtcp_cipher).type_0).id == 1 as libc::c_int as libc::c_uint
        || (*(*(*session_keys).rtcp_cipher).type_0).id
            == 4 as libc::c_int as libc::c_uint
        || (*(*(*session_keys).rtcp_cipher).type_0).id
            == 5 as libc::c_int as libc::c_uint
    {
        let mut iv: v128_t = v128_t { v8: [0; 16] };
        iv.v32[0 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
        iv.v32[1 as libc::c_int as usize] = (*hdr).ssrc;
        iv.v32[2 as libc::c_int as usize] = __bswap_32(seq_num >> 16 as libc::c_int);
        iv.v32[3 as libc::c_int as usize] = __bswap_32(seq_num << 16 as libc::c_int);
        status = srtp_cipher_set_iv(
            (*session_keys).rtcp_cipher,
            &mut iv as *mut v128_t as *mut uint8_t,
            srtp_direction_encrypt as libc::c_int,
        );
    } else {
        let mut iv_0: v128_t = v128_t { v8: [0; 16] };
        iv_0.v32[0 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
        iv_0.v32[1 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
        iv_0.v32[2 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
        iv_0.v32[3 as libc::c_int as usize] = __bswap_32(seq_num);
        status = srtp_cipher_set_iv(
            (*session_keys).rtcp_cipher,
            &mut iv_0 as *mut v128_t as *mut uint8_t,
            srtp_direction_encrypt as libc::c_int,
        );
    }
    if status as u64 != 0 {
        return srtp_err_status_cipher_fail;
    }
    if !auth_start.is_null() {
        prefix_len = srtp_auth_get_prefix_length((*session_keys).rtcp_auth) as uint32_t;
        status = srtp_cipher_output(
            (*session_keys).rtcp_cipher,
            auth_tag,
            &mut prefix_len,
        );
        if mod_srtp.on != 0 {
            srtp_err_report(
                srtp_err_level_debug,
                b"%s: keystream prefix: %s\n\0" as *const u8 as *const libc::c_char,
                mod_srtp.name,
                srtp_octet_string_hex_string(
                    auth_tag as *const libc::c_void,
                    prefix_len as libc::c_int,
                ),
            );
        }
        if status as u64 != 0 {
            return srtp_err_status_cipher_fail;
        }
    }
    if !enc_start.is_null() {
        status = srtp_cipher_encrypt(
            (*session_keys).rtcp_cipher,
            enc_start as *mut uint8_t,
            &mut enc_octet_len,
        );
        if status as u64 != 0 {
            return srtp_err_status_cipher_fail;
        }
    }
    status = ((*(*(*session_keys).rtcp_auth).type_0).start)
        .expect("non-null function pointer")((*(*session_keys).rtcp_auth).state);
    if status as u64 != 0 {
        return status;
    }
    status = ((*(*(*session_keys).rtcp_auth).type_0).compute)
        .expect(
            "non-null function pointer",
        )(
        (*(*session_keys).rtcp_auth).state,
        auth_start as *mut uint8_t,
        (*pkt_octet_len as libc::c_ulong)
            .wrapping_add(::core::mem::size_of::<srtcp_trailer_t>() as libc::c_ulong)
            as libc::c_int,
        (*(*session_keys).rtcp_auth).out_len,
        auth_tag,
    );
    if mod_srtp.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: srtcp auth tag:    %s\n\0" as *const u8 as *const libc::c_char,
            mod_srtp.name,
            srtp_octet_string_hex_string(auth_tag as *const libc::c_void, tag_len),
        );
    }
    if status as u64 != 0 {
        return srtp_err_status_auth_fail;
    }
    *pkt_octet_len = (*pkt_octet_len as libc::c_ulong)
        .wrapping_add(
            (tag_len as libc::c_ulong)
                .wrapping_add(::core::mem::size_of::<srtcp_trailer_t>() as libc::c_ulong),
        ) as libc::c_int as libc::c_int;
    *pkt_octet_len = (*pkt_octet_len as libc::c_uint).wrapping_add(mki_size)
        as libc::c_int as libc::c_int;
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_unprotect_rtcp(
    mut ctx: srtp_t,
    mut srtcp_hdr: *mut libc::c_void,
    mut pkt_octet_len: *mut libc::c_int,
) -> srtp_err_status_t {
    return srtp_unprotect_rtcp_mki(
        ctx,
        srtcp_hdr,
        pkt_octet_len,
        0 as libc::c_int as libc::c_uint,
    );
}
#[no_mangle]
pub unsafe extern "C" fn srtp_unprotect_rtcp_mki(
    mut ctx: srtp_t,
    mut srtcp_hdr: *mut libc::c_void,
    mut pkt_octet_len: *mut libc::c_int,
    mut use_mki: libc::c_uint,
) -> srtp_err_status_t {
    let mut hdr: *mut srtcp_hdr_t = srtcp_hdr as *mut srtcp_hdr_t;
    let mut enc_start: *mut uint32_t = 0 as *mut uint32_t;
    let mut auth_start: *mut uint32_t = 0 as *mut uint32_t;
    let mut trailer_p: *mut uint32_t = 0 as *mut uint32_t;
    let mut trailer: uint32_t = 0;
    let mut enc_octet_len: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut auth_tag: *mut uint8_t = 0 as *mut uint8_t;
    let mut tmp_tag: [uint8_t; 16] = [0; 16];
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut auth_len: libc::c_uint = 0;
    let mut tag_len: libc::c_int = 0;
    let mut stream: *mut srtp_stream_ctx_t = 0 as *mut srtp_stream_ctx_t;
    let mut prefix_len: uint32_t = 0;
    let mut seq_num: uint32_t = 0;
    let mut e_bit_in_packet: libc::c_int = 0;
    let mut sec_serv_confidentiality: libc::c_int = 0;
    let mut mki_size: libc::c_uint = 0 as libc::c_int as libc::c_uint;
    let mut session_keys: *mut srtp_session_keys_t = 0 as *mut srtp_session_keys_t;
    if *pkt_octet_len < 0 as libc::c_int {
        return srtp_err_status_bad_param;
    }
    if (*pkt_octet_len as libc::c_uint as libc::c_ulong)
        < (8 as libc::c_int as libc::c_ulong)
            .wrapping_add(::core::mem::size_of::<srtcp_trailer_t>() as libc::c_ulong)
    {
        return srtp_err_status_bad_param;
    }
    stream = srtp_get_stream(ctx, (*hdr).ssrc);
    if stream.is_null() {
        if !((*ctx).stream_template).is_null() {
            stream = (*ctx).stream_template;
            if mod_srtp.on != 0 {
                srtp_err_report(
                    srtp_err_level_debug,
                    b"%s: srtcp using provisional stream (SSRC: 0x%08x)\n\0" as *const u8
                        as *const libc::c_char,
                    mod_srtp.name,
                    __bswap_32((*hdr).ssrc),
                );
            }
        } else {
            return srtp_err_status_no_ctx
        }
    }
    if use_mki != 0 {
        session_keys = srtp_get_session_keys(
            stream,
            hdr as *mut uint8_t,
            pkt_octet_len as *const libc::c_uint,
            &mut mki_size,
        );
        if session_keys.is_null() {
            return srtp_err_status_bad_mki;
        }
    } else {
        session_keys = &mut *((*stream).session_keys).offset(0 as libc::c_int as isize)
            as *mut srtp_session_keys_t;
    }
    tag_len = srtp_auth_get_tag_length((*session_keys).rtcp_auth);
    if *pkt_octet_len
        < (((8 as libc::c_int + tag_len) as libc::c_uint).wrapping_add(mki_size)
            as libc::c_ulong)
            .wrapping_add(::core::mem::size_of::<srtcp_trailer_t>() as libc::c_ulong)
            as libc::c_int
    {
        return srtp_err_status_bad_param;
    }
    if (*(*session_keys).rtp_cipher).algorithm == 6 as libc::c_int
        || (*(*session_keys).rtp_cipher).algorithm == 7 as libc::c_int
    {
        return srtp_unprotect_rtcp_aead(
            ctx,
            stream,
            srtcp_hdr,
            pkt_octet_len as *mut libc::c_uint,
            session_keys,
            mki_size,
        );
    }
    sec_serv_confidentiality = ((*stream).rtcp_services as libc::c_uint
        == sec_serv_conf as libc::c_int as libc::c_uint
        || (*stream).rtcp_services as libc::c_uint
            == sec_serv_conf_and_auth as libc::c_int as libc::c_uint) as libc::c_int;
    enc_octet_len = (*pkt_octet_len as libc::c_ulong)
        .wrapping_sub(
            (((8 as libc::c_int + tag_len) as libc::c_uint).wrapping_add(mki_size)
                as libc::c_ulong)
                .wrapping_add(::core::mem::size_of::<srtcp_trailer_t>() as libc::c_ulong),
        ) as libc::c_uint;
    trailer_p = (hdr as *mut libc::c_char)
        .offset(*pkt_octet_len as isize)
        .offset(
            -(((tag_len as libc::c_uint).wrapping_add(mki_size) as libc::c_ulong)
                .wrapping_add(::core::mem::size_of::<srtcp_trailer_t>() as libc::c_ulong)
                as isize),
        ) as *mut uint32_t;
    memcpy(
        &mut trailer as *mut uint32_t as *mut libc::c_void,
        trailer_p as *const libc::c_void,
        ::core::mem::size_of::<uint32_t>() as libc::c_ulong,
    );
    e_bit_in_packet = (*(trailer_p as *mut libc::c_uchar) as libc::c_int
        & 0x80 as libc::c_int == 0x80 as libc::c_int) as libc::c_int;
    if e_bit_in_packet != sec_serv_confidentiality {
        return srtp_err_status_cant_check;
    }
    if sec_serv_confidentiality != 0 {
        enc_start = (hdr as *mut uint32_t).offset(2 as libc::c_int as isize);
    } else {
        enc_octet_len = 0 as libc::c_int as libc::c_uint;
        enc_start = 0 as *mut uint32_t;
    }
    auth_start = hdr as *mut uint32_t;
    auth_len = ((*pkt_octet_len - tag_len) as libc::c_uint).wrapping_sub(mki_size);
    auth_tag = (hdr as *mut uint8_t).offset(auth_len as isize).offset(mki_size as isize);
    seq_num = __bswap_32(trailer) & 0x7fffffff as libc::c_int as libc::c_uint;
    if mod_srtp.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: srtcp index: %x\n\0" as *const u8 as *const libc::c_char,
            mod_srtp.name,
            seq_num,
        );
    }
    status = srtp_rdb_check(&mut (*stream).rtcp_rdb, seq_num);
    if status as u64 != 0 {
        return status;
    }
    if (*(*(*session_keys).rtcp_cipher).type_0).id == 1 as libc::c_int as libc::c_uint
        || (*(*(*session_keys).rtcp_cipher).type_0).id
            == 4 as libc::c_int as libc::c_uint
        || (*(*(*session_keys).rtcp_cipher).type_0).id
            == 5 as libc::c_int as libc::c_uint
    {
        let mut iv: v128_t = v128_t { v8: [0; 16] };
        iv.v32[0 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
        iv.v32[1 as libc::c_int as usize] = (*hdr).ssrc;
        iv.v32[2 as libc::c_int as usize] = __bswap_32(seq_num >> 16 as libc::c_int);
        iv.v32[3 as libc::c_int as usize] = __bswap_32(seq_num << 16 as libc::c_int);
        status = srtp_cipher_set_iv(
            (*session_keys).rtcp_cipher,
            &mut iv as *mut v128_t as *mut uint8_t,
            srtp_direction_decrypt as libc::c_int,
        );
    } else {
        let mut iv_0: v128_t = v128_t { v8: [0; 16] };
        iv_0.v32[0 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
        iv_0.v32[1 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
        iv_0.v32[2 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
        iv_0.v32[3 as libc::c_int as usize] = __bswap_32(seq_num);
        status = srtp_cipher_set_iv(
            (*session_keys).rtcp_cipher,
            &mut iv_0 as *mut v128_t as *mut uint8_t,
            srtp_direction_decrypt as libc::c_int,
        );
    }
    if status as u64 != 0 {
        return srtp_err_status_cipher_fail;
    }
    status = ((*(*(*session_keys).rtcp_auth).type_0).start)
        .expect("non-null function pointer")((*(*session_keys).rtcp_auth).state);
    if status as u64 != 0 {
        return status;
    }
    status = ((*(*(*session_keys).rtcp_auth).type_0).compute)
        .expect(
            "non-null function pointer",
        )(
        (*(*session_keys).rtcp_auth).state,
        auth_start as *mut uint8_t,
        auth_len as libc::c_int,
        (*(*session_keys).rtcp_auth).out_len,
        tmp_tag.as_mut_ptr(),
    );
    if mod_srtp.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: srtcp computed tag:       %s\n\0" as *const u8 as *const libc::c_char,
            mod_srtp.name,
            srtp_octet_string_hex_string(
                tmp_tag.as_mut_ptr() as *const libc::c_void,
                tag_len,
            ),
        );
    }
    if status as u64 != 0 {
        return srtp_err_status_auth_fail;
    }
    if mod_srtp.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: srtcp tag from packet:    %s\n\0" as *const u8 as *const libc::c_char,
            mod_srtp.name,
            srtp_octet_string_hex_string(auth_tag as *const libc::c_void, tag_len),
        );
    }
    if srtp_octet_string_is_eq(tmp_tag.as_mut_ptr(), auth_tag, tag_len) != 0 {
        return srtp_err_status_auth_fail;
    }
    prefix_len = srtp_auth_get_prefix_length((*session_keys).rtcp_auth) as uint32_t;
    if prefix_len != 0 {
        status = srtp_cipher_output(
            (*session_keys).rtcp_cipher,
            auth_tag,
            &mut prefix_len,
        );
        if mod_srtp.on != 0 {
            srtp_err_report(
                srtp_err_level_debug,
                b"%s: keystream prefix: %s\n\0" as *const u8 as *const libc::c_char,
                mod_srtp.name,
                srtp_octet_string_hex_string(
                    auth_tag as *const libc::c_void,
                    prefix_len as libc::c_int,
                ),
            );
        }
        if status as u64 != 0 {
            return srtp_err_status_cipher_fail;
        }
    }
    if !enc_start.is_null() {
        status = srtp_cipher_decrypt(
            (*session_keys).rtcp_cipher,
            enc_start as *mut uint8_t,
            &mut enc_octet_len,
        );
        if status as u64 != 0 {
            return srtp_err_status_cipher_fail;
        }
    }
    *pkt_octet_len = (*pkt_octet_len as libc::c_ulong)
        .wrapping_sub(
            (tag_len as libc::c_ulong)
                .wrapping_add(::core::mem::size_of::<srtcp_trailer_t>() as libc::c_ulong),
        ) as libc::c_int as libc::c_int;
    *pkt_octet_len = (*pkt_octet_len as libc::c_uint).wrapping_sub(mki_size)
        as libc::c_int as libc::c_int;
    if (*stream).direction as libc::c_uint
        != dir_srtp_receiver as libc::c_int as libc::c_uint
    {
        if (*stream).direction as libc::c_uint
            == dir_unknown as libc::c_int as libc::c_uint
        {
            (*stream).direction = dir_srtp_receiver;
        } else if srtp_event_handler.is_some() {
            let mut data: srtp_event_data_t = srtp_event_data_t {
                session: 0 as *mut srtp_ctx_t,
                ssrc: 0,
                event: event_ssrc_collision,
            };
            data.session = ctx;
            data.ssrc = __bswap_32((*stream).ssrc);
            data.event = event_ssrc_collision;
            srtp_event_handler.expect("non-null function pointer")(&mut data);
        }
    }
    if stream == (*ctx).stream_template {
        let mut new_stream: *mut srtp_stream_ctx_t = 0 as *mut srtp_stream_ctx_t;
        status = srtp_stream_clone((*ctx).stream_template, (*hdr).ssrc, &mut new_stream);
        if status as u64 != 0 {
            return status;
        }
        (*new_stream).next = (*ctx).stream_list;
        (*ctx).stream_list = new_stream;
        stream = new_stream;
    }
    srtp_rdb_add_index(&mut (*stream).rtcp_rdb, seq_num);
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_set_user_data(
    mut ctx: srtp_t,
    mut data: *mut libc::c_void,
) {
    (*ctx).user_data = data;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_get_user_data(mut ctx: srtp_t) -> *mut libc::c_void {
    return (*ctx).user_data;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_crypto_policy_set_from_profile_for_rtp(
    mut policy: *mut srtp_crypto_policy_t,
    mut profile: srtp_profile_t,
) -> srtp_err_status_t {
    match profile as libc::c_uint {
        1 => {
            srtp_crypto_policy_set_rtp_default(policy);
        }
        2 => {
            srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(policy);
        }
        5 => {
            srtp_crypto_policy_set_null_cipher_hmac_sha1_80(policy);
        }
        6 | _ => return srtp_err_status_bad_param,
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_crypto_policy_set_from_profile_for_rtcp(
    mut policy: *mut srtp_crypto_policy_t,
    mut profile: srtp_profile_t,
) -> srtp_err_status_t {
    match profile as libc::c_uint {
        1 => {
            srtp_crypto_policy_set_rtp_default(policy);
        }
        2 => {
            srtp_crypto_policy_set_rtp_default(policy);
        }
        5 => {
            srtp_crypto_policy_set_null_cipher_hmac_sha1_80(policy);
        }
        6 | _ => return srtp_err_status_bad_param,
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_append_salt_to_key(
    mut key: *mut uint8_t,
    mut bytes_in_key: libc::c_uint,
    mut salt: *mut uint8_t,
    mut bytes_in_salt: libc::c_uint,
) {
    memcpy(
        key.offset(bytes_in_key as isize) as *mut libc::c_void,
        salt as *const libc::c_void,
        bytes_in_salt as libc::c_ulong,
    );
}
#[no_mangle]
pub unsafe extern "C" fn srtp_profile_get_master_key_length(
    mut profile: srtp_profile_t,
) -> libc::c_uint {
    match profile as libc::c_uint {
        1 => return 16 as libc::c_int as libc::c_uint,
        2 => return 16 as libc::c_int as libc::c_uint,
        5 => return 16 as libc::c_int as libc::c_uint,
        7 => return 16 as libc::c_int as libc::c_uint,
        8 => return 32 as libc::c_int as libc::c_uint,
        6 | _ => return 0 as libc::c_int as libc::c_uint,
    };
}
#[no_mangle]
pub unsafe extern "C" fn srtp_profile_get_master_salt_length(
    mut profile: srtp_profile_t,
) -> libc::c_uint {
    match profile as libc::c_uint {
        1 => return 14 as libc::c_int as libc::c_uint,
        2 => return 14 as libc::c_int as libc::c_uint,
        5 => return 14 as libc::c_int as libc::c_uint,
        7 => return 12 as libc::c_int as libc::c_uint,
        8 => return 12 as libc::c_int as libc::c_uint,
        6 | _ => return 0 as libc::c_int as libc::c_uint,
    };
}
#[no_mangle]
pub unsafe extern "C" fn stream_get_protect_trailer_length(
    mut stream: *mut srtp_stream_ctx_t,
    mut is_rtp: uint32_t,
    mut use_mki: uint32_t,
    mut mki_index: uint32_t,
    mut length: *mut uint32_t,
) -> srtp_err_status_t {
    let mut session_key: *mut srtp_session_keys_t = 0 as *mut srtp_session_keys_t;
    *length = 0 as libc::c_int as uint32_t;
    if use_mki != 0 {
        if mki_index >= (*stream).num_master_keys {
            return srtp_err_status_bad_mki;
        }
        session_key = &mut *((*stream).session_keys).offset(mki_index as isize)
            as *mut srtp_session_keys_t;
        *length = (*length as libc::c_uint).wrapping_add((*session_key).mki_size)
            as uint32_t as uint32_t;
    } else {
        session_key = &mut *((*stream).session_keys).offset(0 as libc::c_int as isize)
            as *mut srtp_session_keys_t;
    }
    if is_rtp != 0 {
        *length = (*length as libc::c_uint)
            .wrapping_add(
                srtp_auth_get_tag_length((*session_key).rtp_auth) as libc::c_uint,
            ) as uint32_t as uint32_t;
    } else {
        *length = (*length as libc::c_uint)
            .wrapping_add(
                srtp_auth_get_tag_length((*session_key).rtcp_auth) as libc::c_uint,
            ) as uint32_t as uint32_t;
        *length = (*length as libc::c_ulong)
            .wrapping_add(::core::mem::size_of::<srtcp_trailer_t>() as libc::c_ulong)
            as uint32_t as uint32_t;
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn get_protect_trailer_length(
    mut session: srtp_t,
    mut is_rtp: uint32_t,
    mut use_mki: uint32_t,
    mut mki_index: uint32_t,
    mut length: *mut uint32_t,
) -> srtp_err_status_t {
    let mut stream: *mut srtp_stream_ctx_t = 0 as *mut srtp_stream_ctx_t;
    if session.is_null() {
        return srtp_err_status_bad_param;
    }
    if ((*session).stream_template).is_null() && ((*session).stream_list).is_null() {
        return srtp_err_status_bad_param;
    }
    *length = 0 as libc::c_int as uint32_t;
    stream = (*session).stream_template;
    if !stream.is_null() {
        stream_get_protect_trailer_length(stream, is_rtp, use_mki, mki_index, length);
    }
    stream = (*session).stream_list;
    while !stream.is_null() {
        let mut temp_length: uint32_t = 0;
        if stream_get_protect_trailer_length(
            stream,
            is_rtp,
            use_mki,
            mki_index,
            &mut temp_length,
        ) as libc::c_uint == srtp_err_status_ok as libc::c_int as libc::c_uint
        {
            if temp_length > *length {
                *length = temp_length;
            }
        }
        stream = (*stream).next;
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_get_protect_trailer_length(
    mut session: srtp_t,
    mut use_mki: uint32_t,
    mut mki_index: uint32_t,
    mut length: *mut uint32_t,
) -> srtp_err_status_t {
    return get_protect_trailer_length(
        session,
        1 as libc::c_int as uint32_t,
        use_mki,
        mki_index,
        length,
    );
}
#[no_mangle]
pub unsafe extern "C" fn srtp_get_protect_rtcp_trailer_length(
    mut session: srtp_t,
    mut use_mki: uint32_t,
    mut mki_index: uint32_t,
    mut length: *mut uint32_t,
) -> srtp_err_status_t {
    return get_protect_trailer_length(
        session,
        0 as libc::c_int as uint32_t,
        use_mki,
        mki_index,
        length,
    );
}
#[no_mangle]
pub unsafe extern "C" fn srtp_set_debug_module(
    mut mod_name: *const libc::c_char,
    mut v: libc::c_int,
) -> srtp_err_status_t {
    return srtp_crypto_kernel_set_debug_module(mod_name, v);
}
#[no_mangle]
pub unsafe extern "C" fn srtp_list_debug_modules() -> srtp_err_status_t {
    return srtp_crypto_kernel_list_debug_modules();
}
static mut srtp_log_handler: Option::<srtp_log_handler_func_t> = None;
static mut srtp_log_handler_data: *mut libc::c_void = 0 as *const libc::c_void
    as *mut libc::c_void;
#[no_mangle]
pub unsafe extern "C" fn srtp_err_handler(
    mut level: srtp_err_reporting_level_t,
    mut msg: *const libc::c_char,
) {
    if srtp_log_handler.is_some() {
        let mut log_level: srtp_log_level_t = srtp_log_level_error;
        match level as libc::c_uint {
            0 => {
                log_level = srtp_log_level_error;
            }
            1 => {
                log_level = srtp_log_level_warning;
            }
            2 => {
                log_level = srtp_log_level_info;
            }
            3 => {
                log_level = srtp_log_level_debug;
            }
            _ => {}
        }
        srtp_log_handler
            .expect("non-null function pointer")(log_level, msg, srtp_log_handler_data);
    }
}
#[no_mangle]
pub unsafe extern "C" fn srtp_install_log_handler(
    mut func: Option::<srtp_log_handler_func_t>,
    mut data: *mut libc::c_void,
) -> srtp_err_status_t {
    if srtp_log_handler.is_some() {
        srtp_install_err_report_handler(None);
    }
    srtp_log_handler = func;
    srtp_log_handler_data = data;
    if srtp_log_handler.is_some() {
        srtp_install_err_report_handler(
            Some(
                srtp_err_handler
                    as unsafe extern "C" fn(
                        srtp_err_reporting_level_t,
                        *const libc::c_char,
                    ) -> (),
            ),
        );
    }
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_set_stream_roc(
    mut session: srtp_t,
    mut ssrc: uint32_t,
    mut roc: uint32_t,
) -> srtp_err_status_t {
    let mut stream: srtp_stream_t = 0 as *mut srtp_stream_ctx_t;
    stream = srtp_get_stream(session, __bswap_32(ssrc));
    if stream.is_null() {
        return srtp_err_status_bad_param;
    }
    (*stream).pending_roc = roc;
    return srtp_err_status_ok;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_get_stream_roc(
    mut session: srtp_t,
    mut ssrc: uint32_t,
    mut roc: *mut uint32_t,
) -> srtp_err_status_t {
    let mut stream: srtp_stream_t = 0 as *mut srtp_stream_ctx_t;
    stream = srtp_get_stream(session, __bswap_32(ssrc));
    if stream.is_null() {
        return srtp_err_status_bad_param;
    }
    *roc = srtp_rdbx_get_roc(&mut (*stream).rtp_rdbx);
    return srtp_err_status_ok;
}
