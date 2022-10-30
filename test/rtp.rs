#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
#![feature(extern_types)]
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    static mut stderr: *mut FILE;
    fn fprintf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn srtp_protect(
        ctx: srtp_t,
        rtp_hdr: *mut libc::c_void,
        len_ptr: *mut libc::c_int,
    ) -> srtp_err_status_t;
    fn srtp_unprotect(
        ctx: srtp_t,
        srtp_hdr: *mut libc::c_void,
        len_ptr: *mut libc::c_int,
    ) -> srtp_err_status_t;
    fn srtp_create(
        session: *mut srtp_t,
        policy: *const srtp_policy_t,
    ) -> srtp_err_status_t;
    fn srtp_dealloc(s: srtp_t) -> srtp_err_status_t;
    fn malloc(_: libc::c_ulong) -> *mut libc::c_void;
    fn free(_: *mut libc::c_void);
    fn strncpy(
        _: *mut libc::c_char,
        _: *const libc::c_char,
        _: libc::c_ulong,
    ) -> *mut libc::c_char;
    fn sendto(
        __fd: libc::c_int,
        __buf: *const libc::c_void,
        __n: size_t,
        __flags: libc::c_int,
        __addr: *const sockaddr,
        __addr_len: socklen_t,
    ) -> ssize_t;
    fn recvfrom(
        __fd: libc::c_int,
        __buf: *mut libc::c_void,
        __n: size_t,
        __flags: libc::c_int,
        __addr: *mut sockaddr,
        __addr_len: *mut socklen_t,
    ) -> ssize_t;
    fn srtp_cipher_rand_u32_for_tests() -> uint32_t;
}
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __ssize_t = libc::c_long;
pub type __socklen_t = libc::c_uint;
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
pub type size_t = libc::c_ulong;
pub type ssize_t = __ssize_t;
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
pub type socklen_t = __socklen_t;
pub type sa_family_t = libc::c_ushort;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [libc::c_char; 14],
}
pub type in_addr_t = uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct in_addr {
    pub s_addr: in_addr_t,
}
pub type in_port_t = uint16_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_in {
    pub sin_family: sa_family_t,
    pub sin_port: in_port_t,
    pub sin_addr: in_addr,
    pub sin_zero: [libc::c_uchar; 8],
}
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rtp_msg_t {
    pub header: srtp_hdr_t,
    pub body: [libc::c_char; 16384],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rtp_sender_ctx_t {
    pub message: rtp_msg_t,
    pub socket: libc::c_int,
    pub srtp_ctx: *mut srtp_ctx_t,
    pub addr: sockaddr_in,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct rtp_receiver_ctx_t {
    pub message: rtp_msg_t,
    pub socket: libc::c_int,
    pub srtp_ctx: *mut srtp_ctx_t,
    pub addr: sockaddr_in,
}
pub type rtp_sender_t = *mut rtp_sender_ctx_t;
pub type rtp_receiver_t = *mut rtp_receiver_ctx_t;
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
pub unsafe extern "C" fn rtp_sendto(
    mut sender: rtp_sender_t,
    mut msg: *const libc::c_void,
    mut len: libc::c_int,
) -> libc::c_int {
    let mut octets_sent: libc::c_int = 0;
    let mut stat: srtp_err_status_t = srtp_err_status_ok;
    let mut pkt_len: libc::c_int = len + 12 as libc::c_int;
    strncpy(
        ((*sender).message.body).as_mut_ptr(),
        msg as *const libc::c_char,
        len as libc::c_ulong,
    );
    (*sender)
        .message
        .header
        .seq = (__bswap_16((*sender).message.header.seq) as libc::c_int
        + 1 as libc::c_int) as uint16_t;
    (*sender).message.header.seq = __bswap_16((*sender).message.header.seq);
    (*sender)
        .message
        .header
        .ts = (__bswap_32((*sender).message.header.ts))
        .wrapping_add(1 as libc::c_int as libc::c_uint);
    (*sender).message.header.ts = __bswap_32((*sender).message.header.ts);
    stat = srtp_protect(
        (*sender).srtp_ctx,
        &mut (*sender).message.header as *mut srtp_hdr_t as *mut libc::c_void,
        &mut pkt_len,
    );
    if stat as u64 != 0 {
        return -(1 as libc::c_int);
    }
    octets_sent = sendto(
        (*sender).socket,
        &mut (*sender).message as *mut rtp_msg_t as *mut libc::c_void,
        pkt_len as size_t,
        0 as libc::c_int,
        &mut (*sender).addr as *mut sockaddr_in as *mut sockaddr,
        ::core::mem::size_of::<sockaddr_in>() as libc::c_ulong as socklen_t,
    ) as libc::c_int;
    octets_sent != pkt_len;
    return octets_sent;
}
#[no_mangle]
pub unsafe extern "C" fn rtp_recvfrom(
    mut receiver: rtp_receiver_t,
    mut msg: *mut libc::c_void,
    mut len: *mut libc::c_int,
) -> libc::c_int {
    let mut octets_recvd: libc::c_int = 0;
    let mut stat: srtp_err_status_t = srtp_err_status_ok;
    octets_recvd = recvfrom(
        (*receiver).socket,
        &mut (*receiver).message as *mut rtp_msg_t as *mut libc::c_void,
        *len as size_t,
        0 as libc::c_int,
        0 as *mut libc::c_void as *mut sockaddr,
        0 as *mut socklen_t,
    ) as libc::c_int;
    if octets_recvd == -(1 as libc::c_int) {
        *len = 0 as libc::c_int;
        return -(1 as libc::c_int);
    }
    if ((*receiver).message.header).version() as libc::c_int != 2 as libc::c_int {
        *len = 0 as libc::c_int;
        return -(1 as libc::c_int);
    }
    stat = srtp_unprotect(
        (*receiver).srtp_ctx,
        &mut (*receiver).message.header as *mut srtp_hdr_t as *mut libc::c_void,
        &mut octets_recvd,
    );
    if stat as u64 != 0 {
        fprintf(
            stderr,
            b"error: srtp unprotection failed with code %d%s\n\0" as *const u8
                as *const libc::c_char,
            stat as libc::c_uint,
            if stat as libc::c_uint
                == srtp_err_status_replay_fail as libc::c_int as libc::c_uint
            {
                b" (replay check failed)\0" as *const u8 as *const libc::c_char
            } else if stat as libc::c_uint
                    == srtp_err_status_auth_fail as libc::c_int as libc::c_uint
                {
                b" (auth check failed)\0" as *const u8 as *const libc::c_char
            } else {
                b"\0" as *const u8 as *const libc::c_char
            },
        );
        return -(1 as libc::c_int);
    }
    strncpy(
        msg as *mut libc::c_char,
        ((*receiver).message.body).as_mut_ptr(),
        octets_recvd as libc::c_ulong,
    );
    return octets_recvd;
}
#[no_mangle]
pub unsafe extern "C" fn rtp_sender_init(
    mut sender: rtp_sender_t,
    mut sock: libc::c_int,
    mut addr: sockaddr_in,
    mut ssrc: libc::c_uint,
) -> libc::c_int {
    (*sender).message.header.ssrc = __bswap_32(ssrc);
    (*sender).message.header.ts = 0 as libc::c_int as uint32_t;
    (*sender).message.header.seq = srtp_cipher_rand_u32_for_tests() as uint16_t;
    ((*sender).message.header).set_m(0 as libc::c_int as libc::c_uchar);
    ((*sender).message.header).set_pt(0x1 as libc::c_int as libc::c_uchar);
    ((*sender).message.header).set_version(2 as libc::c_int as libc::c_uchar);
    ((*sender).message.header).set_p(0 as libc::c_int as libc::c_uchar);
    ((*sender).message.header).set_x(0 as libc::c_int as libc::c_uchar);
    ((*sender).message.header).set_cc(0 as libc::c_int as libc::c_uchar);
    (*sender).socket = sock;
    (*sender).addr = addr;
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn rtp_receiver_init(
    mut rcvr: rtp_receiver_t,
    mut sock: libc::c_int,
    mut addr: sockaddr_in,
    mut ssrc: libc::c_uint,
) -> libc::c_int {
    (*rcvr).message.header.ssrc = __bswap_32(ssrc);
    (*rcvr).message.header.ts = 0 as libc::c_int as uint32_t;
    (*rcvr).message.header.seq = 0 as libc::c_int as uint16_t;
    ((*rcvr).message.header).set_m(0 as libc::c_int as libc::c_uchar);
    ((*rcvr).message.header).set_pt(0x1 as libc::c_int as libc::c_uchar);
    ((*rcvr).message.header).set_version(2 as libc::c_int as libc::c_uchar);
    ((*rcvr).message.header).set_p(0 as libc::c_int as libc::c_uchar);
    ((*rcvr).message.header).set_x(0 as libc::c_int as libc::c_uchar);
    ((*rcvr).message.header).set_cc(0 as libc::c_int as libc::c_uchar);
    (*rcvr).socket = sock;
    (*rcvr).addr = addr;
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn rtp_sender_init_srtp(
    mut sender: rtp_sender_t,
    mut policy: *const srtp_policy_t,
) -> libc::c_int {
    return srtp_create(&mut (*sender).srtp_ctx, policy) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn rtp_sender_deinit_srtp(
    mut sender: rtp_sender_t,
) -> libc::c_int {
    return srtp_dealloc((*sender).srtp_ctx) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn rtp_receiver_init_srtp(
    mut sender: rtp_receiver_t,
    mut policy: *const srtp_policy_t,
) -> libc::c_int {
    return srtp_create(&mut (*sender).srtp_ctx, policy) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn rtp_receiver_deinit_srtp(
    mut sender: rtp_receiver_t,
) -> libc::c_int {
    return srtp_dealloc((*sender).srtp_ctx) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn rtp_sender_alloc() -> rtp_sender_t {
    return malloc(::core::mem::size_of::<rtp_sender_ctx_t>() as libc::c_ulong)
        as rtp_sender_t;
}
#[no_mangle]
pub unsafe extern "C" fn rtp_sender_dealloc(mut rtp_ctx: rtp_sender_t) {
    free(rtp_ctx as *mut libc::c_void);
}
#[no_mangle]
pub unsafe extern "C" fn rtp_receiver_alloc() -> rtp_receiver_t {
    return malloc(::core::mem::size_of::<rtp_receiver_ctx_t>() as libc::c_ulong)
        as rtp_receiver_t;
}
#[no_mangle]
pub unsafe extern "C" fn rtp_receiver_dealloc(mut rtp_ctx: rtp_receiver_t) {
    free(rtp_ctx as *mut libc::c_void);
}
