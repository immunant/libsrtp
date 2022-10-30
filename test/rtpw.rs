#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
#![feature(extern_types)]
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    fn getopt_s(
        argc: libc::c_int,
        argv: *const *mut libc::c_char,
        optstring: *const libc::c_char,
    ) -> libc::c_int;
    static mut optarg_s: *mut libc::c_char;
    static mut optind_s: libc::c_int;
    static mut stderr: *mut FILE;
    fn fclose(__stream: *mut FILE) -> libc::c_int;
    fn fopen(_: *const libc::c_char, _: *const libc::c_char) -> *mut FILE;
    fn fprintf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    fn fgets(
        __s: *mut libc::c_char,
        __n: libc::c_int,
        __stream: *mut FILE,
    ) -> *mut libc::c_char;
    fn perror(__s: *const libc::c_char);
    fn strtol(
        _: *const libc::c_char,
        _: *mut *mut libc::c_char,
        _: libc::c_int,
    ) -> libc::c_long;
    fn exit(_: libc::c_int) -> !;
    fn __errno_location() -> *mut libc::c_int;
    fn signal(__sig: libc::c_int, __handler: __sighandler_t) -> __sighandler_t;
    fn sigemptyset(__set: *mut sigset_t) -> libc::c_int;
    fn sigaction(
        __sig: libc::c_int,
        __act: *const sigaction,
        __oact: *mut sigaction,
    ) -> libc::c_int;
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn close(__fd: libc::c_int) -> libc::c_int;
    fn usleep(__useconds: __useconds_t) -> libc::c_int;
    fn socket(
        __domain: libc::c_int,
        __type: libc::c_int,
        __protocol: libc::c_int,
    ) -> libc::c_int;
    fn bind(__fd: libc::c_int, __addr: *const sockaddr, __len: socklen_t) -> libc::c_int;
    fn setsockopt(
        __fd: libc::c_int,
        __level: libc::c_int,
        __optname: libc::c_int,
        __optval: *const libc::c_void,
        __optlen: socklen_t,
    ) -> libc::c_int;
    fn inet_pton(
        __af: libc::c_int,
        __cp: *const libc::c_char,
        __buf: *mut libc::c_void,
    ) -> libc::c_int;
    fn srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80(p: *mut srtp_crypto_policy_t);
    fn srtp_crypto_policy_set_null_cipher_hmac_null(p: *mut srtp_crypto_policy_t);
    fn srtp_crypto_policy_set_null_cipher_hmac_sha1_80(p: *mut srtp_crypto_policy_t);
    fn srtp_crypto_policy_set_aes_cm_128_null_auth(p: *mut srtp_crypto_policy_t);
    fn srtp_crypto_policy_set_rtcp_default(p: *mut srtp_crypto_policy_t);
    fn srtp_crypto_policy_set_rtp_default(p: *mut srtp_crypto_policy_t);
    fn srtp_shutdown() -> srtp_err_status_t;
    fn srtp_init() -> srtp_err_status_t;
    fn srtp_crypto_policy_set_aes_cm_256_null_auth(p: *mut srtp_crypto_policy_t);
    fn srtp_list_debug_modules() -> srtp_err_status_t;
    fn srtp_set_debug_module(
        mod_name: *const libc::c_char,
        v: libc::c_int,
    ) -> srtp_err_status_t;
    fn srtp_get_version() -> libc::c_uint;
    fn srtp_get_version_string() -> *const libc::c_char;
    fn rtp_sendto(
        sender_0: rtp_sender_t,
        msg: *const libc::c_void,
        len: libc::c_int,
    ) -> libc::c_int;
    fn rtp_recvfrom(
        receiver_0: rtp_receiver_t,
        msg: *mut libc::c_void,
        len: *mut libc::c_int,
    ) -> libc::c_int;
    fn rtp_receiver_init(
        rcvr: rtp_receiver_t,
        sock: libc::c_int,
        addr: sockaddr_in,
        ssrc: libc::c_uint,
    ) -> libc::c_int;
    fn rtp_sender_init(
        sender_0: rtp_sender_t,
        sock: libc::c_int,
        addr: sockaddr_in,
        ssrc: libc::c_uint,
    ) -> libc::c_int;
    fn rtp_sender_init_srtp(
        sender_0: rtp_sender_t,
        policy: *const srtp_policy_t,
    ) -> libc::c_int;
    fn rtp_sender_deinit_srtp(sender_0: rtp_sender_t) -> libc::c_int;
    fn rtp_receiver_init_srtp(
        sender_0: rtp_receiver_t,
        policy: *const srtp_policy_t,
    ) -> libc::c_int;
    fn rtp_receiver_deinit_srtp(sender_0: rtp_receiver_t) -> libc::c_int;
    fn rtp_sender_alloc() -> rtp_sender_t;
    fn rtp_sender_dealloc(rtp_ctx: rtp_sender_t);
    fn rtp_receiver_alloc() -> rtp_receiver_t;
    fn rtp_receiver_dealloc(rtp_ctx: rtp_receiver_t);
    fn hex_string_to_octet_string(
        raw: *mut libc::c_char,
        hex: *mut libc::c_char,
        len: libc::c_int,
    ) -> libc::c_int;
    fn octet_string_hex_string(
        s: *const libc::c_void,
        length: libc::c_int,
    ) -> *mut libc::c_char;
    fn base64_string_to_octet_string(
        raw: *mut libc::c_char,
        pad: *mut libc::c_int,
        base64: *mut libc::c_char,
        len: libc::c_int,
    ) -> libc::c_int;
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint16_t = libc::c_ushort;
pub type __uint32_t = libc::c_uint;
pub type __uint64_t = libc::c_ulong;
pub type __uid_t = libc::c_uint;
pub type __off_t = libc::c_long;
pub type __off64_t = libc::c_long;
pub type __pid_t = libc::c_int;
pub type __clock_t = libc::c_long;
pub type __useconds_t = libc::c_uint;
pub type __socklen_t = libc::c_uint;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub struct __sigset_t {
    pub __val: [libc::c_ulong; 16],
}
pub type sigset_t = __sigset_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub union sigval {
    pub sival_int: libc::c_int,
    pub sival_ptr: *mut libc::c_void,
}
pub type __sigval_t = sigval;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct siginfo_t {
    pub si_signo: libc::c_int,
    pub si_errno: libc::c_int,
    pub si_code: libc::c_int,
    pub __pad0: libc::c_int,
    pub _sifields: C2RustUnnamed,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed {
    pub _pad: [libc::c_int; 28],
    pub _kill: C2RustUnnamed_8,
    pub _timer: C2RustUnnamed_7,
    pub _rt: C2RustUnnamed_6,
    pub _sigchld: C2RustUnnamed_5,
    pub _sigfault: C2RustUnnamed_2,
    pub _sigpoll: C2RustUnnamed_1,
    pub _sigsys: C2RustUnnamed_0,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_0 {
    pub _call_addr: *mut libc::c_void,
    pub _syscall: libc::c_int,
    pub _arch: libc::c_uint,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_1 {
    pub si_band: libc::c_long,
    pub si_fd: libc::c_int,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_2 {
    pub si_addr: *mut libc::c_void,
    pub si_addr_lsb: libc::c_short,
    pub _bounds: C2RustUnnamed_3,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_3 {
    pub _addr_bnd: C2RustUnnamed_4,
    pub _pkey: __uint32_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_4 {
    pub _lower: *mut libc::c_void,
    pub _upper: *mut libc::c_void,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_5 {
    pub si_pid: __pid_t,
    pub si_uid: __uid_t,
    pub si_status: libc::c_int,
    pub si_utime: __clock_t,
    pub si_stime: __clock_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_6 {
    pub si_pid: __pid_t,
    pub si_uid: __uid_t,
    pub si_sigval: __sigval_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_7 {
    pub si_tid: libc::c_int,
    pub si_overrun: libc::c_int,
    pub si_sigval: __sigval_t,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct C2RustUnnamed_8 {
    pub si_pid: __pid_t,
    pub si_uid: __uid_t,
}
pub type __sighandler_t = Option::<unsafe extern "C" fn(libc::c_int) -> ()>;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sigaction {
    pub __sigaction_handler: C2RustUnnamed_9,
    pub sa_mask: __sigset_t,
    pub sa_flags: libc::c_int,
    pub sa_restorer: Option::<unsafe extern "C" fn() -> ()>,
}
#[derive(Copy, Clone)]
#[repr(C)]
pub union C2RustUnnamed_9 {
    pub sa_handler: __sighandler_t,
    pub sa_sigaction: Option::<
        unsafe extern "C" fn(libc::c_int, *mut siginfo_t, *mut libc::c_void) -> (),
    >,
}
pub type socklen_t = __socklen_t;
pub type __socket_type = libc::c_uint;
pub const SOCK_NONBLOCK: __socket_type = 2048;
pub const SOCK_CLOEXEC: __socket_type = 524288;
pub const SOCK_PACKET: __socket_type = 10;
pub const SOCK_DCCP: __socket_type = 6;
pub const SOCK_SEQPACKET: __socket_type = 5;
pub const SOCK_RDM: __socket_type = 4;
pub const SOCK_RAW: __socket_type = 3;
pub const SOCK_DGRAM: __socket_type = 2;
pub const SOCK_STREAM: __socket_type = 1;
pub type sa_family_t = libc::c_ushort;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
    pub sa_data: [libc::c_char; 14],
}
pub type uint8_t = __uint8_t;
pub type uint16_t = __uint16_t;
pub type uint32_t = __uint32_t;
pub type uint64_t = __uint64_t;
pub type in_addr_t = uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct in_addr {
    pub s_addr: in_addr_t,
}
pub type C2RustUnnamed_10 = libc::c_uint;
pub const IPPROTO_MAX: C2RustUnnamed_10 = 263;
pub const IPPROTO_MPTCP: C2RustUnnamed_10 = 262;
pub const IPPROTO_RAW: C2RustUnnamed_10 = 255;
pub const IPPROTO_ETHERNET: C2RustUnnamed_10 = 143;
pub const IPPROTO_MPLS: C2RustUnnamed_10 = 137;
pub const IPPROTO_UDPLITE: C2RustUnnamed_10 = 136;
pub const IPPROTO_SCTP: C2RustUnnamed_10 = 132;
pub const IPPROTO_COMP: C2RustUnnamed_10 = 108;
pub const IPPROTO_PIM: C2RustUnnamed_10 = 103;
pub const IPPROTO_ENCAP: C2RustUnnamed_10 = 98;
pub const IPPROTO_BEETPH: C2RustUnnamed_10 = 94;
pub const IPPROTO_MTP: C2RustUnnamed_10 = 92;
pub const IPPROTO_AH: C2RustUnnamed_10 = 51;
pub const IPPROTO_ESP: C2RustUnnamed_10 = 50;
pub const IPPROTO_GRE: C2RustUnnamed_10 = 47;
pub const IPPROTO_RSVP: C2RustUnnamed_10 = 46;
pub const IPPROTO_IPV6: C2RustUnnamed_10 = 41;
pub const IPPROTO_DCCP: C2RustUnnamed_10 = 33;
pub const IPPROTO_TP: C2RustUnnamed_10 = 29;
pub const IPPROTO_IDP: C2RustUnnamed_10 = 22;
pub const IPPROTO_UDP: C2RustUnnamed_10 = 17;
pub const IPPROTO_PUP: C2RustUnnamed_10 = 12;
pub const IPPROTO_EGP: C2RustUnnamed_10 = 8;
pub const IPPROTO_TCP: C2RustUnnamed_10 = 6;
pub const IPPROTO_IPIP: C2RustUnnamed_10 = 4;
pub const IPPROTO_IGMP: C2RustUnnamed_10 = 2;
pub const IPPROTO_ICMP: C2RustUnnamed_10 = 1;
pub const IPPROTO_IP: C2RustUnnamed_10 = 0;
pub type in_port_t = uint16_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct sockaddr_in {
    pub sin_family: sa_family_t,
    pub sin_port: in_port_t,
    pub sin_addr: in_addr,
    pub sin_zero: [libc::c_uchar; 8],
}
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ip_mreq {
    pub imr_multiaddr: in_addr,
    pub imr_interface: in_addr,
}
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
pub type program_type = libc::c_uint;
pub const unknown: program_type = 2;
pub const receiver: program_type = 1;
pub const sender: program_type = 0;
#[inline]
unsafe extern "C" fn __bswap_16(mut __bsx: __uint16_t) -> __uint16_t {
    return (__bsx as libc::c_int >> 8 as libc::c_int & 0xff as libc::c_int
        | (__bsx as libc::c_int & 0xff as libc::c_int) << 8 as libc::c_int)
        as __uint16_t;
}
#[inline]
unsafe extern "C" fn atoi(mut __nptr: *const libc::c_char) -> libc::c_int {
    return strtol(
        __nptr,
        0 as *mut libc::c_void as *mut *mut libc::c_char,
        10 as libc::c_int,
    ) as libc::c_int;
}
#[inline]
unsafe extern "C" fn __bswap_32(mut __bsx: __uint32_t) -> __uint32_t {
    return (__bsx & 0xff000000 as libc::c_uint) >> 24 as libc::c_int
        | (__bsx & 0xff0000 as libc::c_uint) >> 8 as libc::c_int
        | (__bsx & 0xff00 as libc::c_uint) << 8 as libc::c_int
        | (__bsx & 0xff as libc::c_uint) << 24 as libc::c_int;
}
#[no_mangle]
pub static mut interrupted: libc::c_int = 0 as libc::c_int;
unsafe fn main_0(
    mut argc: libc::c_int,
    mut argv: *mut *mut libc::c_char,
) -> libc::c_int {
    let mut dictfile: *mut libc::c_char = b"words.txt\0" as *const u8
        as *const libc::c_char as *mut libc::c_char;
    let mut dict: *mut FILE = 0 as *mut FILE;
    let mut word: [libc::c_char; 128] = [0; 128];
    let mut sock: libc::c_int = 0;
    let mut ret: libc::c_int = 0;
    let mut rcvr_addr: in_addr = in_addr { s_addr: 0 };
    let mut name: sockaddr_in = sockaddr_in {
        sin_family: 0,
        sin_port: 0,
        sin_addr: in_addr { s_addr: 0 },
        sin_zero: [0; 8],
    };
    let mut mreq: ip_mreq = ip_mreq {
        imr_multiaddr: in_addr { s_addr: 0 },
        imr_interface: in_addr { s_addr: 0 },
    };
    let mut prog_type: program_type = unknown;
    let mut sec_servs: srtp_sec_serv_t = sec_serv_none;
    let mut ttl: libc::c_uchar = 5 as libc::c_int as libc::c_uchar;
    let mut c: libc::c_int = 0;
    let mut key_size: libc::c_int = 128 as libc::c_int;
    let mut tag_size: libc::c_int = 8 as libc::c_int;
    let mut gcm_on: libc::c_int = 0 as libc::c_int;
    let mut input_key: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut b64_input: libc::c_int = 0 as libc::c_int;
    let mut address: *mut libc::c_char = 0 as *mut libc::c_char;
    let mut key: [libc::c_char; 96] = [0; 96];
    let mut port: libc::c_ushort = 0 as libc::c_int as libc::c_ushort;
    let mut snd: rtp_sender_t = 0 as *mut rtp_sender_ctx_t;
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
    let mut status: srtp_err_status_t = srtp_err_status_ok;
    let mut len: libc::c_int = 0;
    let mut expected_len: libc::c_int = 0;
    let mut do_list_mods: libc::c_int = 0 as libc::c_int;
    let mut ssrc: uint32_t = 0xdeadbeef as libc::c_uint;
    memset(
        &mut policy as *mut srtp_policy_t as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<srtp_policy_t>() as libc::c_ulong,
    );
    printf(
        b"Using %s [0x%x]\n\0" as *const u8 as *const libc::c_char,
        srtp_get_version_string(),
        srtp_get_version(),
    );
    if setup_signal_handler(*argv.offset(0 as libc::c_int as isize)) != 0 as libc::c_int
    {
        exit(1 as libc::c_int);
    }
    status = srtp_init();
    if status as u64 != 0 {
        printf(
            b"error: srtp initialization failed with error code %d\n\0" as *const u8
                as *const libc::c_char,
            status as libc::c_uint,
        );
        exit(1 as libc::c_int);
    }
    loop {
        c = getopt_s(
            argc,
            argv as *const *mut libc::c_char,
            b"b:k:rsgt:ae:ld:w:\0" as *const u8 as *const libc::c_char,
        );
        if c == -(1 as libc::c_int) {
            break;
        }
        let mut current_block_36: u64;
        match c {
            98 => {
                b64_input = 1 as libc::c_int;
                current_block_36 = 3961239128618364832;
            }
            107 => {
                current_block_36 = 3961239128618364832;
            }
            101 => {
                key_size = atoi(optarg_s);
                if key_size != 128 as libc::c_int && key_size != 256 as libc::c_int {
                    printf(
                        b"error: encryption key size must be 128 or 256 (%d)\n\0"
                            as *const u8 as *const libc::c_char,
                        key_size,
                    );
                    exit(1 as libc::c_int);
                }
                sec_servs = ::core::mem::transmute::<
                    libc::c_uint,
                    srtp_sec_serv_t,
                >(
                    sec_servs as libc::c_uint
                        | sec_serv_conf as libc::c_int as libc::c_uint,
                );
                current_block_36 = 6717214610478484138;
            }
            116 => {
                tag_size = atoi(optarg_s);
                if tag_size != 8 as libc::c_int && tag_size != 16 as libc::c_int {
                    printf(
                        b"error: GCM tag size must be 8 or 16 (%d)\n\0" as *const u8
                            as *const libc::c_char,
                        tag_size,
                    );
                    exit(1 as libc::c_int);
                }
                current_block_36 = 6717214610478484138;
            }
            97 => {
                sec_servs = ::core::mem::transmute::<
                    libc::c_uint,
                    srtp_sec_serv_t,
                >(
                    sec_servs as libc::c_uint
                        | sec_serv_auth as libc::c_int as libc::c_uint,
                );
                current_block_36 = 6717214610478484138;
            }
            103 => {
                gcm_on = 1 as libc::c_int;
                sec_servs = ::core::mem::transmute::<
                    libc::c_uint,
                    srtp_sec_serv_t,
                >(
                    sec_servs as libc::c_uint
                        | sec_serv_auth as libc::c_int as libc::c_uint,
                );
                current_block_36 = 6717214610478484138;
            }
            114 => {
                prog_type = receiver;
                current_block_36 = 6717214610478484138;
            }
            115 => {
                prog_type = sender;
                current_block_36 = 6717214610478484138;
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
                current_block_36 = 6717214610478484138;
            }
            108 => {
                do_list_mods = 1 as libc::c_int;
                current_block_36 = 6717214610478484138;
            }
            119 => {
                dictfile = optarg_s;
                current_block_36 = 6717214610478484138;
            }
            _ => {
                usage(*argv.offset(0 as libc::c_int as isize));
                current_block_36 = 6717214610478484138;
            }
        }
        match current_block_36 {
            3961239128618364832 => {
                input_key = optarg_s;
            }
            _ => {}
        }
    }
    if prog_type as libc::c_uint == unknown as libc::c_int as libc::c_uint {
        if do_list_mods != 0 {
            status = srtp_list_debug_modules();
            if status as u64 != 0 {
                printf(
                    b"error: list of debug modules failed\n\0" as *const u8
                        as *const libc::c_char,
                );
                exit(1 as libc::c_int);
            }
            return 0 as libc::c_int;
        } else {
            printf(
                b"error: neither sender [-s] nor receiver [-r] specified\n\0"
                    as *const u8 as *const libc::c_char,
            );
            usage(*argv.offset(0 as libc::c_int as isize));
        }
    }
    if sec_servs as libc::c_uint != 0 && input_key.is_null()
        || sec_servs as u64 == 0 && !input_key.is_null()
    {
        usage(*argv.offset(0 as libc::c_int as isize));
    }
    if argc != optind_s + 2 as libc::c_int {
        usage(*argv.offset(0 as libc::c_int as isize));
    }
    let fresh0 = optind_s;
    optind_s = optind_s + 1;
    address = *argv.offset(fresh0 as isize);
    let fresh1 = optind_s;
    optind_s = optind_s + 1;
    port = atoi(*argv.offset(fresh1 as isize)) as libc::c_ushort;
    if 0 as libc::c_int
        == inet_pton(
            2 as libc::c_int,
            address,
            &mut rcvr_addr as *mut in_addr as *mut libc::c_void,
        )
    {
        fprintf(
            stderr,
            b"%s: cannot parse IP v4 address %s\n\0" as *const u8 as *const libc::c_char,
            *argv.offset(0 as libc::c_int as isize),
            address,
        );
        exit(1 as libc::c_int);
    }
    if rcvr_addr.s_addr == 0xffffffff as libc::c_uint {
        fprintf(
            stderr,
            b"%s: address error\0" as *const u8 as *const libc::c_char,
            *argv.offset(0 as libc::c_int as isize),
        );
        exit(1 as libc::c_int);
    }
    sock = socket(
        2 as libc::c_int,
        SOCK_DGRAM as libc::c_int,
        IPPROTO_UDP as libc::c_int,
    );
    if sock < 0 as libc::c_int {
        let mut err: libc::c_int = 0;
        err = *__errno_location();
        fprintf(
            stderr,
            b"%s: couldn't open socket: %d\n\0" as *const u8 as *const libc::c_char,
            *argv.offset(0 as libc::c_int as isize),
            err,
        );
        exit(1 as libc::c_int);
    }
    memset(
        &mut name as *mut sockaddr_in as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<sockaddr_in>() as libc::c_ulong,
    );
    name.sin_addr = rcvr_addr;
    name.sin_family = 2 as libc::c_int as sa_family_t;
    name.sin_port = __bswap_16(port);
    if __bswap_32(rcvr_addr.s_addr) & 0xf0000000 as libc::c_uint
        == 0xe0000000 as libc::c_uint
    {
        if prog_type as libc::c_uint == sender as libc::c_int as libc::c_uint {
            ret = setsockopt(
                sock,
                IPPROTO_IP as libc::c_int,
                33 as libc::c_int,
                &mut ttl as *mut libc::c_uchar as *const libc::c_void,
                ::core::mem::size_of::<libc::c_uchar>() as libc::c_ulong as socklen_t,
            );
            if ret < 0 as libc::c_int {
                fprintf(
                    stderr,
                    b"%s: Failed to set TTL for multicast group\0" as *const u8
                        as *const libc::c_char,
                    *argv.offset(0 as libc::c_int as isize),
                );
                perror(b"\0" as *const u8 as *const libc::c_char);
                exit(1 as libc::c_int);
            }
        }
        mreq.imr_multiaddr.s_addr = rcvr_addr.s_addr;
        mreq.imr_interface.s_addr = __bswap_32(0 as libc::c_int as in_addr_t);
        ret = setsockopt(
            sock,
            IPPROTO_IP as libc::c_int,
            35 as libc::c_int,
            &mut mreq as *mut ip_mreq as *mut libc::c_void,
            ::core::mem::size_of::<ip_mreq>() as libc::c_ulong as socklen_t,
        );
        if ret < 0 as libc::c_int {
            fprintf(
                stderr,
                b"%s: Failed to join multicast group\0" as *const u8
                    as *const libc::c_char,
                *argv.offset(0 as libc::c_int as isize),
            );
            perror(b"\0" as *const u8 as *const libc::c_char);
            exit(1 as libc::c_int);
        }
    }
    printf(b"security services: \0" as *const u8 as *const libc::c_char);
    if sec_servs as libc::c_uint & sec_serv_conf as libc::c_int as libc::c_uint != 0 {
        printf(b"confidentiality \0" as *const u8 as *const libc::c_char);
    }
    if sec_servs as libc::c_uint & sec_serv_auth as libc::c_int as libc::c_uint != 0 {
        printf(b"message authentication\0" as *const u8 as *const libc::c_char);
    }
    if sec_servs as libc::c_uint == sec_serv_none as libc::c_int as libc::c_uint {
        printf(b"none\0" as *const u8 as *const libc::c_char);
    }
    printf(b"\n\0" as *const u8 as *const libc::c_char);
    if sec_servs as u64 != 0 {
        match sec_servs as libc::c_uint {
            3 => {
                if gcm_on != 0 {
                    printf(
                        b"error: GCM mode only supported when using the OpenSSL or NSS crypto engine.\n\0"
                            as *const u8 as *const libc::c_char,
                    );
                    return 0 as libc::c_int;
                } else {
                    match key_size {
                        128 => {
                            srtp_crypto_policy_set_rtp_default(&mut policy.rtp);
                            srtp_crypto_policy_set_rtcp_default(&mut policy.rtcp);
                        }
                        256 => {
                            srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80(
                                &mut policy.rtp,
                            );
                            srtp_crypto_policy_set_rtcp_default(&mut policy.rtcp);
                        }
                        _ => {}
                    }
                }
            }
            1 => {
                if gcm_on != 0 {
                    printf(
                        b"error: GCM mode must always be used with auth enabled\n\0"
                            as *const u8 as *const libc::c_char,
                    );
                    return -(1 as libc::c_int);
                } else {
                    match key_size {
                        128 => {
                            srtp_crypto_policy_set_aes_cm_128_null_auth(&mut policy.rtp);
                            srtp_crypto_policy_set_rtcp_default(&mut policy.rtcp);
                        }
                        256 => {
                            srtp_crypto_policy_set_aes_cm_256_null_auth(&mut policy.rtp);
                            srtp_crypto_policy_set_rtcp_default(&mut policy.rtcp);
                        }
                        _ => {}
                    }
                }
            }
            2 => {
                if gcm_on != 0 {
                    printf(
                        b"error: GCM mode only supported when using the OpenSSL crypto engine.\n\0"
                            as *const u8 as *const libc::c_char,
                    );
                    return 0 as libc::c_int;
                } else {
                    srtp_crypto_policy_set_null_cipher_hmac_sha1_80(&mut policy.rtp);
                    srtp_crypto_policy_set_rtcp_default(&mut policy.rtcp);
                }
            }
            _ => {
                printf(
                    b"error: unknown security service requested\n\0" as *const u8
                        as *const libc::c_char,
                );
                return -(1 as libc::c_int);
            }
        }
        policy.ssrc.type_0 = ssrc_specific;
        policy.ssrc.value = ssrc;
        policy.key = key.as_mut_ptr() as *mut uint8_t;
        policy.next = 0 as *mut srtp_policy_t;
        policy.window_size = 128 as libc::c_int as libc::c_ulong;
        policy.allow_repeat_tx = 0 as libc::c_int;
        policy.rtp.sec_serv = sec_servs;
        policy.rtcp.sec_serv = sec_serv_none;
        if gcm_on != 0 && tag_size != 8 as libc::c_int {
            policy.rtp.auth_tag_len = tag_size;
        }
        if b64_input != 0 {
            let mut pad: libc::c_int = 0;
            expected_len = policy.rtp.cipher_key_len * 4 as libc::c_int
                / 3 as libc::c_int;
            len = base64_string_to_octet_string(
                key.as_mut_ptr(),
                &mut pad,
                input_key,
                expected_len,
            );
            if pad != 0 as libc::c_int {
                fprintf(
                    stderr,
                    b"error: padding in base64 unexpected\n\0" as *const u8
                        as *const libc::c_char,
                );
                exit(1 as libc::c_int);
            }
        } else {
            expected_len = policy.rtp.cipher_key_len * 2 as libc::c_int;
            len = hex_string_to_octet_string(key.as_mut_ptr(), input_key, expected_len);
        }
        if len < expected_len {
            fprintf(
                stderr,
                b"error: too few digits in key/salt (should be %d digits, found %d)\n\0"
                    as *const u8 as *const libc::c_char,
                expected_len,
                len,
            );
            exit(1 as libc::c_int);
        }
        if strlen(input_key) as libc::c_int
            > policy.rtp.cipher_key_len * 2 as libc::c_int
        {
            fprintf(
                stderr,
                b"error: too many digits in key/salt (should be %d hexadecimal digits, found %u)\n\0"
                    as *const u8 as *const libc::c_char,
                policy.rtp.cipher_key_len * 2 as libc::c_int,
                strlen(input_key) as libc::c_uint,
            );
            exit(1 as libc::c_int);
        }
        printf(
            b"set master key/salt to %s/\0" as *const u8 as *const libc::c_char,
            octet_string_hex_string(
                key.as_mut_ptr() as *const libc::c_void,
                16 as libc::c_int,
            ),
        );
        printf(
            b"%s\n\0" as *const u8 as *const libc::c_char,
            octet_string_hex_string(
                key.as_mut_ptr().offset(16 as libc::c_int as isize)
                    as *const libc::c_void,
                14 as libc::c_int,
            ),
        );
    } else {
        srtp_crypto_policy_set_null_cipher_hmac_null(&mut policy.rtp);
        srtp_crypto_policy_set_null_cipher_hmac_null(&mut policy.rtcp);
        policy.key = key.as_mut_ptr() as *mut uint8_t;
        policy.ssrc.type_0 = ssrc_specific;
        policy.ssrc.value = ssrc;
        policy.window_size = 0 as libc::c_int as libc::c_ulong;
        policy.allow_repeat_tx = 0 as libc::c_int;
        policy.next = 0 as *mut srtp_policy_t;
    }
    if prog_type as libc::c_uint == sender as libc::c_int as libc::c_uint {
        snd = rtp_sender_alloc();
        if snd.is_null() {
            fprintf(
                stderr,
                b"error: malloc() failed\n\0" as *const u8 as *const libc::c_char,
            );
            exit(1 as libc::c_int);
        }
        rtp_sender_init(snd, sock, name, ssrc);
        status = rtp_sender_init_srtp(snd, &mut policy) as srtp_err_status_t;
        if status as u64 != 0 {
            fprintf(
                stderr,
                b"error: srtp_create() failed with code %d\n\0" as *const u8
                    as *const libc::c_char,
                status as libc::c_uint,
            );
            exit(1 as libc::c_int);
        }
        dict = fopen(dictfile, b"r\0" as *const u8 as *const libc::c_char);
        if dict.is_null() {
            fprintf(
                stderr,
                b"%s: couldn't open file %s\n\0" as *const u8 as *const libc::c_char,
                *argv.offset(0 as libc::c_int as isize),
                dictfile,
            );
            if __bswap_32(rcvr_addr.s_addr) & 0xf0000000 as libc::c_uint
                == 0xe0000000 as libc::c_uint
            {
                leave_group(sock, mreq, *argv.offset(0 as libc::c_int as isize));
            }
            exit(1 as libc::c_int);
        }
        while interrupted == 0
            && !(fgets(word.as_mut_ptr(), 128 as libc::c_int, dict)).is_null()
        {
            len = (strlen(word.as_mut_ptr()))
                .wrapping_add(1 as libc::c_int as libc::c_ulong) as libc::c_int;
            if len > 128 as libc::c_int {
                printf(
                    b"error: word %s too large to send\n\0" as *const u8
                        as *const libc::c_char,
                    word.as_mut_ptr(),
                );
            } else {
                rtp_sendto(snd, word.as_mut_ptr() as *const libc::c_void, len);
                printf(
                    b"sending word: %s\0" as *const u8 as *const libc::c_char,
                    word.as_mut_ptr(),
                );
            }
            usleep(5e5f64 as __useconds_t);
        }
        rtp_sender_deinit_srtp(snd);
        rtp_sender_dealloc(snd);
        fclose(dict);
    } else {
        let mut rcvr: rtp_receiver_t = 0 as *mut rtp_receiver_ctx_t;
        if bind(
            sock,
            &mut name as *mut sockaddr_in as *mut sockaddr,
            ::core::mem::size_of::<sockaddr_in>() as libc::c_ulong as socklen_t,
        ) < 0 as libc::c_int
        {
            close(sock);
            fprintf(
                stderr,
                b"%s: socket bind error\n\0" as *const u8 as *const libc::c_char,
                *argv.offset(0 as libc::c_int as isize),
            );
            perror(0 as *const libc::c_char);
            if __bswap_32(rcvr_addr.s_addr) & 0xf0000000 as libc::c_uint
                == 0xe0000000 as libc::c_uint
            {
                leave_group(sock, mreq, *argv.offset(0 as libc::c_int as isize));
            }
            exit(1 as libc::c_int);
        }
        rcvr = rtp_receiver_alloc();
        if rcvr.is_null() {
            fprintf(
                stderr,
                b"error: malloc() failed\n\0" as *const u8 as *const libc::c_char,
            );
            exit(1 as libc::c_int);
        }
        rtp_receiver_init(rcvr, sock, name, ssrc);
        status = rtp_receiver_init_srtp(rcvr, &mut policy) as srtp_err_status_t;
        if status as u64 != 0 {
            fprintf(
                stderr,
                b"error: srtp_create() failed with code %d\n\0" as *const u8
                    as *const libc::c_char,
                status as libc::c_uint,
            );
            exit(1 as libc::c_int);
        }
        while interrupted == 0 {
            len = 128 as libc::c_int;
            if rtp_recvfrom(rcvr, word.as_mut_ptr() as *mut libc::c_void, &mut len)
                > -(1 as libc::c_int)
            {
                printf(
                    b"\tword: %s\n\0" as *const u8 as *const libc::c_char,
                    word.as_mut_ptr(),
                );
            }
        }
        rtp_receiver_deinit_srtp(rcvr);
        rtp_receiver_dealloc(rcvr);
    }
    if __bswap_32(rcvr_addr.s_addr) & 0xf0000000 as libc::c_uint
        == 0xe0000000 as libc::c_uint
    {
        leave_group(sock, mreq, *argv.offset(0 as libc::c_int as isize));
    }
    ret = close(sock);
    if ret < 0 as libc::c_int {
        fprintf(
            stderr,
            b"%s: Failed to close socket\0" as *const u8 as *const libc::c_char,
            *argv.offset(0 as libc::c_int as isize),
        );
        perror(b"\0" as *const u8 as *const libc::c_char);
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
pub unsafe extern "C" fn usage(mut string: *mut libc::c_char) {
    printf(
        b"usage: %s [-d <debug>]* [-k <key> [-a][-e]] [-s | -r] dest_ip dest_port\nor     %s -l\nwhere  -a use message authentication\n       -e <key size> use encryption (use 128 or 256 for key size)\n       -g Use AES-GCM mode (must be used with -e)\n       -t <tag size> Tag size to use in GCM mode (use 8 or 16)\n       -k <key>  sets the srtp master key given in hexadecimal\n       -b <key>  sets the srtp master key given in base64\n       -s act as rtp sender\n       -r act as rtp receiver\n       -l list debug modules\n       -d <debug> turn on debugging for module <debug>\n       -w <wordsfile> use <wordsfile> for input, rather than %s\n\0"
            as *const u8 as *const libc::c_char,
        string,
        string,
        b"words.txt\0" as *const u8 as *const libc::c_char,
    );
    exit(1 as libc::c_int);
}
#[no_mangle]
pub unsafe extern "C" fn leave_group(
    mut sock: libc::c_int,
    mut mreq: ip_mreq,
    mut name: *mut libc::c_char,
) {
    let mut ret: libc::c_int = 0;
    ret = setsockopt(
        sock,
        IPPROTO_IP as libc::c_int,
        36 as libc::c_int,
        &mut mreq as *mut ip_mreq as *mut libc::c_void,
        ::core::mem::size_of::<ip_mreq>() as libc::c_ulong as socklen_t,
    );
    if ret < 0 as libc::c_int {
        fprintf(
            stderr,
            b"%s: Failed to leave multicast group\0" as *const u8 as *const libc::c_char,
            name,
        );
        perror(b"\0" as *const u8 as *const libc::c_char);
    }
}
#[no_mangle]
pub unsafe extern "C" fn handle_signal(mut signum: libc::c_int) {
    ::core::ptr::write_volatile(&mut interrupted as *mut libc::c_int, 1 as libc::c_int);
    signal(signum, None);
}
#[no_mangle]
pub unsafe extern "C" fn setup_signal_handler(
    mut name: *mut libc::c_char,
) -> libc::c_int {
    let mut act: sigaction = sigaction {
        __sigaction_handler: C2RustUnnamed_9 {
            sa_handler: None,
        },
        sa_mask: __sigset_t { __val: [0; 16] },
        sa_flags: 0,
        sa_restorer: None,
    };
    memset(
        &mut act as *mut sigaction as *mut libc::c_void,
        0 as libc::c_int,
        ::core::mem::size_of::<sigaction>() as libc::c_ulong,
    );
    act
        .__sigaction_handler
        .sa_handler = Some(handle_signal as unsafe extern "C" fn(libc::c_int) -> ());
    sigemptyset(&mut act.sa_mask);
    act.sa_flags = 0x80000000 as libc::c_uint as libc::c_int;
    if sigaction(15 as libc::c_int, &mut act, 0 as *mut sigaction) != 0 as libc::c_int {
        fprintf(
            stderr,
            b"%s: error setting up signal handler\0" as *const u8 as *const libc::c_char,
            name,
        );
        perror(b"\0" as *const u8 as *const libc::c_char);
        return -(1 as libc::c_int);
    }
    return 0 as libc::c_int;
}
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
