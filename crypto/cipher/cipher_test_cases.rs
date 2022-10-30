#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
pub type __uint8_t = libc::c_uchar;
pub type uint8_t = __uint8_t;
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
static mut srtp_aes_icm_128_test_case_0_key: [uint8_t; 30] = [
    0x2b as libc::c_int as uint8_t,
    0x7e as libc::c_int as uint8_t,
    0x15 as libc::c_int as uint8_t,
    0x16 as libc::c_int as uint8_t,
    0x28 as libc::c_int as uint8_t,
    0xae as libc::c_int as uint8_t,
    0xd2 as libc::c_int as uint8_t,
    0xa6 as libc::c_int as uint8_t,
    0xab as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0x15 as libc::c_int as uint8_t,
    0x88 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0xcf as libc::c_int as uint8_t,
    0x4f as libc::c_int as uint8_t,
    0x3c as libc::c_int as uint8_t,
    0xf0 as libc::c_int as uint8_t,
    0xf1 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0xf3 as libc::c_int as uint8_t,
    0xf4 as libc::c_int as uint8_t,
    0xf5 as libc::c_int as uint8_t,
    0xf6 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xf8 as libc::c_int as uint8_t,
    0xf9 as libc::c_int as uint8_t,
    0xfa as libc::c_int as uint8_t,
    0xfb as libc::c_int as uint8_t,
    0xfc as libc::c_int as uint8_t,
    0xfd as libc::c_int as uint8_t,
];
static mut srtp_aes_icm_128_test_case_0_nonce: [uint8_t; 16] = [
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
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
];
static mut srtp_aes_icm_128_test_case_0_plaintext: [uint8_t; 32] = [
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
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
];
static mut srtp_aes_icm_128_test_case_0_ciphertext: [uint8_t; 32] = [
    0xe0 as libc::c_int as uint8_t,
    0x3e as libc::c_int as uint8_t,
    0xad as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x35 as libc::c_int as uint8_t,
    0xc9 as libc::c_int as uint8_t,
    0x5e as libc::c_int as uint8_t,
    0x80 as libc::c_int as uint8_t,
    0xe1 as libc::c_int as uint8_t,
    0x66 as libc::c_int as uint8_t,
    0xb1 as libc::c_int as uint8_t,
    0x6d as libc::c_int as uint8_t,
    0xd9 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x4e as libc::c_int as uint8_t,
    0xb4 as libc::c_int as uint8_t,
    0xd2 as libc::c_int as uint8_t,
    0x35 as libc::c_int as uint8_t,
    0x13 as libc::c_int as uint8_t,
    0x16 as libc::c_int as uint8_t,
    0x2b as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0xd0 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x43 as libc::c_int as uint8_t,
    0xa2 as libc::c_int as uint8_t,
    0xfe as libc::c_int as uint8_t,
    0x4a as libc::c_int as uint8_t,
    0x5f as libc::c_int as uint8_t,
    0x97 as libc::c_int as uint8_t,
    0xab as libc::c_int as uint8_t,
];
#[no_mangle]
pub static mut srtp_aes_icm_128_test_case_0: srtp_cipher_test_case_t = unsafe {
    {
        let mut init = srtp_cipher_test_case_t {
            key_length_octets: 14 as libc::c_int + 16 as libc::c_int,
            key: srtp_aes_icm_128_test_case_0_key.as_ptr(),
            idx: srtp_aes_icm_128_test_case_0_nonce.as_ptr() as *mut _,
            plaintext_length_octets: 32 as libc::c_int as libc::c_uint,
            plaintext: srtp_aes_icm_128_test_case_0_plaintext.as_ptr(),
            ciphertext_length_octets: 32 as libc::c_int as libc::c_uint,
            ciphertext: srtp_aes_icm_128_test_case_0_ciphertext.as_ptr(),
            aad_length_octets: 0 as libc::c_int,
            aad: 0 as *const uint8_t,
            tag_length_octets: 0 as libc::c_int,
            next_test_case: 0 as *const srtp_cipher_test_case_t,
        };
        init
    }
};
static mut srtp_aes_icm_192_test_case_0_key: [uint8_t; 38] = [
    0xea as libc::c_int as uint8_t,
    0xb2 as libc::c_int as uint8_t,
    0x34 as libc::c_int as uint8_t,
    0x76 as libc::c_int as uint8_t,
    0x4e as libc::c_int as uint8_t,
    0x51 as libc::c_int as uint8_t,
    0x7b as libc::c_int as uint8_t,
    0x2d as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x16 as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0x58 as libc::c_int as uint8_t,
    0x7d as libc::c_int as uint8_t,
    0x8c as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x21 as libc::c_int as uint8_t,
    0x97 as libc::c_int as uint8_t,
    0x40 as libc::c_int as uint8_t,
    0xf6 as libc::c_int as uint8_t,
    0x5f as libc::c_int as uint8_t,
    0x99 as libc::c_int as uint8_t,
    0xb6 as libc::c_int as uint8_t,
    0xbc as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xf0 as libc::c_int as uint8_t,
    0xf1 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0xf3 as libc::c_int as uint8_t,
    0xf4 as libc::c_int as uint8_t,
    0xf5 as libc::c_int as uint8_t,
    0xf6 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xf8 as libc::c_int as uint8_t,
    0xf9 as libc::c_int as uint8_t,
    0xfa as libc::c_int as uint8_t,
    0xfb as libc::c_int as uint8_t,
    0xfc as libc::c_int as uint8_t,
    0xfd as libc::c_int as uint8_t,
];
static mut srtp_aes_icm_192_test_case_0_nonce: [uint8_t; 16] = [
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
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
];
static mut srtp_aes_icm_192_test_case_0_plaintext: [uint8_t; 32] = [
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
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
];
static mut srtp_aes_icm_192_test_case_0_ciphertext: [uint8_t; 32] = [
    0x35 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x6c as libc::c_int as uint8_t,
    0xba as libc::c_int as uint8_t,
    0x46 as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x8d as libc::c_int as uint8_t,
    0xc1 as libc::c_int as uint8_t,
    0xb5 as libc::c_int as uint8_t,
    0x75 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x80 as libc::c_int as uint8_t,
    0x4c as libc::c_int as uint8_t,
    0xe3 as libc::c_int as uint8_t,
    0x7c as libc::c_int as uint8_t,
    0x5d as libc::c_int as uint8_t,
    0xe9 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x29 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
    0xcc as libc::c_int as uint8_t,
    0xe1 as libc::c_int as uint8_t,
    0x61 as libc::c_int as uint8_t,
    0xd5 as libc::c_int as uint8_t,
    0x16 as libc::c_int as uint8_t,
    0x5e as libc::c_int as uint8_t,
    0xc4 as libc::c_int as uint8_t,
    0x56 as libc::c_int as uint8_t,
    0x8f as libc::c_int as uint8_t,
    0x5c as libc::c_int as uint8_t,
    0x9a as libc::c_int as uint8_t,
];
#[no_mangle]
pub static mut srtp_aes_icm_192_test_case_0: srtp_cipher_test_case_t = unsafe {
    {
        let mut init = srtp_cipher_test_case_t {
            key_length_octets: 14 as libc::c_int + 24 as libc::c_int,
            key: srtp_aes_icm_192_test_case_0_key.as_ptr(),
            idx: srtp_aes_icm_192_test_case_0_nonce.as_ptr() as *mut _,
            plaintext_length_octets: 32 as libc::c_int as libc::c_uint,
            plaintext: srtp_aes_icm_192_test_case_0_plaintext.as_ptr(),
            ciphertext_length_octets: 32 as libc::c_int as libc::c_uint,
            ciphertext: srtp_aes_icm_192_test_case_0_ciphertext.as_ptr(),
            aad_length_octets: 0 as libc::c_int,
            aad: 0 as *const uint8_t,
            tag_length_octets: 0 as libc::c_int,
            next_test_case: 0 as *const srtp_cipher_test_case_t,
        };
        init
    }
};
static mut srtp_aes_icm_256_test_case_0_key: [uint8_t; 46] = [
    0x57 as libc::c_int as uint8_t,
    0xf8 as libc::c_int as uint8_t,
    0x2f as libc::c_int as uint8_t,
    0xe3 as libc::c_int as uint8_t,
    0x61 as libc::c_int as uint8_t,
    0x3f as libc::c_int as uint8_t,
    0xd1 as libc::c_int as uint8_t,
    0x70 as libc::c_int as uint8_t,
    0xa8 as libc::c_int as uint8_t,
    0x5e as libc::c_int as uint8_t,
    0xc9 as libc::c_int as uint8_t,
    0x3c as libc::c_int as uint8_t,
    0x40 as libc::c_int as uint8_t,
    0xb1 as libc::c_int as uint8_t,
    0xf0 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x2e as libc::c_int as uint8_t,
    0xc4 as libc::c_int as uint8_t,
    0xcb as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0xc0 as libc::c_int as uint8_t,
    0x25 as libc::c_int as uint8_t,
    0xb5 as libc::c_int as uint8_t,
    0x82 as libc::c_int as uint8_t,
    0x72 as libc::c_int as uint8_t,
    0x14 as libc::c_int as uint8_t,
    0x7c as libc::c_int as uint8_t,
    0xc4 as libc::c_int as uint8_t,
    0x38 as libc::c_int as uint8_t,
    0x94 as libc::c_int as uint8_t,
    0x4a as libc::c_int as uint8_t,
    0x98 as libc::c_int as uint8_t,
    0xf0 as libc::c_int as uint8_t,
    0xf1 as libc::c_int as uint8_t,
    0xf2 as libc::c_int as uint8_t,
    0xf3 as libc::c_int as uint8_t,
    0xf4 as libc::c_int as uint8_t,
    0xf5 as libc::c_int as uint8_t,
    0xf6 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xf8 as libc::c_int as uint8_t,
    0xf9 as libc::c_int as uint8_t,
    0xfa as libc::c_int as uint8_t,
    0xfb as libc::c_int as uint8_t,
    0xfc as libc::c_int as uint8_t,
    0xfd as libc::c_int as uint8_t,
];
static mut srtp_aes_icm_256_test_case_0_nonce: [uint8_t; 16] = [
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
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
];
static mut srtp_aes_icm_256_test_case_0_plaintext: [uint8_t; 32] = [
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
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
];
static mut srtp_aes_icm_256_test_case_0_ciphertext: [uint8_t; 32] = [
    0x92 as libc::c_int as uint8_t,
    0xbd as libc::c_int as uint8_t,
    0xd2 as libc::c_int as uint8_t,
    0x8a as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xc3 as libc::c_int as uint8_t,
    0xf5 as libc::c_int as uint8_t,
    0x25 as libc::c_int as uint8_t,
    0x11 as libc::c_int as uint8_t,
    0xc6 as libc::c_int as uint8_t,
    0x77 as libc::c_int as uint8_t,
    0xd0 as libc::c_int as uint8_t,
    0x8b as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x15 as libc::c_int as uint8_t,
    0xa4 as libc::c_int as uint8_t,
    0x9d as libc::c_int as uint8_t,
    0xa7 as libc::c_int as uint8_t,
    0x1b as libc::c_int as uint8_t,
    0x23 as libc::c_int as uint8_t,
    0x78 as libc::c_int as uint8_t,
    0xa8 as libc::c_int as uint8_t,
    0x54 as libc::c_int as uint8_t,
    0xf6 as libc::c_int as uint8_t,
    0x70 as libc::c_int as uint8_t,
    0x50 as libc::c_int as uint8_t,
    0x75 as libc::c_int as uint8_t,
    0x6d as libc::c_int as uint8_t,
    0xed as libc::c_int as uint8_t,
    0x16 as libc::c_int as uint8_t,
    0x5b as libc::c_int as uint8_t,
    0xac as libc::c_int as uint8_t,
];
#[no_mangle]
pub static mut srtp_aes_icm_256_test_case_0: srtp_cipher_test_case_t = unsafe {
    {
        let mut init = srtp_cipher_test_case_t {
            key_length_octets: 14 as libc::c_int + 32 as libc::c_int,
            key: srtp_aes_icm_256_test_case_0_key.as_ptr(),
            idx: srtp_aes_icm_256_test_case_0_nonce.as_ptr() as *mut _,
            plaintext_length_octets: 32 as libc::c_int as libc::c_uint,
            plaintext: srtp_aes_icm_256_test_case_0_plaintext.as_ptr(),
            ciphertext_length_octets: 32 as libc::c_int as libc::c_uint,
            ciphertext: srtp_aes_icm_256_test_case_0_ciphertext.as_ptr(),
            aad_length_octets: 0 as libc::c_int,
            aad: 0 as *const uint8_t,
            tag_length_octets: 0 as libc::c_int,
            next_test_case: 0 as *const srtp_cipher_test_case_t,
        };
        init
    }
};
static mut srtp_aes_gcm_128_test_case_0_key: [uint8_t; 28] = [
    0xfe as libc::c_int as uint8_t,
    0xff as libc::c_int as uint8_t,
    0xe9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x73 as libc::c_int as uint8_t,
    0x1c as libc::c_int as uint8_t,
    0x6d as libc::c_int as uint8_t,
    0x6a as libc::c_int as uint8_t,
    0x8f as libc::c_int as uint8_t,
    0x94 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x30 as libc::c_int as uint8_t,
    0x83 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
];
static mut srtp_aes_gcm_128_test_case_0_iv: [uint8_t; 12] = [
    0xca as libc::c_int as uint8_t,
    0xfe as libc::c_int as uint8_t,
    0xba as libc::c_int as uint8_t,
    0xbe as libc::c_int as uint8_t,
    0xfa as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0xdb as libc::c_int as uint8_t,
    0xad as libc::c_int as uint8_t,
    0xde as libc::c_int as uint8_t,
    0xca as libc::c_int as uint8_t,
    0xf8 as libc::c_int as uint8_t,
    0x88 as libc::c_int as uint8_t,
];
static mut srtp_aes_gcm_128_test_case_0_plaintext: [uint8_t; 60] = [
    0xd9 as libc::c_int as uint8_t,
    0x31 as libc::c_int as uint8_t,
    0x32 as libc::c_int as uint8_t,
    0x25 as libc::c_int as uint8_t,
    0xf8 as libc::c_int as uint8_t,
    0x84 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0xe5 as libc::c_int as uint8_t,
    0xa5 as libc::c_int as uint8_t,
    0x59 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0xc5 as libc::c_int as uint8_t,
    0xaf as libc::c_int as uint8_t,
    0xf5 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x9a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xa7 as libc::c_int as uint8_t,
    0xa9 as libc::c_int as uint8_t,
    0x53 as libc::c_int as uint8_t,
    0x15 as libc::c_int as uint8_t,
    0x34 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xda as libc::c_int as uint8_t,
    0x2e as libc::c_int as uint8_t,
    0x4c as libc::c_int as uint8_t,
    0x30 as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x8a as libc::c_int as uint8_t,
    0x31 as libc::c_int as uint8_t,
    0x8a as libc::c_int as uint8_t,
    0x72 as libc::c_int as uint8_t,
    0x1c as libc::c_int as uint8_t,
    0x3c as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0x95 as libc::c_int as uint8_t,
    0x95 as libc::c_int as uint8_t,
    0x68 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x53 as libc::c_int as uint8_t,
    0x2f as libc::c_int as uint8_t,
    0xcf as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x24 as libc::c_int as uint8_t,
    0x49 as libc::c_int as uint8_t,
    0xa6 as libc::c_int as uint8_t,
    0xb5 as libc::c_int as uint8_t,
    0x25 as libc::c_int as uint8_t,
    0xb1 as libc::c_int as uint8_t,
    0x6a as libc::c_int as uint8_t,
    0xed as libc::c_int as uint8_t,
    0xf5 as libc::c_int as uint8_t,
    0xaa as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0xe6 as libc::c_int as uint8_t,
    0x57 as libc::c_int as uint8_t,
    0xba as libc::c_int as uint8_t,
    0x63 as libc::c_int as uint8_t,
    0x7b as libc::c_int as uint8_t,
    0x39 as libc::c_int as uint8_t,
];
static mut srtp_aes_gcm_128_test_case_0_aad: [uint8_t; 20] = [
    0xfe as libc::c_int as uint8_t,
    0xed as libc::c_int as uint8_t,
    0xfa as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0xde as libc::c_int as uint8_t,
    0xad as libc::c_int as uint8_t,
    0xbe as libc::c_int as uint8_t,
    0xef as libc::c_int as uint8_t,
    0xfe as libc::c_int as uint8_t,
    0xed as libc::c_int as uint8_t,
    0xfa as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0xde as libc::c_int as uint8_t,
    0xad as libc::c_int as uint8_t,
    0xbe as libc::c_int as uint8_t,
    0xef as libc::c_int as uint8_t,
    0xab as libc::c_int as uint8_t,
    0xad as libc::c_int as uint8_t,
    0xda as libc::c_int as uint8_t,
    0xd2 as libc::c_int as uint8_t,
];
static mut srtp_aes_gcm_128_test_case_0_ciphertext: [uint8_t; 76] = [
    0x42 as libc::c_int as uint8_t,
    0x83 as libc::c_int as uint8_t,
    0x1e as libc::c_int as uint8_t,
    0xc2 as libc::c_int as uint8_t,
    0x21 as libc::c_int as uint8_t,
    0x77 as libc::c_int as uint8_t,
    0x74 as libc::c_int as uint8_t,
    0x24 as libc::c_int as uint8_t,
    0x4b as libc::c_int as uint8_t,
    0x72 as libc::c_int as uint8_t,
    0x21 as libc::c_int as uint8_t,
    0xb7 as libc::c_int as uint8_t,
    0x84 as libc::c_int as uint8_t,
    0xd0 as libc::c_int as uint8_t,
    0xd4 as libc::c_int as uint8_t,
    0x9c as libc::c_int as uint8_t,
    0xe3 as libc::c_int as uint8_t,
    0xaa as libc::c_int as uint8_t,
    0x21 as libc::c_int as uint8_t,
    0x2f as libc::c_int as uint8_t,
    0x2c as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0xa4 as libc::c_int as uint8_t,
    0xe0 as libc::c_int as uint8_t,
    0x35 as libc::c_int as uint8_t,
    0xc1 as libc::c_int as uint8_t,
    0x7e as libc::c_int as uint8_t,
    0x23 as libc::c_int as uint8_t,
    0x29 as libc::c_int as uint8_t,
    0xac as libc::c_int as uint8_t,
    0xa1 as libc::c_int as uint8_t,
    0x2e as libc::c_int as uint8_t,
    0x21 as libc::c_int as uint8_t,
    0xd5 as libc::c_int as uint8_t,
    0x14 as libc::c_int as uint8_t,
    0xb2 as libc::c_int as uint8_t,
    0x54 as libc::c_int as uint8_t,
    0x66 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0x1c as libc::c_int as uint8_t,
    0x7d as libc::c_int as uint8_t,
    0x8f as libc::c_int as uint8_t,
    0x6a as libc::c_int as uint8_t,
    0x5a as libc::c_int as uint8_t,
    0xac as libc::c_int as uint8_t,
    0x84 as libc::c_int as uint8_t,
    0xaa as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x1b as libc::c_int as uint8_t,
    0xa3 as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0x39 as libc::c_int as uint8_t,
    0x6a as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0xac as libc::c_int as uint8_t,
    0x97 as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x58 as libc::c_int as uint8_t,
    0xe0 as libc::c_int as uint8_t,
    0x91 as libc::c_int as uint8_t,
    0x5b as libc::c_int as uint8_t,
    0xc9 as libc::c_int as uint8_t,
    0x4f as libc::c_int as uint8_t,
    0xbc as libc::c_int as uint8_t,
    0x32 as libc::c_int as uint8_t,
    0x21 as libc::c_int as uint8_t,
    0xa5 as libc::c_int as uint8_t,
    0xdb as libc::c_int as uint8_t,
    0x94 as libc::c_int as uint8_t,
    0xfa as libc::c_int as uint8_t,
    0xe9 as libc::c_int as uint8_t,
    0x5a as libc::c_int as uint8_t,
    0xe7 as libc::c_int as uint8_t,
    0x12 as libc::c_int as uint8_t,
    0x1a as libc::c_int as uint8_t,
    0x47 as libc::c_int as uint8_t,
];
static mut srtp_aes_gcm_128_test_case_0a: srtp_cipher_test_case_t = unsafe {
    {
        let mut init = srtp_cipher_test_case_t {
            key_length_octets: 12 as libc::c_int + 16 as libc::c_int,
            key: srtp_aes_gcm_128_test_case_0_key.as_ptr(),
            idx: srtp_aes_gcm_128_test_case_0_iv.as_ptr() as *mut _,
            plaintext_length_octets: 60 as libc::c_int as libc::c_uint,
            plaintext: srtp_aes_gcm_128_test_case_0_plaintext.as_ptr(),
            ciphertext_length_octets: 68 as libc::c_int as libc::c_uint,
            ciphertext: srtp_aes_gcm_128_test_case_0_ciphertext.as_ptr(),
            aad_length_octets: 20 as libc::c_int,
            aad: srtp_aes_gcm_128_test_case_0_aad.as_ptr(),
            tag_length_octets: 8 as libc::c_int,
            next_test_case: 0 as *const srtp_cipher_test_case_t,
        };
        init
    }
};
#[no_mangle]
pub static mut srtp_aes_gcm_128_test_case_0: srtp_cipher_test_case_t = unsafe {
    {
        let mut init = srtp_cipher_test_case_t {
            key_length_octets: 12 as libc::c_int + 16 as libc::c_int,
            key: srtp_aes_gcm_128_test_case_0_key.as_ptr(),
            idx: srtp_aes_gcm_128_test_case_0_iv.as_ptr() as *mut _,
            plaintext_length_octets: 60 as libc::c_int as libc::c_uint,
            plaintext: srtp_aes_gcm_128_test_case_0_plaintext.as_ptr(),
            ciphertext_length_octets: 76 as libc::c_int as libc::c_uint,
            ciphertext: srtp_aes_gcm_128_test_case_0_ciphertext.as_ptr(),
            aad_length_octets: 20 as libc::c_int,
            aad: srtp_aes_gcm_128_test_case_0_aad.as_ptr(),
            tag_length_octets: 16 as libc::c_int,
            next_test_case: &srtp_aes_gcm_128_test_case_0a
                as *const srtp_cipher_test_case_t,
        };
        init
    }
};
static mut srtp_aes_gcm_256_test_case_0_key: [uint8_t; 44] = [
    0xfe as libc::c_int as uint8_t,
    0xff as libc::c_int as uint8_t,
    0xe9 as libc::c_int as uint8_t,
    0x92 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x73 as libc::c_int as uint8_t,
    0x1c as libc::c_int as uint8_t,
    0xa5 as libc::c_int as uint8_t,
    0x59 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0xc5 as libc::c_int as uint8_t,
    0x54 as libc::c_int as uint8_t,
    0x66 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0x1c as libc::c_int as uint8_t,
    0xaf as libc::c_int as uint8_t,
    0xf5 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x9a as libc::c_int as uint8_t,
    0x21 as libc::c_int as uint8_t,
    0xd5 as libc::c_int as uint8_t,
    0x14 as libc::c_int as uint8_t,
    0xb2 as libc::c_int as uint8_t,
    0x6d as libc::c_int as uint8_t,
    0x6a as libc::c_int as uint8_t,
    0x8f as libc::c_int as uint8_t,
    0x94 as libc::c_int as uint8_t,
    0x67 as libc::c_int as uint8_t,
    0x30 as libc::c_int as uint8_t,
    0x83 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x1 as libc::c_int as uint8_t,
    0x2 as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0x4 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0x7 as libc::c_int as uint8_t,
    0x8 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
];
static mut srtp_aes_gcm_256_test_case_0_iv: [uint8_t; 12] = [
    0xca as libc::c_int as uint8_t,
    0xfe as libc::c_int as uint8_t,
    0xba as libc::c_int as uint8_t,
    0xbe as libc::c_int as uint8_t,
    0xfa as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0xdb as libc::c_int as uint8_t,
    0xad as libc::c_int as uint8_t,
    0xde as libc::c_int as uint8_t,
    0xca as libc::c_int as uint8_t,
    0xf8 as libc::c_int as uint8_t,
    0x88 as libc::c_int as uint8_t,
];
static mut srtp_aes_gcm_256_test_case_0_plaintext: [uint8_t; 60] = [
    0xd9 as libc::c_int as uint8_t,
    0x31 as libc::c_int as uint8_t,
    0x32 as libc::c_int as uint8_t,
    0x25 as libc::c_int as uint8_t,
    0xf8 as libc::c_int as uint8_t,
    0x84 as libc::c_int as uint8_t,
    0x6 as libc::c_int as uint8_t,
    0xe5 as libc::c_int as uint8_t,
    0xa5 as libc::c_int as uint8_t,
    0x59 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0xc5 as libc::c_int as uint8_t,
    0xaf as libc::c_int as uint8_t,
    0xf5 as libc::c_int as uint8_t,
    0x26 as libc::c_int as uint8_t,
    0x9a as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xa7 as libc::c_int as uint8_t,
    0xa9 as libc::c_int as uint8_t,
    0x53 as libc::c_int as uint8_t,
    0x15 as libc::c_int as uint8_t,
    0x34 as libc::c_int as uint8_t,
    0xf7 as libc::c_int as uint8_t,
    0xda as libc::c_int as uint8_t,
    0x2e as libc::c_int as uint8_t,
    0x4c as libc::c_int as uint8_t,
    0x30 as libc::c_int as uint8_t,
    0x3d as libc::c_int as uint8_t,
    0x8a as libc::c_int as uint8_t,
    0x31 as libc::c_int as uint8_t,
    0x8a as libc::c_int as uint8_t,
    0x72 as libc::c_int as uint8_t,
    0x1c as libc::c_int as uint8_t,
    0x3c as libc::c_int as uint8_t,
    0xc as libc::c_int as uint8_t,
    0x95 as libc::c_int as uint8_t,
    0x95 as libc::c_int as uint8_t,
    0x68 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0x53 as libc::c_int as uint8_t,
    0x2f as libc::c_int as uint8_t,
    0xcf as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x24 as libc::c_int as uint8_t,
    0x49 as libc::c_int as uint8_t,
    0xa6 as libc::c_int as uint8_t,
    0xb5 as libc::c_int as uint8_t,
    0x25 as libc::c_int as uint8_t,
    0xb1 as libc::c_int as uint8_t,
    0x6a as libc::c_int as uint8_t,
    0xed as libc::c_int as uint8_t,
    0xf5 as libc::c_int as uint8_t,
    0xaa as libc::c_int as uint8_t,
    0xd as libc::c_int as uint8_t,
    0xe6 as libc::c_int as uint8_t,
    0x57 as libc::c_int as uint8_t,
    0xba as libc::c_int as uint8_t,
    0x63 as libc::c_int as uint8_t,
    0x7b as libc::c_int as uint8_t,
    0x39 as libc::c_int as uint8_t,
];
static mut srtp_aes_gcm_256_test_case_0_aad: [uint8_t; 20] = [
    0xfe as libc::c_int as uint8_t,
    0xed as libc::c_int as uint8_t,
    0xfa as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0xde as libc::c_int as uint8_t,
    0xad as libc::c_int as uint8_t,
    0xbe as libc::c_int as uint8_t,
    0xef as libc::c_int as uint8_t,
    0xfe as libc::c_int as uint8_t,
    0xed as libc::c_int as uint8_t,
    0xfa as libc::c_int as uint8_t,
    0xce as libc::c_int as uint8_t,
    0xde as libc::c_int as uint8_t,
    0xad as libc::c_int as uint8_t,
    0xbe as libc::c_int as uint8_t,
    0xef as libc::c_int as uint8_t,
    0xab as libc::c_int as uint8_t,
    0xad as libc::c_int as uint8_t,
    0xda as libc::c_int as uint8_t,
    0xd2 as libc::c_int as uint8_t,
];
static mut srtp_aes_gcm_256_test_case_0_ciphertext: [uint8_t; 76] = [
    0xb as libc::c_int as uint8_t,
    0x11 as libc::c_int as uint8_t,
    0xcf as libc::c_int as uint8_t,
    0xaf as libc::c_int as uint8_t,
    0x68 as libc::c_int as uint8_t,
    0x4d as libc::c_int as uint8_t,
    0xae as libc::c_int as uint8_t,
    0x46 as libc::c_int as uint8_t,
    0xc7 as libc::c_int as uint8_t,
    0x90 as libc::c_int as uint8_t,
    0xb8 as libc::c_int as uint8_t,
    0x8e as libc::c_int as uint8_t,
    0xb7 as libc::c_int as uint8_t,
    0x6a as libc::c_int as uint8_t,
    0x76 as libc::c_int as uint8_t,
    0x2a as libc::c_int as uint8_t,
    0x94 as libc::c_int as uint8_t,
    0x82 as libc::c_int as uint8_t,
    0xca as libc::c_int as uint8_t,
    0xab as libc::c_int as uint8_t,
    0x3e as libc::c_int as uint8_t,
    0x39 as libc::c_int as uint8_t,
    0xd7 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x1b as libc::c_int as uint8_t,
    0xc7 as libc::c_int as uint8_t,
    0x93 as libc::c_int as uint8_t,
    0xed as libc::c_int as uint8_t,
    0x75 as libc::c_int as uint8_t,
    0x7f as libc::c_int as uint8_t,
    0x23 as libc::c_int as uint8_t,
    0x5a as libc::c_int as uint8_t,
    0xda as libc::c_int as uint8_t,
    0xfd as libc::c_int as uint8_t,
    0xd3 as libc::c_int as uint8_t,
    0xe2 as libc::c_int as uint8_t,
    0xe as libc::c_int as uint8_t,
    0x80 as libc::c_int as uint8_t,
    0x87 as libc::c_int as uint8_t,
    0xa9 as libc::c_int as uint8_t,
    0x6d as libc::c_int as uint8_t,
    0xd7 as libc::c_int as uint8_t,
    0xe2 as libc::c_int as uint8_t,
    0x6a as libc::c_int as uint8_t,
    0x7d as libc::c_int as uint8_t,
    0x5f as libc::c_int as uint8_t,
    0xb4 as libc::c_int as uint8_t,
    0x80 as libc::c_int as uint8_t,
    0xef as libc::c_int as uint8_t,
    0xef as libc::c_int as uint8_t,
    0xc5 as libc::c_int as uint8_t,
    0x29 as libc::c_int as uint8_t,
    0x12 as libc::c_int as uint8_t,
    0xd1 as libc::c_int as uint8_t,
    0xaa as libc::c_int as uint8_t,
    0x10 as libc::c_int as uint8_t,
    0x9 as libc::c_int as uint8_t,
    0xc9 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0xc1 as libc::c_int as uint8_t,
    0x45 as libc::c_int as uint8_t,
    0xbc as libc::c_int as uint8_t,
    0x3 as libc::c_int as uint8_t,
    0xe6 as libc::c_int as uint8_t,
    0xe1 as libc::c_int as uint8_t,
    0xac as libc::c_int as uint8_t,
    0xa as libc::c_int as uint8_t,
    0x9f as libc::c_int as uint8_t,
    0x81 as libc::c_int as uint8_t,
    0xcb as libc::c_int as uint8_t,
    0x8e as libc::c_int as uint8_t,
    0x5b as libc::c_int as uint8_t,
    0x46 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x63 as libc::c_int as uint8_t,
    0x1d as libc::c_int as uint8_t,
];
static mut srtp_aes_gcm_256_test_case_0a: srtp_cipher_test_case_t = unsafe {
    {
        let mut init = srtp_cipher_test_case_t {
            key_length_octets: 12 as libc::c_int + 32 as libc::c_int,
            key: srtp_aes_gcm_256_test_case_0_key.as_ptr(),
            idx: srtp_aes_gcm_256_test_case_0_iv.as_ptr() as *mut _,
            plaintext_length_octets: 60 as libc::c_int as libc::c_uint,
            plaintext: srtp_aes_gcm_256_test_case_0_plaintext.as_ptr(),
            ciphertext_length_octets: 68 as libc::c_int as libc::c_uint,
            ciphertext: srtp_aes_gcm_256_test_case_0_ciphertext.as_ptr(),
            aad_length_octets: 20 as libc::c_int,
            aad: srtp_aes_gcm_256_test_case_0_aad.as_ptr(),
            tag_length_octets: 8 as libc::c_int,
            next_test_case: 0 as *const srtp_cipher_test_case_t,
        };
        init
    }
};
#[no_mangle]
pub static mut srtp_aes_gcm_256_test_case_0: srtp_cipher_test_case_t = unsafe {
    {
        let mut init = srtp_cipher_test_case_t {
            key_length_octets: 12 as libc::c_int + 32 as libc::c_int,
            key: srtp_aes_gcm_256_test_case_0_key.as_ptr(),
            idx: srtp_aes_gcm_256_test_case_0_iv.as_ptr() as *mut _,
            plaintext_length_octets: 60 as libc::c_int as libc::c_uint,
            plaintext: srtp_aes_gcm_256_test_case_0_plaintext.as_ptr(),
            ciphertext_length_octets: 76 as libc::c_int as libc::c_uint,
            ciphertext: srtp_aes_gcm_256_test_case_0_ciphertext.as_ptr(),
            aad_length_octets: 20 as libc::c_int,
            aad: srtp_aes_gcm_256_test_case_0_aad.as_ptr(),
            tag_length_octets: 16 as libc::c_int,
            next_test_case: &srtp_aes_gcm_256_test_case_0a
                as *const srtp_cipher_test_case_t,
        };
        init
    }
};