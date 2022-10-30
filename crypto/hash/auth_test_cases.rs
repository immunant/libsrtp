#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
pub type __uint8_t = libc::c_uchar;
pub type uint8_t = __uint8_t;
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
static mut srtp_hmac_test_case_0_key: [uint8_t; 20] = [
    0xb as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
    0xb as libc::c_int as uint8_t,
];
static mut srtp_hmac_test_case_0_data: [uint8_t; 8] = [
    0x48 as libc::c_int as uint8_t,
    0x69 as libc::c_int as uint8_t,
    0x20 as libc::c_int as uint8_t,
    0x54 as libc::c_int as uint8_t,
    0x68 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
    0x72 as libc::c_int as uint8_t,
    0x65 as libc::c_int as uint8_t,
];
static mut srtp_hmac_test_case_0_tag: [uint8_t; 20] = [
    0xb6 as libc::c_int as uint8_t,
    0x17 as libc::c_int as uint8_t,
    0x31 as libc::c_int as uint8_t,
    0x86 as libc::c_int as uint8_t,
    0x55 as libc::c_int as uint8_t,
    0x5 as libc::c_int as uint8_t,
    0x72 as libc::c_int as uint8_t,
    0x64 as libc::c_int as uint8_t,
    0xe2 as libc::c_int as uint8_t,
    0x8b as libc::c_int as uint8_t,
    0xc0 as libc::c_int as uint8_t,
    0xb6 as libc::c_int as uint8_t,
    0xfb as libc::c_int as uint8_t,
    0x37 as libc::c_int as uint8_t,
    0x8c as libc::c_int as uint8_t,
    0x8e as libc::c_int as uint8_t,
    0xf1 as libc::c_int as uint8_t,
    0x46 as libc::c_int as uint8_t,
    0xbe as libc::c_int as uint8_t,
    0 as libc::c_int as uint8_t,
];
#[no_mangle]
pub static mut srtp_hmac_test_case_0: srtp_auth_test_case_t = unsafe {
    {
        let mut init = srtp_auth_test_case_t {
            key_length_octets: ::core::mem::size_of::<[uint8_t; 20]>() as libc::c_ulong
                as libc::c_int,
            key: srtp_hmac_test_case_0_key.as_ptr(),
            data_length_octets: ::core::mem::size_of::<[uint8_t; 8]>() as libc::c_ulong
                as libc::c_int,
            data: srtp_hmac_test_case_0_data.as_ptr(),
            tag_length_octets: ::core::mem::size_of::<[uint8_t; 20]>() as libc::c_ulong
                as libc::c_int,
            tag: srtp_hmac_test_case_0_tag.as_ptr(),
            next_test_case: 0 as *const srtp_auth_test_case_t,
        };
        init
    }
};
