#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
extern "C" {
    fn srtp_err_report(
        level: srtp_err_reporting_level_t,
        format: *const libc::c_char,
        _: ...
    );
}
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
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
pub struct srtp_sha1_ctx_t {
    pub H: [uint32_t; 5],
    pub M: [uint32_t; 16],
    pub octets_in_buffer: libc::c_int,
    pub num_bits_in_msg: uint32_t,
}
#[inline]
unsafe extern "C" fn __bswap_32(mut __bsx: __uint32_t) -> __uint32_t {
    return (__bsx & 0xff000000 as libc::c_uint) >> 24 as libc::c_int
        | (__bsx & 0xff0000 as libc::c_uint) >> 8 as libc::c_int
        | (__bsx & 0xff00 as libc::c_uint) << 8 as libc::c_int
        | (__bsx & 0xff as libc::c_uint) << 24 as libc::c_int;
}
#[no_mangle]
pub static mut srtp_mod_sha1: srtp_debug_module_t = {
    let mut init = srtp_debug_module_t {
        on: 0 as libc::c_int,
        name: b"sha-1\0" as *const u8 as *const libc::c_char,
    };
    init
};
#[no_mangle]
pub static mut SHA_K0: uint32_t = 0x5a827999 as libc::c_int as uint32_t;
#[no_mangle]
pub static mut SHA_K1: uint32_t = 0x6ed9eba1 as libc::c_int as uint32_t;
#[no_mangle]
pub static mut SHA_K2: uint32_t = 0x8f1bbcdc as libc::c_uint;
#[no_mangle]
pub static mut SHA_K3: uint32_t = 0xca62c1d6 as libc::c_uint;
#[no_mangle]
pub unsafe extern "C" fn srtp_sha1_core(
    mut M: *const uint32_t,
    mut hash_value: *mut uint32_t,
) {
    let mut H0: uint32_t = 0;
    let mut H1: uint32_t = 0;
    let mut H2: uint32_t = 0;
    let mut H3: uint32_t = 0;
    let mut H4: uint32_t = 0;
    let mut W: [uint32_t; 80] = [0; 80];
    let mut A: uint32_t = 0;
    let mut B: uint32_t = 0;
    let mut C: uint32_t = 0;
    let mut D: uint32_t = 0;
    let mut E: uint32_t = 0;
    let mut TEMP: uint32_t = 0;
    let mut t: libc::c_int = 0;
    H0 = *hash_value.offset(0 as libc::c_int as isize);
    H1 = *hash_value.offset(1 as libc::c_int as isize);
    H2 = *hash_value.offset(2 as libc::c_int as isize);
    H3 = *hash_value.offset(3 as libc::c_int as isize);
    H4 = *hash_value.offset(4 as libc::c_int as isize);
    W[0 as libc::c_int as usize] = __bswap_32(*M.offset(0 as libc::c_int as isize));
    W[1 as libc::c_int as usize] = __bswap_32(*M.offset(1 as libc::c_int as isize));
    W[2 as libc::c_int as usize] = __bswap_32(*M.offset(2 as libc::c_int as isize));
    W[3 as libc::c_int as usize] = __bswap_32(*M.offset(3 as libc::c_int as isize));
    W[4 as libc::c_int as usize] = __bswap_32(*M.offset(4 as libc::c_int as isize));
    W[5 as libc::c_int as usize] = __bswap_32(*M.offset(5 as libc::c_int as isize));
    W[6 as libc::c_int as usize] = __bswap_32(*M.offset(6 as libc::c_int as isize));
    W[7 as libc::c_int as usize] = __bswap_32(*M.offset(7 as libc::c_int as isize));
    W[8 as libc::c_int as usize] = __bswap_32(*M.offset(8 as libc::c_int as isize));
    W[9 as libc::c_int as usize] = __bswap_32(*M.offset(9 as libc::c_int as isize));
    W[10 as libc::c_int as usize] = __bswap_32(*M.offset(10 as libc::c_int as isize));
    W[11 as libc::c_int as usize] = __bswap_32(*M.offset(11 as libc::c_int as isize));
    W[12 as libc::c_int as usize] = __bswap_32(*M.offset(12 as libc::c_int as isize));
    W[13 as libc::c_int as usize] = __bswap_32(*M.offset(13 as libc::c_int as isize));
    W[14 as libc::c_int as usize] = __bswap_32(*M.offset(14 as libc::c_int as isize));
    W[15 as libc::c_int as usize] = __bswap_32(*M.offset(15 as libc::c_int as isize));
    TEMP = W[13 as libc::c_int as usize] ^ W[8 as libc::c_int as usize]
        ^ W[2 as libc::c_int as usize] ^ W[0 as libc::c_int as usize];
    W[16 as libc::c_int as usize] = TEMP << 1 as libc::c_int | TEMP >> 31 as libc::c_int;
    TEMP = W[14 as libc::c_int as usize] ^ W[9 as libc::c_int as usize]
        ^ W[3 as libc::c_int as usize] ^ W[1 as libc::c_int as usize];
    W[17 as libc::c_int as usize] = TEMP << 1 as libc::c_int | TEMP >> 31 as libc::c_int;
    TEMP = W[15 as libc::c_int as usize] ^ W[10 as libc::c_int as usize]
        ^ W[4 as libc::c_int as usize] ^ W[2 as libc::c_int as usize];
    W[18 as libc::c_int as usize] = TEMP << 1 as libc::c_int | TEMP >> 31 as libc::c_int;
    TEMP = W[16 as libc::c_int as usize] ^ W[11 as libc::c_int as usize]
        ^ W[5 as libc::c_int as usize] ^ W[3 as libc::c_int as usize];
    W[19 as libc::c_int as usize] = TEMP << 1 as libc::c_int | TEMP >> 31 as libc::c_int;
    TEMP = W[17 as libc::c_int as usize] ^ W[12 as libc::c_int as usize]
        ^ W[6 as libc::c_int as usize] ^ W[4 as libc::c_int as usize];
    W[20 as libc::c_int as usize] = TEMP << 1 as libc::c_int | TEMP >> 31 as libc::c_int;
    TEMP = W[18 as libc::c_int as usize] ^ W[13 as libc::c_int as usize]
        ^ W[7 as libc::c_int as usize] ^ W[5 as libc::c_int as usize];
    W[21 as libc::c_int as usize] = TEMP << 1 as libc::c_int | TEMP >> 31 as libc::c_int;
    TEMP = W[19 as libc::c_int as usize] ^ W[14 as libc::c_int as usize]
        ^ W[8 as libc::c_int as usize] ^ W[6 as libc::c_int as usize];
    W[22 as libc::c_int as usize] = TEMP << 1 as libc::c_int | TEMP >> 31 as libc::c_int;
    TEMP = W[20 as libc::c_int as usize] ^ W[15 as libc::c_int as usize]
        ^ W[9 as libc::c_int as usize] ^ W[7 as libc::c_int as usize];
    W[23 as libc::c_int as usize] = TEMP << 1 as libc::c_int | TEMP >> 31 as libc::c_int;
    TEMP = W[21 as libc::c_int as usize] ^ W[16 as libc::c_int as usize]
        ^ W[10 as libc::c_int as usize] ^ W[8 as libc::c_int as usize];
    W[24 as libc::c_int as usize] = TEMP << 1 as libc::c_int | TEMP >> 31 as libc::c_int;
    TEMP = W[22 as libc::c_int as usize] ^ W[17 as libc::c_int as usize]
        ^ W[11 as libc::c_int as usize] ^ W[9 as libc::c_int as usize];
    W[25 as libc::c_int as usize] = TEMP << 1 as libc::c_int | TEMP >> 31 as libc::c_int;
    TEMP = W[23 as libc::c_int as usize] ^ W[18 as libc::c_int as usize]
        ^ W[12 as libc::c_int as usize] ^ W[10 as libc::c_int as usize];
    W[26 as libc::c_int as usize] = TEMP << 1 as libc::c_int | TEMP >> 31 as libc::c_int;
    TEMP = W[24 as libc::c_int as usize] ^ W[19 as libc::c_int as usize]
        ^ W[13 as libc::c_int as usize] ^ W[11 as libc::c_int as usize];
    W[27 as libc::c_int as usize] = TEMP << 1 as libc::c_int | TEMP >> 31 as libc::c_int;
    TEMP = W[25 as libc::c_int as usize] ^ W[20 as libc::c_int as usize]
        ^ W[14 as libc::c_int as usize] ^ W[12 as libc::c_int as usize];
    W[28 as libc::c_int as usize] = TEMP << 1 as libc::c_int | TEMP >> 31 as libc::c_int;
    TEMP = W[26 as libc::c_int as usize] ^ W[21 as libc::c_int as usize]
        ^ W[15 as libc::c_int as usize] ^ W[13 as libc::c_int as usize];
    W[29 as libc::c_int as usize] = TEMP << 1 as libc::c_int | TEMP >> 31 as libc::c_int;
    TEMP = W[27 as libc::c_int as usize] ^ W[22 as libc::c_int as usize]
        ^ W[16 as libc::c_int as usize] ^ W[14 as libc::c_int as usize];
    W[30 as libc::c_int as usize] = TEMP << 1 as libc::c_int | TEMP >> 31 as libc::c_int;
    TEMP = W[28 as libc::c_int as usize] ^ W[23 as libc::c_int as usize]
        ^ W[17 as libc::c_int as usize] ^ W[15 as libc::c_int as usize];
    W[31 as libc::c_int as usize] = TEMP << 1 as libc::c_int | TEMP >> 31 as libc::c_int;
    t = 32 as libc::c_int;
    while t < 80 as libc::c_int {
        TEMP = W[(t - 3 as libc::c_int) as usize] ^ W[(t - 8 as libc::c_int) as usize]
            ^ W[(t - 14 as libc::c_int) as usize] ^ W[(t - 16 as libc::c_int) as usize];
        W[t as usize] = TEMP << 1 as libc::c_int | TEMP >> 31 as libc::c_int;
        t += 1;
    }
    A = H0;
    B = H1;
    C = H2;
    D = H3;
    E = H4;
    t = 0 as libc::c_int;
    while t < 20 as libc::c_int {
        TEMP = (A << 5 as libc::c_int | A >> 27 as libc::c_int)
            .wrapping_add(B & C | !B & D)
            .wrapping_add(E)
            .wrapping_add(W[t as usize])
            .wrapping_add(SHA_K0);
        E = D;
        D = C;
        C = B << 30 as libc::c_int | B >> 2 as libc::c_int;
        B = A;
        A = TEMP;
        t += 1;
    }
    while t < 40 as libc::c_int {
        TEMP = (A << 5 as libc::c_int | A >> 27 as libc::c_int)
            .wrapping_add(B ^ C ^ D)
            .wrapping_add(E)
            .wrapping_add(W[t as usize])
            .wrapping_add(SHA_K1);
        E = D;
        D = C;
        C = B << 30 as libc::c_int | B >> 2 as libc::c_int;
        B = A;
        A = TEMP;
        t += 1;
    }
    while t < 60 as libc::c_int {
        TEMP = (A << 5 as libc::c_int | A >> 27 as libc::c_int)
            .wrapping_add(B & C | B & D | C & D)
            .wrapping_add(E)
            .wrapping_add(W[t as usize])
            .wrapping_add(SHA_K2);
        E = D;
        D = C;
        C = B << 30 as libc::c_int | B >> 2 as libc::c_int;
        B = A;
        A = TEMP;
        t += 1;
    }
    while t < 80 as libc::c_int {
        TEMP = (A << 5 as libc::c_int | A >> 27 as libc::c_int)
            .wrapping_add(B ^ C ^ D)
            .wrapping_add(E)
            .wrapping_add(W[t as usize])
            .wrapping_add(SHA_K3);
        E = D;
        D = C;
        C = B << 30 as libc::c_int | B >> 2 as libc::c_int;
        B = A;
        A = TEMP;
        t += 1;
    }
    *hash_value.offset(0 as libc::c_int as isize) = H0.wrapping_add(A);
    *hash_value.offset(1 as libc::c_int as isize) = H1.wrapping_add(B);
    *hash_value.offset(2 as libc::c_int as isize) = H2.wrapping_add(C);
    *hash_value.offset(3 as libc::c_int as isize) = H3.wrapping_add(D);
    *hash_value.offset(4 as libc::c_int as isize) = H4.wrapping_add(E);
}
#[no_mangle]
pub unsafe extern "C" fn srtp_sha1_init(mut ctx: *mut srtp_sha1_ctx_t) {
    (*ctx).H[0 as libc::c_int as usize] = 0x67452301 as libc::c_int as uint32_t;
    (*ctx).H[1 as libc::c_int as usize] = 0xefcdab89 as libc::c_uint;
    (*ctx).H[2 as libc::c_int as usize] = 0x98badcfe as libc::c_uint;
    (*ctx).H[3 as libc::c_int as usize] = 0x10325476 as libc::c_int as uint32_t;
    (*ctx).H[4 as libc::c_int as usize] = 0xc3d2e1f0 as libc::c_uint;
    (*ctx).octets_in_buffer = 0 as libc::c_int;
    (*ctx).num_bits_in_msg = 0 as libc::c_int as uint32_t;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_sha1_update(
    mut ctx: *mut srtp_sha1_ctx_t,
    mut msg: *const uint8_t,
    mut octets_in_msg: libc::c_int,
) {
    let mut i: libc::c_int = 0;
    let mut buf: *mut uint8_t = ((*ctx).M).as_mut_ptr() as *mut uint8_t;
    (*ctx)
        .num_bits_in_msg = ((*ctx).num_bits_in_msg as libc::c_uint)
        .wrapping_add((octets_in_msg * 8 as libc::c_int) as libc::c_uint) as uint32_t
        as uint32_t;
    while octets_in_msg > 0 as libc::c_int {
        if octets_in_msg + (*ctx).octets_in_buffer >= 64 as libc::c_int {
            octets_in_msg -= 64 as libc::c_int - (*ctx).octets_in_buffer;
            i = (*ctx).octets_in_buffer;
            while i < 64 as libc::c_int {
                let fresh0 = msg;
                msg = msg.offset(1);
                *buf.offset(i as isize) = *fresh0;
                i += 1;
            }
            (*ctx).octets_in_buffer = 0 as libc::c_int;
            if srtp_mod_sha1.on != 0 {
                srtp_err_report(
                    srtp_err_level_debug,
                    b"%s: (update) running srtp_sha1_core()\n\0" as *const u8
                        as *const libc::c_char,
                    srtp_mod_sha1.name,
                );
            }
            srtp_sha1_core(
                ((*ctx).M).as_mut_ptr() as *const uint32_t,
                ((*ctx).H).as_mut_ptr(),
            );
        } else {
            if srtp_mod_sha1.on != 0 {
                srtp_err_report(
                    srtp_err_level_debug,
                    b"%s: (update) not running srtp_sha1_core()\n\0" as *const u8
                        as *const libc::c_char,
                    srtp_mod_sha1.name,
                );
            }
            i = (*ctx).octets_in_buffer;
            while i < (*ctx).octets_in_buffer + octets_in_msg {
                let fresh1 = msg;
                msg = msg.offset(1);
                *buf.offset(i as isize) = *fresh1;
                i += 1;
            }
            (*ctx).octets_in_buffer += octets_in_msg;
            octets_in_msg = 0 as libc::c_int;
        }
    }
}
#[no_mangle]
pub unsafe extern "C" fn srtp_sha1_final(
    mut ctx: *mut srtp_sha1_ctx_t,
    mut output: *mut uint32_t,
) {
    let mut A: uint32_t = 0;
    let mut B: uint32_t = 0;
    let mut C: uint32_t = 0;
    let mut D: uint32_t = 0;
    let mut E: uint32_t = 0;
    let mut TEMP: uint32_t = 0;
    let mut W: [uint32_t; 80] = [0; 80];
    let mut i: libc::c_int = 0;
    let mut t: libc::c_int = 0;
    let mut tail: libc::c_int = (*ctx).octets_in_buffer % 4 as libc::c_int;
    i = 0 as libc::c_int;
    while i < ((*ctx).octets_in_buffer + 3 as libc::c_int) / 4 as libc::c_int {
        W[i as usize] = __bswap_32((*ctx).M[i as usize]);
        i += 1;
    }
    match tail {
        3 => {
            W[(i - 1 as libc::c_int)
                as usize] = __bswap_32((*ctx).M[(i - 1 as libc::c_int) as usize])
                & 0xffffff00 as libc::c_uint | 0x80 as libc::c_int as libc::c_uint;
            W[i as usize] = 0 as libc::c_int as uint32_t;
        }
        2 => {
            W[(i - 1 as libc::c_int)
                as usize] = __bswap_32((*ctx).M[(i - 1 as libc::c_int) as usize])
                & 0xffff0000 as libc::c_uint | 0x8000 as libc::c_int as libc::c_uint;
            W[i as usize] = 0 as libc::c_int as uint32_t;
        }
        1 => {
            W[(i - 1 as libc::c_int)
                as usize] = __bswap_32((*ctx).M[(i - 1 as libc::c_int) as usize])
                & 0xff000000 as libc::c_uint | 0x800000 as libc::c_int as libc::c_uint;
            W[i as usize] = 0 as libc::c_int as uint32_t;
        }
        0 => {
            W[i as usize] = 0x80000000 as libc::c_uint;
        }
        _ => {}
    }
    i += 1;
    while i < 15 as libc::c_int {
        W[i as usize] = 0 as libc::c_int as uint32_t;
        i += 1;
    }
    if (*ctx).octets_in_buffer < 56 as libc::c_int {
        W[15 as libc::c_int as usize] = (*ctx).num_bits_in_msg;
    } else if (*ctx).octets_in_buffer < 60 as libc::c_int {
        W[15 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    }
    t = 16 as libc::c_int;
    while t < 80 as libc::c_int {
        TEMP = W[(t - 3 as libc::c_int) as usize] ^ W[(t - 8 as libc::c_int) as usize]
            ^ W[(t - 14 as libc::c_int) as usize] ^ W[(t - 16 as libc::c_int) as usize];
        W[t as usize] = TEMP << 1 as libc::c_int | TEMP >> 31 as libc::c_int;
        t += 1;
    }
    A = (*ctx).H[0 as libc::c_int as usize];
    B = (*ctx).H[1 as libc::c_int as usize];
    C = (*ctx).H[2 as libc::c_int as usize];
    D = (*ctx).H[3 as libc::c_int as usize];
    E = (*ctx).H[4 as libc::c_int as usize];
    t = 0 as libc::c_int;
    while t < 20 as libc::c_int {
        TEMP = (A << 5 as libc::c_int | A >> 27 as libc::c_int)
            .wrapping_add(B & C | !B & D)
            .wrapping_add(E)
            .wrapping_add(W[t as usize])
            .wrapping_add(SHA_K0);
        E = D;
        D = C;
        C = B << 30 as libc::c_int | B >> 2 as libc::c_int;
        B = A;
        A = TEMP;
        t += 1;
    }
    while t < 40 as libc::c_int {
        TEMP = (A << 5 as libc::c_int | A >> 27 as libc::c_int)
            .wrapping_add(B ^ C ^ D)
            .wrapping_add(E)
            .wrapping_add(W[t as usize])
            .wrapping_add(SHA_K1);
        E = D;
        D = C;
        C = B << 30 as libc::c_int | B >> 2 as libc::c_int;
        B = A;
        A = TEMP;
        t += 1;
    }
    while t < 60 as libc::c_int {
        TEMP = (A << 5 as libc::c_int | A >> 27 as libc::c_int)
            .wrapping_add(B & C | B & D | C & D)
            .wrapping_add(E)
            .wrapping_add(W[t as usize])
            .wrapping_add(SHA_K2);
        E = D;
        D = C;
        C = B << 30 as libc::c_int | B >> 2 as libc::c_int;
        B = A;
        A = TEMP;
        t += 1;
    }
    while t < 80 as libc::c_int {
        TEMP = (A << 5 as libc::c_int | A >> 27 as libc::c_int)
            .wrapping_add(B ^ C ^ D)
            .wrapping_add(E)
            .wrapping_add(W[t as usize])
            .wrapping_add(SHA_K3);
        E = D;
        D = C;
        C = B << 30 as libc::c_int | B >> 2 as libc::c_int;
        B = A;
        A = TEMP;
        t += 1;
    }
    (*ctx)
        .H[0 as libc::c_int
        as usize] = ((*ctx).H[0 as libc::c_int as usize] as libc::c_uint).wrapping_add(A)
        as uint32_t as uint32_t;
    (*ctx)
        .H[1 as libc::c_int
        as usize] = ((*ctx).H[1 as libc::c_int as usize] as libc::c_uint).wrapping_add(B)
        as uint32_t as uint32_t;
    (*ctx)
        .H[2 as libc::c_int
        as usize] = ((*ctx).H[2 as libc::c_int as usize] as libc::c_uint).wrapping_add(C)
        as uint32_t as uint32_t;
    (*ctx)
        .H[3 as libc::c_int
        as usize] = ((*ctx).H[3 as libc::c_int as usize] as libc::c_uint).wrapping_add(D)
        as uint32_t as uint32_t;
    (*ctx)
        .H[4 as libc::c_int
        as usize] = ((*ctx).H[4 as libc::c_int as usize] as libc::c_uint).wrapping_add(E)
        as uint32_t as uint32_t;
    if srtp_mod_sha1.on != 0 {
        srtp_err_report(
            srtp_err_level_debug,
            b"%s: (final) running srtp_sha1_core()\n\0" as *const u8
                as *const libc::c_char,
            srtp_mod_sha1.name,
        );
    }
    if (*ctx).octets_in_buffer >= 56 as libc::c_int {
        if srtp_mod_sha1.on != 0 {
            srtp_err_report(
                srtp_err_level_debug,
                b"%s: (final) running srtp_sha1_core() again\n\0" as *const u8
                    as *const libc::c_char,
                srtp_mod_sha1.name,
            );
        }
        i = 0 as libc::c_int;
        while i < 15 as libc::c_int {
            W[i as usize] = 0 as libc::c_int as uint32_t;
            i += 1;
        }
        W[15 as libc::c_int as usize] = (*ctx).num_bits_in_msg;
        t = 16 as libc::c_int;
        while t < 80 as libc::c_int {
            TEMP = W[(t - 3 as libc::c_int) as usize]
                ^ W[(t - 8 as libc::c_int) as usize]
                ^ W[(t - 14 as libc::c_int) as usize]
                ^ W[(t - 16 as libc::c_int) as usize];
            W[t as usize] = TEMP << 1 as libc::c_int | TEMP >> 31 as libc::c_int;
            t += 1;
        }
        A = (*ctx).H[0 as libc::c_int as usize];
        B = (*ctx).H[1 as libc::c_int as usize];
        C = (*ctx).H[2 as libc::c_int as usize];
        D = (*ctx).H[3 as libc::c_int as usize];
        E = (*ctx).H[4 as libc::c_int as usize];
        t = 0 as libc::c_int;
        while t < 20 as libc::c_int {
            TEMP = (A << 5 as libc::c_int | A >> 27 as libc::c_int)
                .wrapping_add(B & C | !B & D)
                .wrapping_add(E)
                .wrapping_add(W[t as usize])
                .wrapping_add(SHA_K0);
            E = D;
            D = C;
            C = B << 30 as libc::c_int | B >> 2 as libc::c_int;
            B = A;
            A = TEMP;
            t += 1;
        }
        while t < 40 as libc::c_int {
            TEMP = (A << 5 as libc::c_int | A >> 27 as libc::c_int)
                .wrapping_add(B ^ C ^ D)
                .wrapping_add(E)
                .wrapping_add(W[t as usize])
                .wrapping_add(SHA_K1);
            E = D;
            D = C;
            C = B << 30 as libc::c_int | B >> 2 as libc::c_int;
            B = A;
            A = TEMP;
            t += 1;
        }
        while t < 60 as libc::c_int {
            TEMP = (A << 5 as libc::c_int | A >> 27 as libc::c_int)
                .wrapping_add(B & C | B & D | C & D)
                .wrapping_add(E)
                .wrapping_add(W[t as usize])
                .wrapping_add(SHA_K2);
            E = D;
            D = C;
            C = B << 30 as libc::c_int | B >> 2 as libc::c_int;
            B = A;
            A = TEMP;
            t += 1;
        }
        while t < 80 as libc::c_int {
            TEMP = (A << 5 as libc::c_int | A >> 27 as libc::c_int)
                .wrapping_add(B ^ C ^ D)
                .wrapping_add(E)
                .wrapping_add(W[t as usize])
                .wrapping_add(SHA_K3);
            E = D;
            D = C;
            C = B << 30 as libc::c_int | B >> 2 as libc::c_int;
            B = A;
            A = TEMP;
            t += 1;
        }
        (*ctx)
            .H[0 as libc::c_int
            as usize] = ((*ctx).H[0 as libc::c_int as usize] as libc::c_uint)
            .wrapping_add(A) as uint32_t as uint32_t;
        (*ctx)
            .H[1 as libc::c_int
            as usize] = ((*ctx).H[1 as libc::c_int as usize] as libc::c_uint)
            .wrapping_add(B) as uint32_t as uint32_t;
        (*ctx)
            .H[2 as libc::c_int
            as usize] = ((*ctx).H[2 as libc::c_int as usize] as libc::c_uint)
            .wrapping_add(C) as uint32_t as uint32_t;
        (*ctx)
            .H[3 as libc::c_int
            as usize] = ((*ctx).H[3 as libc::c_int as usize] as libc::c_uint)
            .wrapping_add(D) as uint32_t as uint32_t;
        (*ctx)
            .H[4 as libc::c_int
            as usize] = ((*ctx).H[4 as libc::c_int as usize] as libc::c_uint)
            .wrapping_add(E) as uint32_t as uint32_t;
    }
    *output
        .offset(
            0 as libc::c_int as isize,
        ) = __bswap_32((*ctx).H[0 as libc::c_int as usize]);
    *output
        .offset(
            1 as libc::c_int as isize,
        ) = __bswap_32((*ctx).H[1 as libc::c_int as usize]);
    *output
        .offset(
            2 as libc::c_int as isize,
        ) = __bswap_32((*ctx).H[2 as libc::c_int as usize]);
    *output
        .offset(
            3 as libc::c_int as isize,
        ) = __bswap_32((*ctx).H[3 as libc::c_int as usize]);
    *output
        .offset(
            4 as libc::c_int as isize,
        ) = __bswap_32((*ctx).H[4 as libc::c_int as usize]);
    (*ctx).octets_in_buffer = 0 as libc::c_int;
}
