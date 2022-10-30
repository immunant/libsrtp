#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
extern "C" {
    fn strchr(_: *const libc::c_char, _: libc::c_int) -> *mut libc::c_char;
}
pub type uint8_t = __uint8_t;
pub type __uint8_t = libc::c_uchar;
static mut bit_string: [libc::c_char; 1025] = [0; 1025];
#[inline]
unsafe extern "C" fn hex_char_to_nibble(mut c: uint8_t) -> libc::c_int {
    match c as libc::c_int {
        48 => return 0 as libc::c_int,
        49 => return 0x1 as libc::c_int,
        50 => return 0x2 as libc::c_int,
        51 => return 0x3 as libc::c_int,
        52 => return 0x4 as libc::c_int,
        53 => return 0x5 as libc::c_int,
        54 => return 0x6 as libc::c_int,
        55 => return 0x7 as libc::c_int,
        56 => return 0x8 as libc::c_int,
        57 => return 0x9 as libc::c_int,
        97 => return 0xa as libc::c_int,
        65 => return 0xa as libc::c_int,
        98 => return 0xb as libc::c_int,
        66 => return 0xb as libc::c_int,
        99 => return 0xc as libc::c_int,
        67 => return 0xc as libc::c_int,
        100 => return 0xd as libc::c_int,
        68 => return 0xd as libc::c_int,
        101 => return 0xe as libc::c_int,
        69 => return 0xe as libc::c_int,
        102 => return 0xf as libc::c_int,
        70 => return 0xf as libc::c_int,
        _ => return -(1 as libc::c_int),
    };
}
#[no_mangle]
pub unsafe extern "C" fn nibble_to_hex_char(mut nibble: uint8_t) -> uint8_t {
    let mut buf: [libc::c_char; 16] = [
        '0' as i32 as libc::c_char,
        '1' as i32 as libc::c_char,
        '2' as i32 as libc::c_char,
        '3' as i32 as libc::c_char,
        '4' as i32 as libc::c_char,
        '5' as i32 as libc::c_char,
        '6' as i32 as libc::c_char,
        '7' as i32 as libc::c_char,
        '8' as i32 as libc::c_char,
        '9' as i32 as libc::c_char,
        'a' as i32 as libc::c_char,
        'b' as i32 as libc::c_char,
        'c' as i32 as libc::c_char,
        'd' as i32 as libc::c_char,
        'e' as i32 as libc::c_char,
        'f' as i32 as libc::c_char,
    ];
    return buf[(nibble as libc::c_int & 0xf as libc::c_int) as usize] as uint8_t;
}
#[no_mangle]
pub unsafe extern "C" fn hex_string_to_octet_string(
    mut raw: *mut libc::c_char,
    mut hex: *mut libc::c_char,
    mut len: libc::c_int,
) -> libc::c_int {
    let mut x: uint8_t = 0;
    let mut tmp: libc::c_int = 0;
    let mut hex_len: libc::c_int = 0;
    hex_len = 0 as libc::c_int;
    while hex_len < len {
        tmp = hex_char_to_nibble(*hex.offset(0 as libc::c_int as isize) as uint8_t);
        if tmp == -(1 as libc::c_int) {
            return hex_len;
        }
        x = (tmp << 4 as libc::c_int) as uint8_t;
        hex_len += 1;
        tmp = hex_char_to_nibble(*hex.offset(1 as libc::c_int as isize) as uint8_t);
        if tmp == -(1 as libc::c_int) {
            return hex_len;
        }
        x = (x as libc::c_int | tmp & 0xff as libc::c_int) as uint8_t;
        hex_len += 1;
        let fresh0 = raw;
        raw = raw.offset(1);
        *fresh0 = x as libc::c_char;
        hex = hex.offset(2 as libc::c_int as isize);
    }
    return hex_len;
}
#[no_mangle]
pub unsafe extern "C" fn octet_string_hex_string(
    mut s: *const libc::c_void,
    mut length: libc::c_int,
) -> *mut libc::c_char {
    let mut str: *const uint8_t = s as *const uint8_t;
    let mut i: libc::c_int = 0;
    length *= 2 as libc::c_int;
    if length > 1024 as libc::c_int {
        length = 1024 as libc::c_int;
    }
    i = 0 as libc::c_int;
    while i < length {
        bit_string[i
            as usize] = nibble_to_hex_char(
            (*str as libc::c_int >> 4 as libc::c_int) as uint8_t,
        ) as libc::c_char;
        let fresh1 = str;
        str = str.offset(1);
        bit_string[(i + 1 as libc::c_int)
            as usize] = nibble_to_hex_char(
            (*fresh1 as libc::c_int & 0xf as libc::c_int) as uint8_t,
        ) as libc::c_char;
        i += 2 as libc::c_int;
    }
    bit_string[i as usize] = 0 as libc::c_int as libc::c_char;
    return bit_string.as_mut_ptr();
}
static mut b64chars: [libc::c_char; 65] = unsafe {
    *::core::mem::transmute::<
        &[u8; 65],
        &[libc::c_char; 65],
    >(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/\0")
};
unsafe extern "C" fn base64_block_to_octet_triple(
    mut out: *mut libc::c_char,
    mut in_0: *mut libc::c_char,
) -> libc::c_int {
    let mut sextets: [libc::c_uchar; 4] = [0 as libc::c_int as libc::c_uchar, 0, 0, 0];
    let mut j: libc::c_int = 0 as libc::c_int;
    let mut i: libc::c_int = 0;
    i = 0 as libc::c_int;
    while i < 4 as libc::c_int {
        let mut p: *mut libc::c_char = strchr(
            b64chars.as_ptr(),
            *in_0.offset(i as isize) as libc::c_int,
        );
        if !p.is_null() {
            sextets[i
                as usize] = p.offset_from(b64chars.as_ptr()) as libc::c_long
                as libc::c_uchar;
        } else {
            j += 1;
        }
        i += 1;
    }
    *out
        .offset(
            0 as libc::c_int as isize,
        ) = ((sextets[0 as libc::c_int as usize] as libc::c_int) << 2 as libc::c_int
        | sextets[1 as libc::c_int as usize] as libc::c_int >> 4 as libc::c_int)
        as libc::c_char;
    if j < 2 as libc::c_int {
        *out
            .offset(
                1 as libc::c_int as isize,
            ) = ((sextets[1 as libc::c_int as usize] as libc::c_int) << 4 as libc::c_int
            | sextets[2 as libc::c_int as usize] as libc::c_int >> 2 as libc::c_int)
            as libc::c_char;
    }
    if j < 1 as libc::c_int {
        *out
            .offset(
                2 as libc::c_int as isize,
            ) = ((sextets[2 as libc::c_int as usize] as libc::c_int) << 6 as libc::c_int
            | sextets[3 as libc::c_int as usize] as libc::c_int) as libc::c_char;
    }
    return j;
}
#[no_mangle]
pub unsafe extern "C" fn base64_string_to_octet_string(
    mut out: *mut libc::c_char,
    mut pad: *mut libc::c_int,
    mut in_0: *mut libc::c_char,
    mut len: libc::c_int,
) -> libc::c_int {
    let mut k: libc::c_int = 0 as libc::c_int;
    let mut i: libc::c_int = 0 as libc::c_int;
    let mut j: libc::c_int = 0 as libc::c_int;
    if len % 4 as libc::c_int != 0 as libc::c_int {
        return 0 as libc::c_int;
    }
    while i < len && j == 0 as libc::c_int {
        j = base64_block_to_octet_triple(
            out.offset(k as isize),
            in_0.offset(i as isize),
        );
        k += 3 as libc::c_int;
        i += 4 as libc::c_int;
    }
    *pad = j;
    return i;
}
