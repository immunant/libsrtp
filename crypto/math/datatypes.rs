#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
extern "C" {
    fn srtp_crypto_alloc(size: size_t) -> *mut libc::c_void;
    fn srtp_crypto_free(ptr: *mut libc::c_void);
    fn memset(
        _: *mut libc::c_void,
        _: libc::c_int,
        _: libc::c_ulong,
    ) -> *mut libc::c_void;
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
pub struct bitvector_t {
    pub length: uint32_t,
    pub word: *mut uint32_t,
}
static mut bit_string: [libc::c_char; 1025] = [0; 1025];
#[no_mangle]
pub unsafe extern "C" fn srtp_nibble_to_hex_char(mut nibble: uint8_t) -> uint8_t {
    static mut buf: [libc::c_char; 16] = [
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
pub unsafe extern "C" fn srtp_octet_string_hex_string(
    mut s: *const libc::c_void,
    mut length: libc::c_int,
) -> *mut libc::c_char {
    let mut str: *const uint8_t = s as *const uint8_t;
    let mut i: libc::c_int = 0;
    length *= 2 as libc::c_int;
    if length > 1024 as libc::c_int {
        length = 1024 as libc::c_int - 2 as libc::c_int;
    }
    i = 0 as libc::c_int;
    while i < length {
        bit_string[i
            as usize] = srtp_nibble_to_hex_char(
            (*str as libc::c_int >> 4 as libc::c_int) as uint8_t,
        ) as libc::c_char;
        let fresh0 = str;
        str = str.offset(1);
        bit_string[(i + 1 as libc::c_int)
            as usize] = srtp_nibble_to_hex_char(
            (*fresh0 as libc::c_int & 0xf as libc::c_int) as uint8_t,
        ) as libc::c_char;
        i += 2 as libc::c_int;
    }
    bit_string[i as usize] = 0 as libc::c_int as libc::c_char;
    return bit_string.as_mut_ptr();
}
#[no_mangle]
pub unsafe extern "C" fn v128_hex_string(mut x: *mut v128_t) -> *mut libc::c_char {
    let mut i: libc::c_int = 0;
    let mut j: libc::c_int = 0;
    j = 0 as libc::c_int;
    i = j;
    while i < 16 as libc::c_int {
        let fresh1 = j;
        j = j + 1;
        bit_string[fresh1
            as usize] = srtp_nibble_to_hex_char(
            ((*x).v8[i as usize] as libc::c_int >> 4 as libc::c_int) as uint8_t,
        ) as libc::c_char;
        let fresh2 = j;
        j = j + 1;
        bit_string[fresh2
            as usize] = srtp_nibble_to_hex_char(
            ((*x).v8[i as usize] as libc::c_int & 0xf as libc::c_int) as uint8_t,
        ) as libc::c_char;
        i += 1;
    }
    bit_string[j as usize] = 0 as libc::c_int as libc::c_char;
    return bit_string.as_mut_ptr();
}
#[no_mangle]
pub unsafe extern "C" fn v128_bit_string(mut x: *mut v128_t) -> *mut libc::c_char {
    let mut j: libc::c_int = 0;
    let mut i: libc::c_int = 0;
    let mut mask: uint32_t = 0;
    i = 0 as libc::c_int;
    j = i;
    while j < 4 as libc::c_int {
        mask = 0x80000000 as libc::c_uint;
        while mask > 0 as libc::c_int as libc::c_uint {
            if (*x).v32[j as usize] & mask != 0 {
                bit_string[i as usize] = '1' as i32 as libc::c_char;
            } else {
                bit_string[i as usize] = '0' as i32 as libc::c_char;
            }
            i += 1;
            mask >>= 1 as libc::c_int;
        }
        j += 1;
    }
    bit_string[128 as libc::c_int as usize] = 0 as libc::c_int as libc::c_char;
    return bit_string.as_mut_ptr();
}
#[no_mangle]
pub unsafe extern "C" fn v128_copy_octet_string(
    mut x: *mut v128_t,
    mut s: *const uint8_t,
) {
    (*x).v8[0 as libc::c_int as usize] = *s.offset(0 as libc::c_int as isize);
    (*x).v8[1 as libc::c_int as usize] = *s.offset(1 as libc::c_int as isize);
    (*x).v8[2 as libc::c_int as usize] = *s.offset(2 as libc::c_int as isize);
    (*x).v8[3 as libc::c_int as usize] = *s.offset(3 as libc::c_int as isize);
    (*x).v8[4 as libc::c_int as usize] = *s.offset(4 as libc::c_int as isize);
    (*x).v8[5 as libc::c_int as usize] = *s.offset(5 as libc::c_int as isize);
    (*x).v8[6 as libc::c_int as usize] = *s.offset(6 as libc::c_int as isize);
    (*x).v8[7 as libc::c_int as usize] = *s.offset(7 as libc::c_int as isize);
    (*x).v8[8 as libc::c_int as usize] = *s.offset(8 as libc::c_int as isize);
    (*x).v8[9 as libc::c_int as usize] = *s.offset(9 as libc::c_int as isize);
    (*x).v8[10 as libc::c_int as usize] = *s.offset(10 as libc::c_int as isize);
    (*x).v8[11 as libc::c_int as usize] = *s.offset(11 as libc::c_int as isize);
    (*x).v8[12 as libc::c_int as usize] = *s.offset(12 as libc::c_int as isize);
    (*x).v8[13 as libc::c_int as usize] = *s.offset(13 as libc::c_int as isize);
    (*x).v8[14 as libc::c_int as usize] = *s.offset(14 as libc::c_int as isize);
    (*x).v8[15 as libc::c_int as usize] = *s.offset(15 as libc::c_int as isize);
}
#[no_mangle]
pub unsafe extern "C" fn v128_left_shift(mut x: *mut v128_t, mut shift: libc::c_int) {
    let mut i: libc::c_int = 0;
    let base_index: libc::c_int = shift >> 5 as libc::c_int;
    let bit_index: libc::c_int = shift & 31 as libc::c_int;
    if shift > 127 as libc::c_int {
        (*x).v32[0 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
        (*x).v32[1 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
        (*x).v32[2 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
        (*x).v32[3 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
        return;
    }
    if bit_index == 0 as libc::c_int {
        i = 0 as libc::c_int;
        while i < 4 as libc::c_int - base_index {
            (*x).v32[i as usize] = (*x).v32[(i + base_index) as usize];
            i += 1;
        }
    } else {
        i = 0 as libc::c_int;
        while i < 4 as libc::c_int - base_index - 1 as libc::c_int {
            (*x)
                .v32[i
                as usize] = (*x).v32[(i + base_index) as usize] >> bit_index
                ^ (*x).v32[(i + base_index + 1 as libc::c_int) as usize]
                    << 32 as libc::c_int - bit_index;
            i += 1;
        }
        (*x)
            .v32[(4 as libc::c_int - base_index - 1 as libc::c_int)
            as usize] = (*x).v32[(4 as libc::c_int - 1 as libc::c_int) as usize]
            >> bit_index;
    }
    i = 4 as libc::c_int - base_index;
    while i < 4 as libc::c_int {
        (*x).v32[i as usize] = 0 as libc::c_int as uint32_t;
        i += 1;
    }
}
#[no_mangle]
pub unsafe extern "C" fn bitvector_alloc(
    mut v: *mut bitvector_t,
    mut length: libc::c_ulong,
) -> libc::c_int {
    let mut l: libc::c_ulong = 0;
    length = length
        .wrapping_add(32 as libc::c_int as libc::c_ulong)
        .wrapping_sub(1 as libc::c_int as libc::c_ulong)
        & !((32 as libc::c_int - 1 as libc::c_int) as libc::c_ulong);
    l = length
        .wrapping_div(32 as libc::c_int as libc::c_ulong)
        .wrapping_mul(4 as libc::c_int as libc::c_ulong);
    if l == 0 as libc::c_int as libc::c_ulong {
        (*v).word = 0 as *mut uint32_t;
        (*v).length = 0 as libc::c_int as uint32_t;
        return -(1 as libc::c_int);
    } else {
        (*v).word = srtp_crypto_alloc(l) as *mut uint32_t;
        if ((*v).word).is_null() {
            (*v).length = 0 as libc::c_int as uint32_t;
            return -(1 as libc::c_int);
        }
    }
    (*v).length = length as uint32_t;
    bitvector_set_to_zero(v);
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn bitvector_dealloc(mut v: *mut bitvector_t) {
    if !((*v).word).is_null() {
        srtp_crypto_free((*v).word as *mut libc::c_void);
    }
    (*v).word = 0 as *mut uint32_t;
    (*v).length = 0 as libc::c_int as uint32_t;
}
#[no_mangle]
pub unsafe extern "C" fn bitvector_set_to_zero(mut x: *mut bitvector_t) {
    memset(
        (*x).word as *mut libc::c_void,
        0 as libc::c_int,
        ((*x).length >> 3 as libc::c_int) as libc::c_ulong,
    );
}
#[no_mangle]
pub unsafe extern "C" fn bitvector_left_shift(
    mut x: *mut bitvector_t,
    mut shift: libc::c_int,
) {
    let mut i: libc::c_int = 0;
    let base_index: libc::c_int = shift >> 5 as libc::c_int;
    let bit_index: libc::c_int = shift & 31 as libc::c_int;
    let word_length: libc::c_int = ((*x).length >> 5 as libc::c_int) as libc::c_int;
    if shift >= (*x).length as libc::c_int {
        bitvector_set_to_zero(x);
        return;
    }
    if bit_index == 0 as libc::c_int {
        i = 0 as libc::c_int;
        while i < word_length - base_index {
            *((*x).word)
                .offset(i as isize) = *((*x).word).offset((i + base_index) as isize);
            i += 1;
        }
    } else {
        i = 0 as libc::c_int;
        while i < word_length - base_index - 1 as libc::c_int {
            *((*x).word)
                .offset(
                    i as isize,
                ) = *((*x).word).offset((i + base_index) as isize) >> bit_index
                ^ *((*x).word).offset((i + base_index + 1 as libc::c_int) as isize)
                    << 32 as libc::c_int - bit_index;
            i += 1;
        }
        *((*x).word)
            .offset(
                (word_length - base_index - 1 as libc::c_int) as isize,
            ) = *((*x).word).offset((word_length - 1 as libc::c_int) as isize)
            >> bit_index;
    }
    i = word_length - base_index;
    while i < word_length {
        *((*x).word).offset(i as isize) = 0 as libc::c_int as uint32_t;
        i += 1;
    }
}
#[no_mangle]
pub unsafe extern "C" fn srtp_octet_string_is_eq(
    mut a: *mut uint8_t,
    mut b: *mut uint8_t,
    mut len: libc::c_int,
) -> libc::c_int {
    let mut end: *mut uint8_t = b.offset(len as isize);
    let mut accumulator: uint8_t = 0 as libc::c_int as uint8_t;
    while b < end {
        let fresh3 = a;
        a = a.offset(1);
        let fresh4 = b;
        b = b.offset(1);
        accumulator = (accumulator as libc::c_int
            | *fresh3 as libc::c_int ^ *fresh4 as libc::c_int) as uint8_t;
    }
    return (accumulator as libc::c_int != 0 as libc::c_int) as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn srtp_cleanse(mut s: *mut libc::c_void, mut len: size_t) {
    let mut p: *mut libc::c_uchar = s as *mut libc::c_uchar;
    loop {
        let fresh5 = len;
        len = len.wrapping_sub(1);
        if !(fresh5 != 0) {
            break;
        }
        let fresh6 = p;
        p = p.offset(1);
        ::core::ptr::write_volatile(fresh6, 0 as libc::c_int as libc::c_uchar);
    };
}
#[no_mangle]
pub unsafe extern "C" fn octet_string_set_to_zero(
    mut s: *mut libc::c_void,
    mut len: size_t,
) {
    srtp_cleanse(s, len);
}
