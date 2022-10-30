#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
#![feature(extern_types)]
extern "C" {
    pub type _IO_wide_data;
    pub type _IO_codecvt;
    pub type _IO_marker;
    static mut stderr: *mut FILE;
    fn fprintf(_: *mut FILE, _: *const libc::c_char, _: ...) -> libc::c_int;
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
    fn strlen(_: *const libc::c_char) -> libc::c_ulong;
    fn abort() -> !;
    fn v128_bit_string(x: *mut v128_t) -> *mut libc::c_char;
    fn v128_hex_string(x: *mut v128_t) -> *mut libc::c_char;
    fn v128_left_shift(x: *mut v128_t, shift_index: libc::c_int);
    fn octet_string_set_to_zero(s: *mut libc::c_void, len: size_t);
    fn hex_string_to_octet_string(
        raw: *mut libc::c_char,
        hex: *mut libc::c_char,
        len: libc::c_int,
    ) -> libc::c_int;
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
#[derive(Copy, Clone)]
#[repr(C)]
pub union v128_t {
    pub v8: [uint8_t; 16],
    pub v16: [uint16_t; 8],
    pub v32: [uint32_t; 4],
    pub v64: [uint64_t; 2],
}
#[inline]
unsafe extern "C" fn __bswap_32(mut __bsx: __uint32_t) -> __uint32_t {
    return (__bsx & 0xff000000 as libc::c_uint) >> 24 as libc::c_int
        | (__bsx & 0xff0000 as libc::c_uint) >> 8 as libc::c_int
        | (__bsx & 0xff00 as libc::c_uint) << 8 as libc::c_int
        | (__bsx & 0xff as libc::c_uint) << 24 as libc::c_int;
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
unsafe fn main_0() -> libc::c_int {
    let mut i: libc::c_int = 0;
    let mut j: libc::c_int = 0;
    let mut x: v128_t = v128_t { v8: [0; 16] };
    let mut r: *mut libc::c_char = b"The Moving Finger writes; and, having writ,\nMoves on: nor all thy Piety nor Wit\nShall lure it back to cancel half a Line,\nNor all thy Tears wash out a Word of it.\0"
        as *const u8 as *const libc::c_char as *mut libc::c_char;
    let mut s: *mut libc::c_char = b"incomplet\0" as *const u8 as *const libc::c_char
        as *mut libc::c_char;
    print_string(r);
    print_string(s);
    byte_order();
    test_hex_string_funcs();
    j = 0 as libc::c_int;
    while j < 128 as libc::c_int {
        x.v32[0 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
        x.v32[1 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
        x.v32[2 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
        x.v32[3 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
        x.v32[(j >> 5 as libc::c_int) as usize]
            |= (1 as libc::c_int as uint32_t) << (j & 31 as libc::c_int);
        printf(b"%s\n\0" as *const u8 as *const libc::c_char, v128_bit_string(&mut x));
        x.v32[(j >> 5 as libc::c_int) as usize]
            &= !((1 as libc::c_int as uint32_t) << (j & 31 as libc::c_int));
        printf(b"%s\n\0" as *const u8 as *const libc::c_char, v128_bit_string(&mut x));
        j += 1;
    }
    printf(
        b"----------------------------------------------\n\0" as *const u8
            as *const libc::c_char,
    );
    x.v32[0 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    x.v32[1 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    x.v32[2 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    x.v32[3 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    i = 0 as libc::c_int;
    while i < 128 as libc::c_int {
        x.v32[(i >> 5 as libc::c_int) as usize]
            |= (1 as libc::c_int as uint32_t) << (i & 31 as libc::c_int);
        i += 1;
    }
    printf(b"%s\n\0" as *const u8 as *const libc::c_char, v128_bit_string(&mut x));
    printf(
        b"----------------------------------------------\n\0" as *const u8
            as *const libc::c_char,
    );
    x.v32[0 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    x.v32[1 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    x.v32[2 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    x.v32[3 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    x.v32[(127 as libc::c_int >> 5 as libc::c_int) as usize]
        |= (1 as libc::c_int as uint32_t) << (127 as libc::c_int & 31 as libc::c_int);
    i = 0 as libc::c_int;
    while i < 128 as libc::c_int {
        printf(b"%s\n\0" as *const u8 as *const libc::c_char, v128_bit_string(&mut x));
        v128_left_shift(&mut x, 1 as libc::c_int);
        i += 1;
    }
    printf(
        b"----------------------------------------------\n\0" as *const u8
            as *const libc::c_char,
    );
    i = 0 as libc::c_int;
    while i < 128 as libc::c_int {
        x.v32[0 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
        x.v32[1 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
        x.v32[2 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
        x.v32[3 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
        x.v32[(127 as libc::c_int >> 5 as libc::c_int) as usize]
            |= (1 as libc::c_int as uint32_t)
                << (127 as libc::c_int & 31 as libc::c_int);
        v128_left_shift(&mut x, i);
        printf(b"%s\n\0" as *const u8 as *const libc::c_char, v128_bit_string(&mut x));
        i += 1;
    }
    printf(
        b"----------------------------------------------\n\0" as *const u8
            as *const libc::c_char,
    );
    x.v32[0 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    x.v32[1 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    x.v32[2 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    x.v32[3 as libc::c_int as usize] = 0 as libc::c_int as uint32_t;
    i = 0 as libc::c_int;
    while i < 128 as libc::c_int {
        x.v32[(i >> 5 as libc::c_int) as usize]
            |= (1 as libc::c_int as uint32_t) << (i & 31 as libc::c_int);
        i += 2 as libc::c_int;
    }
    printf(
        b"bit_string: { %s }\n\0" as *const u8 as *const libc::c_char,
        v128_bit_string(&mut x),
    );
    printf(b"get_bit:    { \0" as *const u8 as *const libc::c_char);
    i = 0 as libc::c_int;
    while i < 128 as libc::c_int {
        if x.v32[(i >> 5 as libc::c_int) as usize] >> (i & 31 as libc::c_int)
            & 1 as libc::c_int as libc::c_uint == 1 as libc::c_int as libc::c_uint
        {
            printf(b"1\0" as *const u8 as *const libc::c_char);
        } else {
            printf(b"0\0" as *const u8 as *const libc::c_char);
        }
        i += 1;
    }
    printf(b" } \n\0" as *const u8 as *const libc::c_char);
    test_bswap();
    test_set_to_zero();
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn byte_order() {
    let mut i: size_t = 0;
    let mut e: v128_t = v128_t { v8: [0; 16] };
    printf(
        b"byte ordering of crypto/math datatypes:\n\0" as *const u8
            as *const libc::c_char,
    );
    i = 0 as libc::c_int as size_t;
    while i < ::core::mem::size_of::<v128_t>() as libc::c_ulong {
        e.v8[i as usize] = i as uint8_t;
        i = i.wrapping_add(1);
    }
    printf(
        b"v128_t: %s\n\0" as *const u8 as *const libc::c_char,
        v128_hex_string(&mut e),
    );
}
#[no_mangle]
pub unsafe extern "C" fn test_hex_string_funcs() {
    let mut hex1: [libc::c_char; 9] = *::core::mem::transmute::<
        &[u8; 9],
        &mut [libc::c_char; 9],
    >(b"abadcafe\0");
    let mut hex2: [libc::c_char; 22] = *::core::mem::transmute::<
        &[u8; 22],
        &mut [libc::c_char; 22],
    >(b"0123456789abcdefqqqqq\0");
    let mut raw: [libc::c_char; 10] = [0; 10];
    let mut len: libc::c_int = 0;
    len = hex_string_to_octet_string(
        raw.as_mut_ptr(),
        hex1.as_mut_ptr(),
        strlen(hex1.as_mut_ptr()) as libc::c_int,
    );
    printf(
        b"computed length: %d\tstring: %s\n\0" as *const u8 as *const libc::c_char,
        len,
        octet_string_hex_string(
            raw.as_mut_ptr() as *const libc::c_void,
            len / 2 as libc::c_int,
        ),
    );
    printf(
        b"expected length: %u\tstring: %s\n\0" as *const u8 as *const libc::c_char,
        strlen(hex1.as_mut_ptr()) as libc::c_uint,
        hex1.as_mut_ptr(),
    );
    len = hex_string_to_octet_string(
        raw.as_mut_ptr(),
        hex2.as_mut_ptr(),
        strlen(hex2.as_mut_ptr()) as libc::c_int,
    );
    printf(
        b"computed length: %d\tstring: %s\n\0" as *const u8 as *const libc::c_char,
        len,
        octet_string_hex_string(
            raw.as_mut_ptr() as *const libc::c_void,
            len / 2 as libc::c_int,
        ),
    );
    printf(
        b"expected length: %d\tstring: %s\n\0" as *const u8 as *const libc::c_char,
        16 as libc::c_int,
        b"0123456789abcdef\0" as *const u8 as *const libc::c_char,
    );
}
#[no_mangle]
pub unsafe extern "C" fn print_string(mut s: *mut libc::c_char) {
    let mut i: size_t = 0;
    printf(b"%s\n\0" as *const u8 as *const libc::c_char, s);
    printf(
        b"strlen(s) = %u\n\0" as *const u8 as *const libc::c_char,
        strlen(s) as libc::c_uint,
    );
    printf(b"{ \0" as *const u8 as *const libc::c_char);
    i = 0 as libc::c_int as size_t;
    while i < strlen(s) {
        printf(
            b"0x%x, \0" as *const u8 as *const libc::c_char,
            *s.offset(i as isize) as libc::c_int,
        );
        if i
            .wrapping_add(1 as libc::c_int as libc::c_ulong)
            .wrapping_rem(8 as libc::c_int as libc::c_ulong)
            == 0 as libc::c_int as libc::c_ulong
        {
            printf(b"\n   \0" as *const u8 as *const libc::c_char);
        }
        i = i.wrapping_add(1);
    }
    printf(b"}\n\0" as *const u8 as *const libc::c_char);
}
#[no_mangle]
pub unsafe extern "C" fn test_bswap() {
    let mut x: uint32_t = 0x11223344 as libc::c_int as uint32_t;
    let mut y: uint64_t = 0x1122334455667788 as libc::c_longlong as uint64_t;
    printf(
        b"before: %0x\nafter:  %0x\n\0" as *const u8 as *const libc::c_char,
        x,
        __bswap_32(x),
    );
    printf(
        b"before: %0llx\nafter:  %0llx\n\0" as *const u8 as *const libc::c_char,
        y as libc::c_ulonglong,
        __bswap_64(y) as libc::c_ulonglong,
    );
    y = 1234 as libc::c_int as uint64_t;
    printf(
        b"1234: %0llx\n\0" as *const u8 as *const libc::c_char,
        y as libc::c_ulonglong,
    );
    printf(
        b"as octet string: %s\n\0" as *const u8 as *const libc::c_char,
        octet_string_hex_string(
            &mut y as *mut uint64_t as *mut uint8_t as *const libc::c_void,
            8 as libc::c_int,
        ),
    );
    y = __bswap_64(y);
    printf(
        b"bswapped octet string: %s\n\0" as *const u8 as *const libc::c_char,
        octet_string_hex_string(
            &mut y as *mut uint64_t as *mut uint8_t as *const libc::c_void,
            8 as libc::c_int,
        ),
    );
}
#[no_mangle]
pub unsafe extern "C" fn test_set_to_zero() {
    let mut buffer: [uint8_t; 16] = [0; 16];
    let mut i: size_t = 0;
    i = 0 as libc::c_int as size_t;
    while i < 16 as libc::c_int as libc::c_ulong {
        buffer[i as usize] = (i & 0xff as libc::c_int as libc::c_ulong) as uint8_t;
        i = i.wrapping_add(1);
    }
    printf(
        b"Buffer before: %s\n\0" as *const u8 as *const libc::c_char,
        octet_string_hex_string(
            buffer.as_mut_ptr() as *const libc::c_void,
            16 as libc::c_int,
        ),
    );
    octet_string_set_to_zero(
        buffer.as_mut_ptr() as *mut libc::c_void,
        16 as libc::c_int as size_t,
    );
    printf(
        b"Buffer after: %s\n\0" as *const u8 as *const libc::c_char,
        octet_string_hex_string(
            buffer.as_mut_ptr() as *const libc::c_void,
            16 as libc::c_int,
        ),
    );
    i = 0 as libc::c_int as size_t;
    while i < 16 as libc::c_int as libc::c_ulong {
        if buffer[i as usize] != 0 {
            fprintf(
                stderr,
                b"Buffer contents not zero at position %zu (is %d)\n\0" as *const u8
                    as *const libc::c_char,
                i,
                buffer[i as usize] as libc::c_int,
            );
            abort();
        }
        i = i.wrapping_add(1);
    }
}
pub fn main() {
    unsafe { ::std::process::exit(main_0() as i32) }
}
