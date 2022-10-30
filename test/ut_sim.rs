#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
extern "C" {
    fn qsort(
        __base: *mut libc::c_void,
        __nmemb: size_t,
        __size: size_t,
        __compar: __compar_fn_t,
    );
    fn srtp_cipher_rand_for_tests(dest: *mut libc::c_void, len: uint32_t);
}
pub type size_t = libc::c_ulong;
pub type __uint8_t = libc::c_uchar;
pub type __uint32_t = libc::c_uint;
pub type __compar_fn_t = Option::<
    unsafe extern "C" fn(*const libc::c_void, *const libc::c_void) -> libc::c_int,
>;
pub type uint8_t = __uint8_t;
pub type uint32_t = __uint32_t;
#[derive(Copy, Clone)]
#[repr(C)]
pub struct ut_connection {
    pub index: uint32_t,
    pub buffer: [uint32_t; 160],
}
#[no_mangle]
pub unsafe extern "C" fn ut_compar(
    mut a: *const libc::c_void,
    mut b: *const libc::c_void,
) -> libc::c_int {
    let mut r: uint8_t = 0;
    srtp_cipher_rand_for_tests(
        &mut r as *mut uint8_t as *mut libc::c_void,
        ::core::mem::size_of::<uint8_t>() as libc::c_ulong as uint32_t,
    );
    return if r as libc::c_int > 255 as libc::c_int / 2 as libc::c_int {
        -(1 as libc::c_int)
    } else {
        1 as libc::c_int
    };
}
#[no_mangle]
pub unsafe extern "C" fn ut_init(mut utc: *mut ut_connection) {
    let mut i: libc::c_int = 0;
    (*utc).index = 0 as libc::c_int as uint32_t;
    i = 0 as libc::c_int;
    while i < 160 as libc::c_int {
        (*utc).buffer[i as usize] = i as uint32_t;
        i += 1;
    }
    qsort(
        ((*utc).buffer).as_mut_ptr() as *mut libc::c_void,
        160 as libc::c_int as size_t,
        ::core::mem::size_of::<uint32_t>() as libc::c_ulong,
        Some(
            ut_compar
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    );
    (*utc).index = (160 as libc::c_int - 1 as libc::c_int) as uint32_t;
}
#[no_mangle]
pub unsafe extern "C" fn ut_next_index(mut utc: *mut ut_connection) -> uint32_t {
    let mut tmp: uint32_t = 0;
    tmp = (*utc).buffer[0 as libc::c_int as usize];
    (*utc).index = ((*utc).index).wrapping_add(1);
    (*utc).buffer[0 as libc::c_int as usize] = (*utc).index;
    qsort(
        ((*utc).buffer).as_mut_ptr() as *mut libc::c_void,
        160 as libc::c_int as size_t,
        ::core::mem::size_of::<uint32_t>() as libc::c_ulong,
        Some(
            ut_compar
                as unsafe extern "C" fn(
                    *const libc::c_void,
                    *const libc::c_void,
                ) -> libc::c_int,
        ),
    );
    return tmp;
}
