#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
#[no_mangle]
pub static mut optind_s: libc::c_int = 0 as libc::c_int;
#[no_mangle]
pub static mut optarg_s: *mut libc::c_char = 0 as *const libc::c_char
    as *mut libc::c_char;
unsafe extern "C" fn getopt_check_character(
    mut c: libc::c_char,
    mut string: *const libc::c_char,
) -> libc::c_int {
    let mut max_string_len: libc::c_uint = 128 as libc::c_int as libc::c_uint;
    while *string as libc::c_int != 0 as libc::c_int {
        if max_string_len == 0 as libc::c_int as libc::c_uint {
            return 0 as libc::c_int;
        }
        max_string_len = max_string_len.wrapping_sub(1);
        let fresh0 = string;
        string = string.offset(1);
        if *fresh0 as libc::c_int == c as libc::c_int {
            if *string as libc::c_int == ':' as i32 {
                return 1 as libc::c_int
            } else {
                return 2 as libc::c_int
            }
        }
    }
    return 0 as libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn getopt_s(
    mut argc: libc::c_int,
    mut argv: *const *mut libc::c_char,
    mut optstring: *const libc::c_char,
) -> libc::c_int {
    if (optind_s + 1 as libc::c_int) < argc {
        let mut string: *mut libc::c_char = 0 as *mut libc::c_char;
        optind_s += 1;
        string = *argv.offset(optind_s as isize);
        if string.is_null() {
            return '?' as i32;
        }
        if *string.offset(0 as libc::c_int as isize) as libc::c_int != '-' as i32 {
            return -(1 as libc::c_int);
        }
        match getopt_check_character(
            *string.offset(1 as libc::c_int as isize),
            optstring,
        ) {
            1 => {
                if (optind_s + 1 as libc::c_int) < argc {
                    optind_s += 1;
                    optarg_s = *argv.offset(optind_s as isize);
                    return *string.offset(1 as libc::c_int as isize) as libc::c_int;
                } else {
                    return '?' as i32
                }
            }
            2 => return *string.offset(1 as libc::c_int as isize) as libc::c_int,
            0 | _ => return '?' as i32,
        }
    }
    return -(1 as libc::c_int);
}
