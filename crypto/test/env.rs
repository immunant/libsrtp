#![allow(dead_code, mutable_transmutes, non_camel_case_types, non_snake_case, non_upper_case_globals, unused_assignments, unused_mut)]
extern "C" {
    fn printf(_: *const libc::c_char, _: ...) -> libc::c_int;
}
unsafe fn main_0() -> libc::c_int {
    let mut err_count: libc::c_int = 0 as libc::c_int;
    printf(
        b"CPU set to little-endian\t\t(WORDS_BIGENDIAN == 0)\n\0" as *const u8
            as *const libc::c_char,
    );
    printf(
        b"CPU set to CISC\t\t\t\t(CPU_CISC == 1)\n\0" as *const u8 as *const libc::c_char,
    );
    printf(
        b"using native 64-bit type\t\t(NO_64_BIT_MATH == 0)\n\0" as *const u8
            as *const libc::c_char,
    );
    if err_count != 0 {
        printf(
            b"warning: configuration is probably in error (found %d problems)\n\0"
                as *const u8 as *const libc::c_char,
            err_count,
        );
    }
    return err_count;
}
pub fn main() {
    unsafe { ::std::process::exit(main_0() as i32) }
}
