use core::iter::once;
use std::ffi::{c_void, OsStr};

use patternscan::scan_first_match;
use std::io::Cursor;
use lazy_static::lazy_static;
use std::os::windows::ffi::OsStrExt;
use windows::core::{PCSTR, PCWSTR};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Memory::{
    VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS,
};

use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS};
use std::slice;

lazy_static! {
    pub static ref BASE: usize = unsafe { try_get_base_address("UnityPlayer.dll").unwrap() };
}

pub fn wide_str(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain(once(0)).collect()
}

pub unsafe fn try_get_base_address(module_name: &str) -> Option<usize> {
    let w_module_name = wide_str(module_name);

    match GetModuleHandleW(PCWSTR::from_raw(w_module_name.as_ptr())) {
        Ok(module) => Some(module.0 as usize),
        Err(_) => None,
    }
}

// VMProtect hooks NtProtectVirtualMemory to prevent changing protection of executable segments
// We use this trick to remove hook
pub unsafe fn disable_memprotect_guard() {
    let ntdll = wide_str("ntdll.dll");
    let ntdll = GetModuleHandleW(PCWSTR::from_raw(ntdll.as_ptr())).unwrap();
    let proc_addr = GetProcAddress(
        ntdll,
        PCSTR::from_raw(c"NtProtectVirtualMemory".to_bytes_with_nul().as_ptr()),
    )
    .unwrap();
    let nt_func =
        if GetProcAddress(ntdll, PCSTR::from_raw(c"wine_get_version".to_bytes_with_nul().as_ptr())).is_some() {
            GetProcAddress(ntdll, PCSTR::from_raw(c"NtPulseEvent".to_bytes_with_nul().as_ptr())).unwrap()
        } else {
            GetProcAddress(ntdll, PCSTR::from_raw(c"NtQuerySection".to_bytes_with_nul().as_ptr())).unwrap()
        };

    let mut old_prot = PAGE_PROTECTION_FLAGS(0);
    VirtualProtect(
        proc_addr as *const usize as *mut c_void,
        1,
        PAGE_EXECUTE_READWRITE,
        &mut old_prot,
    )
    .unwrap();

    let routine = nt_func as *mut u32;
    let routine_val = *(routine as *const usize);

    let lower_bits_mask = !(0xFFu64 << 32);
    let lower_bits = routine_val & lower_bits_mask as usize;

    let offset_val = *((routine as usize + 4) as *const u32);
    let upper_bits = ((offset_val as usize).wrapping_sub(1) as usize) << 32;

    let result = lower_bits | upper_bits;

    *(proc_addr as *mut usize) = result;

    VirtualProtect(
        proc_addr as *const usize as *mut c_void,
        1,
        old_prot,
        &mut old_prot,
    )
    .unwrap();
}

pub unsafe fn pattern_scan(module: &str, pattern: &str) -> Option<*mut u8> {
    let w_module_name = wide_str(module);
    
    let module_handle = match GetModuleHandleW(PCWSTR::from_raw(w_module_name.as_ptr())) {
        Ok(module) => Some(module.0 as usize),
        Err(_) => return None,
    };
    
    let module_handle_addr = module_handle.unwrap();
    let module_handle_ptr: *const _ = module_handle_addr as *const _;
    let mod_base = module_handle_addr as *const u8;
    let dos_header = unsafe { &*(mod_base as *const IMAGE_DOS_HEADER) };
    let nt_headers = unsafe { &*((mod_base.offset(dos_header.e_lfanew as isize)) as *const IMAGE_NT_HEADERS) };
    let size_of_image = nt_headers.OptionalHeader.SizeOfImage as usize;
    let memory_slice: &[u8] = unsafe { slice::from_raw_parts(module_handle_ptr, size_of_image) };
    let mut cursor = Cursor::new(memory_slice);
     
    let loc = scan_first_match(&mut cursor, pattern).unwrap();
    match loc {
        None => None,
        Some(loc) => Some((module_handle_ptr.wrapping_add(loc)) as *mut u8),
    }
}