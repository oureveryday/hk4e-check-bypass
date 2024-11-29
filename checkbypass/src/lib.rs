#![feature(str_from_utf16_endian)]
#![allow(unused_must_use)]
#![allow(unused_imports)]
#![allow(dead_code)]

mod interceptor;
mod util;
mod modules;

use std::sync::Mutex;
use windows::Win32::{
    Foundation::HINSTANCE,
    System::{Console, SystemServices::DLL_PROCESS_ATTACH},
};
use std::panic;
use std::ffi::CString;
use std::ptr::null_mut;
use winapi::um::libloaderapi::{LoadLibraryW,GetModuleFileNameA};
use winapi::um::winuser::{MessageBoxA, MB_OK, MB_ICONERROR};
use win_dbg_logger::output_debug_string;
use modules::{ModuleManager};
use crate::modules::{MhyContext, Patch1, Patch2};
use lazy_static::lazy_static;

fn print_log(str: &str) {
    let log_str = format!("[hk4eCheckBypass] {}\n", str);
    println!("{}",&log_str);
    output_debug_string(&log_str);
}

unsafe fn thread_func() {

    #[cfg(debug_assertions)]
    {
    Console::AllocConsole();
    }

    #[cfg(not(debug_assertions))]
    {
        panic::set_hook(Box::new(|panic_info| {
            let message = if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
                s
            } else {
                "Unknown panic occurred!\nPlease update bypass.\n(For more info use debug version)"
            };
    
            let c_message = CString::new(message).unwrap();
            let c_title = CString::new("Panic occurred!").unwrap();
    
            unsafe {
                MessageBoxA(null_mut(), c_message.as_ptr(), c_title.as_ptr(), MB_OK | MB_ICONERROR);
            }
        }));
    }

    print_log("hk4e check bypass Init");
    let lib_name = "ext.dll\0";
    let lib_name_utf16: Vec<u16> = lib_name.encode_utf16().collect();
    LoadLibraryW(lib_name_utf16.as_ptr());
    print_log("Loaded ext.dll");
    util::disable_memprotect_guard();
    let mut module_manager = MODULE_MANAGER.lock().unwrap();
    let addrs = util::pattern_scan_multi("YuanShen.exe", "55 41 57 41 56 41 54 56 57 53 48 81 EC A0 00 00 00 48 8D AC 24 80 00 00 00 48 C7 45 18 FE FF FF FF B1 49 31 D2 E8 ?? ?? ?? FF");
    if let Some(addrs) = addrs {
        match addrs.len() {
            0 => panic!("Failed to find pattern"),
            1 => {
                print_log("Found only 1 pattern");
                print_log(&format!("addr1: {:?}", addrs[0]));
                module_manager.enable(MhyContext::<Patch1>::new(Some(addrs[0])));
            }
            _ => {
                print_log("Pattern find success");
                print_log(&format!("addr1: {:?}", addrs[0]));
                print_log(&format!("addr2: {:?}", addrs[1]));
                module_manager.enable(MhyContext::<Patch1>::new(Some(addrs[0])));
                module_manager.enable(MhyContext::<Patch2>::new(Some(addrs[1])));
            }
        }
    } else {
        panic!("Failed to find pattern");
    }
    print_log(&format!("Hooked."));
}

lazy_static! {
    static ref MODULE_MANAGER: Mutex<ModuleManager> = Mutex::new(ModuleManager::default());
}

#[no_mangle]
unsafe extern "system" fn DllMain(_: HINSTANCE, call_reason: u32, _: *mut ()) -> bool {
    if call_reason == DLL_PROCESS_ATTACH {
        thread_func()
    }

    true
}
