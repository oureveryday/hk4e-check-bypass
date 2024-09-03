#![feature(str_from_utf16_endian)]

mod interceptor;
mod util;
mod modules;

use std::sync::Mutex;
use windows::Win32::{
    Foundation::HINSTANCE,
    System::{Console, SystemServices::DLL_PROCESS_ATTACH},
};
use winapi::um::libloaderapi::{LoadLibraryW};
use win_dbg_logger::output_debug_string;
use modules::{ModuleManager};
use crate::modules::{Check, MhyContext, Kick};
use lazy_static::lazy_static;

fn print_log(str: &str) {
    let log_str = format!("[zzzCheckBypass] {}\n", str);

    #[cfg(debug_assertions)]
    {
        println!("{}",&log_str);
    }

    output_debug_string(&log_str);
}

unsafe fn thread_func() {

    #[cfg(debug_assertions)]
    {
    Console::AllocConsole().unwrap();
    }

    print_log("zzz check bypass Init");
    let lib_name = "ext.dll\0";
    let lib_name_utf16: Vec<u16> = lib_name.encode_utf16().collect();
    LoadLibraryW(lib_name_utf16.as_ptr());
    print_log("Loaded ext.dll");
    util::disable_memprotect_guard();
    let mut module_manager = MODULE_MANAGER.lock().unwrap();
    let checkaddr = util::pattern_scan("GenshinImpact.exe","55 41 57 41 56 56 57 53 48 81 EC 98 02 00 00 48");
    let kickaddr = util::pattern_scan("GenshinImpact.exe","55 41 56 56 57 53 48 81 EC 00 01 00 00 48 8D AC 24 80 00 00 00 C7 45 7C 00 00 00 00");
    module_manager.enable(MhyContext::<Check>::new(checkaddr));
    module_manager.enable(MhyContext::<Kick>::new(kickaddr));
}

lazy_static! {
    static ref MODULE_MANAGER: Mutex<ModuleManager> = Mutex::new(ModuleManager::default());
}

#[no_mangle]
unsafe extern "system" fn DllMain(_: HINSTANCE, call_reason: u32, _: *mut ()) -> bool {
    if call_reason == DLL_PROCESS_ATTACH {
        std::thread::spawn(|| thread_func());
    }

    true
}
