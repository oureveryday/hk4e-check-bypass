#![feature(str_from_utf16_endian)]
use windows::Win32::Foundation::HINSTANCE;
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
//use windows::Win32::System::Console;

use std::thread;
use winapi::um::processthreadsapi::{GetCurrentThread,TerminateThread};
use win_dbg_logger::output_debug_string;


#[no_mangle]
#[allow(non_snake_case, unused_variables)]
unsafe extern "cdecl" fn Initialize() -> bool {
    unsafe {
        output_debug_string("[AntiCheatEMU] Initialize");
        thread::sleep(std::time::Duration::from_secs(2));
        output_debug_string("[AntiCheatEMU] TerminateThread");
        let thread = GetCurrentThread();
        TerminateThread(thread,0);
        output_debug_string("[AntiCheatEMU] TerminateThread failed");
    false
    }
}

unsafe fn thread_func() {

}

#[no_mangle]
unsafe extern "system" fn DllMain(_: HINSTANCE, call_reason: u32, _: *mut ()) -> bool {
    if call_reason == DLL_PROCESS_ATTACH {
        std::thread::spawn(|| thread_func());
    }

    true
}
