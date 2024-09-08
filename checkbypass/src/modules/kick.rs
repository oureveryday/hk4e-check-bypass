use super::{MhyContext, MhyModule, ModuleType};
use anyhow::Result;
use ilhook::x64::Registers;
use std::ptr;
use winapi::um::memoryapi::VirtualProtect;
use winapi::um::winnt::{PAGE_EXECUTE_READWRITE};


pub struct Kick;

use win_dbg_logger::output_debug_string;
fn print_log(str: &str) {
    let log_str = format!("[hk4eCheckBypass] {}\n", str);

    #[cfg(debug_assertions)]
    {
        println!("{}",&log_str);
    }

    output_debug_string(&log_str);
}

impl MhyModule for MhyContext<Kick> {
    unsafe fn init(&mut self) -> Result<()> {
        if let Some(addr) = self.addr {

            let mut old_protect: u32 = 0;
            if VirtualProtect(addr as *mut _, 1, PAGE_EXECUTE_READWRITE, &mut old_protect) == 0 {
                panic!("Failed to change memory protection");
            }
            ptr::write(addr, 0xC3);
            if VirtualProtect(addr as *mut _, 1, old_protect, &mut old_protect) == 0 {
                panic!("Failed to restore memory protection");
            }
            print_log(&format!("Disabled kick."));
            Ok(())
        } else {
            Err(anyhow::anyhow!("addr is None"))
        }
    }

    unsafe fn de_init(&mut self) -> Result<()> {
        Ok(())
    }

    fn get_module_type(&self) -> super::ModuleType {
        ModuleType::Kick
    }
}