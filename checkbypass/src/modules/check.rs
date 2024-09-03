use super::{MhyContext, MhyModule, ModuleType};
use anyhow::Result;
use ilhook::x64::Registers;

pub struct Check;

use win_dbg_logger::output_debug_string;
fn print_log(str: &str) {
    let log_str = format!("[zzzCheckBypass] {}\n", str);

    #[cfg(debug_assertions)]
    {
        println!("{}",&log_str);
    }

    output_debug_string(&log_str);
}

impl MhyModule for MhyContext<Check> {
    unsafe fn init(&mut self) -> Result<()> {
        if let Some(addr) = self.addr {
            self.interceptor.attach(
                addr as usize,
                hkcheckaddr,
            )
        } else {
            Err(anyhow::anyhow!("addr is None"))
        }
    }

    unsafe fn de_init(&mut self) -> Result<()> {
        Ok(())
    }

    fn get_module_type(&self) -> super::ModuleType {
        ModuleType::Check
    }
}

unsafe extern "win64" fn hkcheckaddr(reg: *mut Registers, _: usize) {
    
    print_log(&format!("Triggered hook: {:x}", (*reg).rcx));
    if (*reg).rcx == 8 {
        (*reg).rcx = 17; 
        print_log(&format!("Replaced to {}", (*reg).rcx)); 
    }

}