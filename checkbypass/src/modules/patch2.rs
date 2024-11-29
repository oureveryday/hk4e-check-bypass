use super::{MhyContext, MhyModule, ModuleType};
use anyhow::Result;
use ilhook::x64::Registers;

pub struct Patch2;

use win_dbg_logger::output_debug_string;
fn print_log(str: &str) {
    let log_str = format!("[hk4eCheckBypass] {}\n", str);

    #[cfg(debug_assertions)]
    {
        println!("{}",&log_str);
    }

    output_debug_string(&log_str);
}

impl MhyModule for MhyContext<Patch2> {
    unsafe fn init(&mut self) -> Result<()> {
        if let Some(addr) = self.addr {
            self.interceptor.replace(
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
        ModuleType::Patch2
    }
}

unsafe extern "win64" fn hkcheckaddr(_reg: *mut Registers, _: usize, _:usize) ->usize{
    print_log(&format!("Triggered hook 2"));
    0
}