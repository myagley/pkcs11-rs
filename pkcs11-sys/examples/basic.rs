use std::mem;

use libloading as lib;
use pkcs11_sys::*;

fn main() {
    let lib = lib::Library::new("/usr/local/lib/softhsm/libsofthsm2.so").unwrap();

    let list = unsafe {
        let mut list: CK_FUNCTION_LIST_PTR = mem::uninitialized();
        let func: lib::Symbol<unsafe extern "C" fn(CK_FUNCTION_LIST_PTR_PTR) -> CK_RV> = lib.get(b"C_GetFunctionList").unwrap();
        func(&mut list);
        list
    };


    unsafe {
        let arg = std::ptr::null_mut();
        (*list).C_Initialize.unwrap()(arg);
    }

    let info = unsafe {
        let mut info: CK_INFO = mem::uninitialized();
        (*list).C_GetInfo.unwrap()(&mut info);
        info
    };
    println!();
    println!("--------------- Info ----------------");
    println!("Library Version :    {:?}", info.libraryVersion);
    println!("Library Description: {}", std::str::from_utf8(&info.libraryDescription).unwrap());
    println!("Manufacturer ID:     {}", std::str::from_utf8(&info.manufacturerID).unwrap());

    let slot_info = unsafe {
        let mut slot_info: CK_SLOT_INFO = mem::uninitialized();
        (*list).C_GetSlotInfo.unwrap()(1723281416, &mut slot_info);
        slot_info
    };
    println!();
    println!("--------------- Slot ----------------");
    println!("Slot Description: {}", std::str::from_utf8(&slot_info.slotDescription).unwrap());
    println!("Manufacturer ID:  {}", std::str::from_utf8(&slot_info.manufacturerID).unwrap());
    println!("Hardware Version: {:?}", slot_info.hardwareVersion);
}

