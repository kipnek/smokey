mod capture;
mod packet_objects;
mod traits;

use std::panic;

use crate::capture::sniffers;

fn main(){
    panic::set_hook(Box::new(custom_panic_handler));
}
fn custom_panic_handler(info: &panic::PanicInfo) {
    // Handle the panic, e.g., log it or perform some cleanup.
    println!("Panic occurred: {:?}", info);
}
