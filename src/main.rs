use cnote::gui::app::CaptureApp;
use iced::Application;

use std::panic;

fn main() -> iced::Result {
    panic::set_hook(Box::new(custom_panic_handler));

    CaptureApp::run(iced::Settings::default())
}

fn custom_panic_handler(info: &panic::PanicInfo) {
    // Handle the panic, e.g., log it or perform some cleanup.
    println!("Panic occurred: {info:?}");
}
