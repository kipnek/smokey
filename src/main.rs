use cnote::gui::app::Capture;
fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        //drag_and_drop_support: true,
        initial_window_size: Some([1280.0, 1024.0].into()),

        #[cfg(feature = "wgpu")]
        renderer: eframe::Renderer::Wgpu,

        ..Default::default()
    };
    eframe::run_native("cnote", options, Box::new(|cc| Box::new(Capture::new())))
}
