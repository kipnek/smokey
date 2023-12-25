use crate::gui::pane_tree::{create_tree, Pane, TreeBehavior};
use crate::sniffer::Sniffer;
use eframe::Frame;
use egui::{ComboBox, Context};
use std::time::Duration;

//use for separating out stuff
pub struct Capture {
    running: bool,
    sniffer: Sniffer,
    device: Option<String>,
    label: Option<String>,
    device_none_modal: bool,
    show_device_modal: bool,
    tree: egui_tiles::Tree<Pane>,
    selected_packet: Option<i32>,
}

impl eframe::App for Capture {
    fn update(&mut self, ctx: &Context, _frame: &mut Frame) {
        if self.running {
            self.get_packets();
            if let Some(handle) = self.sniffer.file_handle.as_ref() {
                if handle.is_finished() {
                    self.file_finished();
                }
            }
        }
        ctx.request_repaint_after(Duration::from_millis(100));
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("Start").clicked() && !self.running {
                    if self.device.is_some() {
                        println!("started");
                        self.start(None);
                    } else {
                        // Set the state to show the modal window
                        self.device_none_modal = true;
                    }
                }

                //maybe needed, this will stop a file upload. maybe make a conditional that prevents early termination if clicked
                if ui.button("Stop").clicked() {
                    self.stop();
                }

                if ui.button("select device").clicked() {
                    self.show_device_modal = true;
                }

                if let Some(ref device) = self.device {
                    ui.label(format!("selected device: {}", device));
                }

                if ui.button("Upload pcap").clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("Packet Capture Files", &["pcap", "cap"])
                        .pick_file()
                    {
                        self.start(Some(path.to_string_lossy().to_string()))
                    }
                }
                if let Some(ref label) = self.label {
                    ui.label(label);
                }
            });
        });

        egui::Window::new("Interface Selection")
            .open(&mut self.show_device_modal)
            .show(ctx, |ui| {
                ui.label("Please select an interface:");
                match self.sniffer.get_interfaces() {
                    Ok(devices) => {
                        ComboBox::from_label("select device")
                            .selected_text(
                                self.device
                                    .as_ref()
                                    .unwrap_or(&String::from("Select a device")),
                            )
                            .show_ui(ui, |ui| {
                                for device in &devices {
                                    let response = ui.selectable_value(
                                        &mut self.device,
                                        Some(device.name.clone()),
                                        &device.name,
                                    );
                                    if response.changed() {
                                        self.device = Some(device.name.clone());
                                    }
                                }
                            });
                    }
                    Err(e) => {
                        ui.label(e.to_string());
                    }
                }
            });

        egui::Window::new("Device Not Selected")
            .open(&mut self.device_none_modal)
            .show(ctx, |ui| ui.label("Please select a device to run capture"));

        egui::CentralPanel::default().show(ctx, |ui| {
            let mut behavior = TreeBehavior {
                captured_packets: &self.sniffer.captured_packets,
                drilldown: "",
                payload: &[],
                selected_packet: &mut self.selected_packet,
            };
            self.tree.ui(&mut behavior, ui);
        });
    }
}

impl Default for Capture {
    fn default() -> Self {
        Self::new()
    }
}
impl Capture {
    pub fn new() -> Self {
        Self {
            running: false,
            sniffer: Default::default(),
            tree: create_tree(),
            selected_packet: None,
            device: None,
            show_device_modal: false,
            device_none_modal: false,
            label: None,
        }
    }
    pub fn get_packets(&mut self) {
        if let Some(receiver) = self.sniffer.receiver.as_mut() {
            self.sniffer.captured_packets.extend(receiver.try_iter());
        }
    }
    pub fn start(&mut self, file: Option<String>) {
        self.sniffer.captured_packets = vec![];
        if let Some(file) = file {
            self.label = Some(format!("file: {}", file));
            self.sniffer.from_file(file);
            self.running = true;
        } else if let Some(ref device) = self.device {
            self.label = Some("running...".to_string());
            self.sniffer.capture(device);
            self.running = true;
        }
    }
    pub fn stop(&mut self) {
        self.label = None;
        self.sniffer.stop();
        self.running = false;
    }
    pub fn file_finished(&mut self) {
        self.sniffer.stop();
        self.running = false;
    }
}
