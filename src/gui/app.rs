use crate::gui::pane_tree::{create_tree, Pane, TreeBehavior};
use crate::sniffer::Sniffer;
use eframe::Frame;
use egui::Context;
use std::time::Duration;

//use for separating out stuff
pub struct Capture {
    pub running: bool,
    pub sniffer: Sniffer,
    pub pcap_file: Option<String>,
    pub tree: egui_tiles::Tree<Pane>,
    pub selected_packet: Option<i32>,
}

impl eframe::App for Capture {
    fn update(&mut self, ctx: &Context, _frame: &mut Frame) {
        if self.running {
            self.get_packets();
            if let Some(handle) = self.sniffer.file_handle.as_ref() {
                if handle.is_finished() {
                    self.stop();
                }
            }
        }
        ctx.request_repaint_after(Duration::from_millis(100));
        egui::TopBottomPanel::top("top").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui.button("Start").clicked() {
                    if self.sniffer.receiver.is_none() {
                        self.pcap_file = None;
                        self.start(None);
                    }
                }
                if ui.button("Stop").clicked() {
                    self.stop();
                }

                if ui.button("Upload pcap").clicked() {
                    if let Some(path) = rfd::FileDialog::new()
                        .add_filter("Packet Capture Files", &["pcap", "cap"])
                        .pick_file()
                    {
                        self.pcap_file = Some(path.to_string_lossy().to_string());
                        self.start(Some(path.to_string_lossy().to_string()))
                    }
                }
                if let Some(ref path) = self.pcap_file {
                    ui.label(format!("pcap file: {}", &path));
                }
            });
        });
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
impl Capture {
    pub fn new() -> Self {
        Self {
            running: false,
            sniffer: Default::default(),
            tree: create_tree(),
            selected_packet: None,
            pcap_file: None,
        }
    }
    pub fn get_packets(&mut self) {
        if let Some(receiver) = self.sniffer.receiver.as_mut() {
            self.sniffer.captured_packets.extend(receiver.try_iter());
        }
    }
    pub fn start(&mut self, file: Option<String>) {
        self.sniffer.captured_packets = vec![];
        if file.is_none() {
            self.sniffer.capture();
        } else {
            self.sniffer.from_file(file.unwrap());
        }
        self.running = true;
    }
    pub fn stop(&mut self) {
        self.sniffer.stop();
        self.running = false;
    }
}
