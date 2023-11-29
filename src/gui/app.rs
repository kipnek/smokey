use crate::gui::pane_tree::{create_tree, Module, Pane, TreeBehavior};
use crate::packets::data_link::ethernet::EthernetFrame;
use crate::sniffer::Sniffer;
use eframe::Frame;
use egui::Context;
use std::time::Duration;

//use for separating out stuff
pub struct Capture {
    pub running: bool,
    pub sniffer: Sniffer,
    pub tree: egui_tiles::Tree<Pane>,
    pub selected_packet: Option<i32>,
}

impl eframe::App for Capture {
    fn update(&mut self, ctx: &Context, frame: &mut Frame) {
        if self.running {
            self.get_packets();
            ctx.request_repaint_after(Duration::from_millis(100));
        }
        egui::SidePanel::left("tree").show(ctx, |ui| {
            if ui.button("Start").clicked() {
                if !self.running {
                    self.start();
                }
            }
            if ui.button("Stop").clicked() {
                self.stop();
            }
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
        }
    }
    pub fn get_packets(&mut self) {
        if let Some(receiver) = self.sniffer.receiver.as_mut() {
            self.sniffer.captured_packets.extend(receiver.try_iter());
        }
    }
    pub fn start(&mut self) {
        self.sniffer.capture();
        self.running = true;
    }
    pub fn stop(&mut self) {
        self.sniffer.stop();
        self.running = false;
    }
}
