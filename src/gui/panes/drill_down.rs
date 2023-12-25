use crate::packets::data_link::ethernet::EthernetFrame;
use crate::packets::packet_traits::Describable;
use egui::{CollapsingHeader, Ui};

pub fn drill_ui(ui: &mut Ui, packet: &EthernetFrame) {
    let drill_down = packet.get_long();
    ui.vertical(|ui| {
        for (key, value) in &drill_down {
            accordion(ui, &key.to_string(), |ui| {
                ui.label(value);
            });
        }
    });
}

fn accordion(ui: &mut Ui, title: &str, content: impl FnOnce(&mut Ui)) {
    CollapsingHeader::new(title)
        .default_open(false)
        .show(ui, |ui| {
            content(ui);
        });
}
