use crate::packets::data_link::ethernet::EthernetFrame;
use crate::packets::packet_traits::Describable;
use egui::Ui;

pub fn drill_ui(ui: &mut Ui, packet: &EthernetFrame) {
    ui.label(packet.get_long());
}
