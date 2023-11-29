use chrono::prelude::*;
use cnote::gui;
use cnote::gui::app::Capture;
use cnote::gui::packet_table::PacketTable;
use cnote::gui::pane_tree::{create_tree, Pane, TreeBehavior};
use cnote::packets::data_link::ethernet::EthernetFrame;
use cnote::packets::packet_traits::Describable;
use cnote::sniffer::Sniffer;
use eframe::Frame;
use egui::{Context, Sense, Ui, WidgetText};
use egui_tiles::{Behavior, TileId, UiResponse};
use std::time::Duration;

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        //drag_and_drop_support: true,
        initial_window_size: Some([1280.0, 1024.0].into()),

        #[cfg(feature = "wgpu")]
        renderer: eframe::Renderer::Wgpu,

        ..Default::default()
    };
    eframe::run_native(
        "egui demo app",
        options,
        Box::new(|cc| Box::new(Capture::new())),
    )
}
