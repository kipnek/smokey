//use cnote::gui::app::CaptureApp;
//use iced::Application;

use cnote::gui::gui_traits::View;
use cnote::packets::data_link::ethernet::EthernetFrame;
use cnote::packets::packet_traits::Describable;
use cnote::sniffer::LiveCapture;
use eframe;
use eframe::Frame;
use egui;
use egui::{Context, Ui};
use std::panic;
use std::time::Duration;

fn main() -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        drag_and_drop_support: true,

        initial_window_size: Some([1280.0, 1024.0].into()),

        #[cfg(feature = "wgpu")]
        renderer: eframe::Renderer::Wgpu,

        ..Default::default()
    };
    eframe::run_native(
        "egui demo app",
        options,
        Box::new(|cc| Box::new(LiveApp::new(cc))),
    )
}

pub struct LiveApp {
    pub running: bool,
    pub sniffer: LiveCapture,
    pub table: Table,
    pub packet_to_drill: String,
}

impl eframe::App for LiveApp {
    fn update(&mut self, ctx: &Context, frame: &mut Frame) {
        egui::CentralPanel::default()
            .frame(egui::Frame::dark_canvas(&ctx.style()))
            .show(ctx, |ui| self.ui(ui));
    }
}

impl LiveApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        Self {
            running: false,
            sniffer: Default::default(),
            table: Table::new(),
            packet_to_drill: String::new(),
        }
    }
    pub fn get_packets(&mut self) {
        if self.running {
            if let Some(receiver) = self.sniffer.receiver.as_mut() {
                self.sniffer.captured_packets.extend(receiver.try_iter());
            }
        }
    }
    pub fn ui(&mut self, ui: &mut Ui) {
        if self.running {
            ui.ctx().request_repaint_after(Duration::from_secs(1));
        }
        self.get_packets();
        if ui.button("Start").clicked() {
            self.start();
        }
        if ui.button("Stop").clicked() {
            self.stop();
        }
        self.table.table_ui(ui, &mut self.sniffer.captured_packets);
        if let Some(id) = self.table.selected_packet {
            if let Some(packet) = self.sniffer.captured_packets.get(id as usize) {
                let text = packet.get_long();
                println!("{:?}", text);
                self.packet_to_drill = text;
            }
            self.table.selected_packet = None;
        }
        ui.label(&self.packet_to_drill);
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

pub struct Table {
    striped: bool,
    resizable: bool,
    //scroll_to_row_slider: usize,
    scroll_to_row: Option<usize>,
    selected_packet: Option<i32>,
}

impl Table {
    pub fn new() -> Self {
        Self {
            striped: false,
            resizable: false,
            scroll_to_row: None,
            selected_packet: None,
        }
    }
}

impl Table {
    pub fn table_ui(&mut self, ui: &mut egui::Ui, data: &mut Vec<EthernetFrame>) {
        use egui_extras::{Column, TableBuilder};
        let mut table = TableBuilder::new(ui)
            .striped(self.striped)
            .resizable(self.resizable)
            .auto_shrink([false, true])
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::auto())
            .column(Column::auto())
            .column(Column::auto())
            .column(Column::auto())
            .column(Column::auto())
            .min_scrolled_height(0.0);

        if let Some(row_nr) = self.scroll_to_row.take() {
            table = table.scroll_to_row(row_nr, None);
        }

        table
            .header(20.0, |mut header| {
                header.col(|ui| {
                    ui.strong("id");
                });
                header.col(|ui| {
                    ui.strong("timestamp");
                });
                header.col(|ui| {
                    ui.strong("source");
                });
                header.col(|ui| {
                    ui.strong("destination");
                });
                header.col(|ui| {
                    ui.strong("info");
                });
            })
            .body(|body| {
                body.rows(18.0, data.len(), |index, mut row| {
                    let packet = &data[index];
                    let description = packet.get_description();
                    row.col(|ui| {
                        if ui.button(description.id.to_string()).clicked() {
                            self.selected_packet = Some(description.id);
                        }
                    });
                    row.col(|ui| {
                        if ui.button(description.timestamp).clicked() {
                            self.selected_packet = Some(description.id);
                        }
                    });
                    row.col(|ui| {
                        if ui
                            .button(description.src_dest_layer.source().to_string())
                            .clicked()
                        {
                            self.selected_packet = Some(description.id);
                        }
                    });
                    row.col(|ui| {
                        if ui
                            .button(description.src_dest_layer.destination().to_string())
                            .clicked()
                        {
                            self.selected_packet = Some(description.id);
                        }
                    });
                    row.col(|ui| {
                        if ui.button(description.info_layer.info()).clicked() {
                            self.selected_packet = Some(description.id);
                        }
                    });
                });
            });
    }
}

fn custom_panic_handler(info: &panic::PanicInfo) {
    // Handle the panic, e.g., log it or perform some cleanup.
    println!("Panic occurred: {info:?}");
}