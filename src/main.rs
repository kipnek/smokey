//use cnote::gui::app::CaptureApp;
//use iced::Application;

use cnote::packets::data_link::ethernet::EthernetFrame;
use cnote::packets::packet_traits::Describable;
use cnote::sniffer::Sniffer;
use eframe;
use eframe::Frame;
use egui;
use egui::{Context, ScrollArea, Ui, WidgetText};
use egui_tiles::{Behavior, TileId, UiResponse};
use std::panic;
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
pub struct Capture {
    pub running: bool,
    pub sniffer: Sniffer,
    pub tree: egui_tiles::Tree<Pane>,
}
struct TreeBehavior<'a> {
    captured_packets: &'a Vec<EthernetFrame>,
    drilldown: &'a String,
    payload: &'a Vec<u8>,
}
#[derive(Clone)]
pub struct Pane {
    title: String,
    module: Module,
}

#[derive(Clone)]
pub struct Drilldown {
    pub info: String,
}

impl Drilldown {
    pub fn new() -> Self {
        Self {
            info: "".to_string(),
        }
    }
    pub fn render() {}
}

impl eframe::App for Capture {
    fn update(&mut self, ctx: &Context, frame: &mut Frame) {
        if self.running {
            self.get_packets();
            ctx.request_repaint_after(Duration::from_secs(1));
        }
        egui::SidePanel::left("tree").show(ctx, |ui| {
            if ui.button("Start").clicked() {
                self.start();
            }
            if ui.button("Stop").clicked() {
                self.stop();
            }
        });
        egui::CentralPanel::default().show(ctx, |ui| {
            let mut behavior = TreeBehavior {
                captured_packets: &self.sniffer.captured_packets,
                drilldown: &"".to_string(),
                payload: &vec![],
            };
            self.tree.ui(&mut behavior, ui);
        });
        /*egui::CentralPanel::default()
        .frame(egui::Frame::dark_canvas(&ctx.style()))
        .show(ctx, |ui| self.ui(ui));*/
    }
}
impl<'a> Behavior<Pane> for TreeBehavior<'a> {
    fn pane_ui(&mut self, ui: &mut Ui, _tile_id: TileId, pane: &mut Pane) -> UiResponse {
        match pane.module.clone() {
            Module::Packets(mut table) => {
                table.render(ui, &self.captured_packets);
            }
            Module::PacketDrill(drill) => {}
            Module::Payload => {}
        }

        let dragged = ui
            .allocate_rect(ui.max_rect(), egui::Sense::drag())
            .on_hover_cursor(egui::CursorIcon::Grab)
            .dragged();
        if dragged {
            egui_tiles::UiResponse::DragStarted
        } else {
            egui_tiles::UiResponse::None
        }
    }

    fn tab_title_for_pane(&mut self, pane: &Pane) -> WidgetText {
        pane.title.to_owned().into()
    }
}

impl Capture {
    pub fn new() -> Self {
        Self {
            running: false,
            sniffer: Default::default(),
            tree: create_tree(),
        }
    }
    pub fn get_packets(&mut self) {
        if let Some(receiver) = self.sniffer.receiver.as_mut() {
            self.sniffer.captured_packets.extend(receiver.try_iter());
        }
    }
    pub fn ui(&mut self, ui: &mut Ui) {
        /*if ui.button("Start").clicked() {
            self.start();
        }
        if ui.button("Stop").clicked() {
            self.stop();
        }*/

        /*ScrollArea::vertical().max_height(500.0).show(ui, |ui| {
            self.table.render(ui, &mut self.sniffer.captured_packets);
        });
        if let Some(id) = self.table.selected_packet {
            if let Some(packet) = self.sniffer.captured_packets.get(id as usize) {
                let text = packet.get_long();
                self.packet_to_drill = text;
            }
            self.table.selected_packet = None;
        }

        ui.label(&self.packet_to_drill);*/
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

fn create_tree() -> egui_tiles::Tree<Pane> {
    let mut tiles = egui_tiles::Tiles::default();

    let mut tabs = vec![];

    let first = Pane {
        title: "Packets".into(),
        module: Module::Packets(PacketTable::new()),
    };

    tabs.push({
        let children = tiles.insert_pane(first);
        tiles.insert_horizontal_tile(vec![children])
    });

    let second = Pane {
        title: "Drill Down".into(),
        module: Module::PacketDrill(Drilldown::new()),
    };

    tabs.push({
        let children = tiles.insert_pane(second);
        tiles.insert_horizontal_tile(vec![children])
    });

    let root = tiles.insert_tab_tile(tabs);

    egui_tiles::Tree::new(root, tiles)
}

#[derive(Clone)]
pub struct PacketTable {
    striped: bool,
    resizable: bool,
    //scroll_to_row_slider: usize,
    scroll_to_row: Option<usize>,
    selected_packet: Option<i32>,
}

impl PacketTable {
    pub fn new() -> Self {
        Self {
            striped: false,
            resizable: false,
            scroll_to_row: None,
            selected_packet: None,
        }
    }
}

impl PacketTable {
    pub fn render(&mut self, ui: &mut egui::Ui, data: &Vec<EthernetFrame>) {
        use egui_extras::{Column, TableBuilder};
        let mut table = TableBuilder::new(ui)
            .striped(self.striped)
            .resizable(self.resizable)
            .auto_shrink([false, true])
            .stick_to_bottom(true)
            .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
            .column(Column::auto())
            .column(Column::auto())
            .column(Column::auto())
            .column(Column::auto())
            .column(Column::auto())
            .min_scrolled_height(0.0)
            .resizable(true);

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

#[derive(Clone)]
pub enum Module {
    Packets(PacketTable),
    PacketDrill(Drilldown),
    Payload,
}
