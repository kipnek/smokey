use cnote::packets::data_link::ethernet::EthernetFrame;
use cnote::packets::packet_traits::{Describable, Layer};
use cnote::packets::shared_objs::LayerData;
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
pub struct Capture {
    pub running: bool,
    pub sniffer: Sniffer,
    pub tree: egui_tiles::Tree<Pane>,
    pub selected_packet: Option<i32>,
}
struct TreeBehavior<'a> {
    captured_packets: &'a [EthernetFrame],
    drilldown: &'a str,
    payload: &'a [u8],
    selected_packet: &'a mut Option<i32>,
}
#[derive(Clone)]
pub struct Pane {
    title: String,
    module: Module,
}

impl eframe::App for Capture {
    fn update(&mut self, ctx: &Context, frame: &mut Frame) {
        if self.running {
            self.get_packets();
            ctx.request_repaint_after(Duration::from_secs(1));
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
impl<'a> Behavior<Pane> for TreeBehavior<'a> {
    fn pane_ui(&mut self, ui: &mut Ui, _tile_id: TileId, pane: &mut Pane) -> UiResponse {
        let dragged = ui
            .add(egui::Button::new(&pane.title).sense(Sense::drag()))
            .dragged();

        match pane.module.clone() {
            Module::Packets(mut table) => {
                table.render(ui, self.captured_packets, self.selected_packet);
            }
            Module::PacketDrill => {
                if let Some(packet) =
                    { *self.selected_packet }.and_then(|i| self.captured_packets.get(i as usize))
                {
                    ui.label(packet.get_long());
                }
            }
            Module::Payload => {
                if let Some(packet) =
                    { *self.selected_packet }.and_then(|i| self.captured_packets.get(i as usize))
                {
                    let mut layer_data = packet.get_next();
                    let payload = 'payload: loop {
                        match layer_data {
                            LayerData::Layer(layer) => {
                                layer_data = layer.get_next();
                            }
                            LayerData::Data(payload) => {
                                break 'payload payload;
                            }
                        }
                    };

                    ui.label("TODO: Payload here");
                }
            }
        }

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
        module: Module::PacketDrill,
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
}

impl PacketTable {
    pub fn new() -> Self {
        Self {
            striped: false,
            resizable: false,
            scroll_to_row: None,
        }
    }
}

impl PacketTable {
    pub fn render(
        &mut self,
        ui: &mut egui::Ui,
        data: &[EthernetFrame],
        selected_packet: &mut Option<i32>,
    ) {
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
                    [
                        description.id.to_string().as_str(),
                        description.timestamp,
                        description.src_dest_layer.source().to_string().as_str(),
                        description
                            .src_dest_layer
                            .destination()
                            .to_string()
                            .as_str(),
                        description.info_layer.info().as_str(),
                    ]
                    .into_iter()
                    .for_each(|text| {
                        row.col(|ui| {
                            if ui.button(text).clicked() {
                                *selected_packet = Some(description.id);
                            }
                        });
                    });
                });
            });
    }
}

#[derive(Clone)]
pub enum Module {
    Packets(PacketTable),
    PacketDrill,
    Payload,
}
