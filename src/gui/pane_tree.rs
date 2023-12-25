use crate::gui;
use crate::gui::panes::packet_table::PacketTable;
use crate::packets::data_link::ethernet::EthernetFrame;
use egui::{Sense, Ui, WidgetText};
use egui_tiles::{Behavior, TileId, UiResponse};

pub struct TreeBehavior<'a> {
    pub captured_packets: &'a [EthernetFrame],
    pub drilldown: &'a str,
    pub payload: &'a [u8],
    pub selected_packet: &'a mut Option<i32>,
}
#[derive(Clone)]
pub struct Pane {
    title: String,
    module: Module,
}

#[derive(Clone)]
pub enum Module {
    Packets(PacketTable),
    PacketDrill,
    Payload,
    PacketGraph,
}

impl<'a> Behavior<Pane> for TreeBehavior<'a> {
    fn pane_ui(&mut self, ui: &mut Ui, _tile_id: TileId, pane: &mut Pane) -> UiResponse {
        let dragged = ui
            .add(egui::Button::new(&pane.title).sense(Sense::drag()))
            .dragged();

        match pane.module {
            Module::Packets(ref mut table) => {
                table.render(ui, self.captured_packets, self.selected_packet);
            }
            Module::PacketDrill => {
                if let Some(packet) =
                    { *self.selected_packet }.and_then(|i| self.captured_packets.get(i as usize))
                {
                    gui::panes::drill_down::drill_ui(ui, packet);
                }
            }
            Module::Payload => {
                if let Some(packet) =
                    { *self.selected_packet }.and_then(|i| self.captured_packets.get(i as usize))
                {
                    gui::panes::payload::payload_ui(ui, packet);
                }
            }
            Module::PacketGraph => gui::panes::graph::graph_ui(ui, self.captured_packets),
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

pub fn create_tree() -> egui_tiles::Tree<Pane> {
    let mut tiles = egui_tiles::Tiles::default();

    let tabs = vec![
        tiles.insert_pane(Pane {
            title: "Packets".into(),
            module: Module::Packets(PacketTable::default()),
        }),
        tiles.insert_pane(Pane {
            title: "Drill Down".into(),
            module: Module::PacketDrill,
        }),
        tiles.insert_pane(Pane {
            title: "Graph".into(),
            module: Module::PacketGraph,
        }),
        tiles.insert_pane(Pane {
            title: "Payload".into(),
            module: Module::Payload,
        }),
    ];

    let root = tiles.insert_tab_tile(tabs);

    egui_tiles::Tree::new(root, tiles)
}
