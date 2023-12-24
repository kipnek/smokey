use crate::packets::packet_traits::Describable;
use crate::packets::{data_link::ethernet::EthernetFrame, packet_traits::Layer};
use egui_extras::{Column, TableBuilder};

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

    pub fn render(
        &mut self,
        ui: &mut egui::Ui,
        data: &[EthernetFrame],
        selected_packet: &mut Option<i32>,
    ) {
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
                    let info = match description.info_layer {
                        crate::packets::shared_objs::LayerData::Layer(layer) => layer.info(),
                        crate::packets::shared_objs::LayerData::Application(layer) => layer.info(),
                        crate::packets::shared_objs::LayerData::Data(_) => {
                            panic!("this shouldnt be happening")
                        }
                    };
                    [
                        description.id.to_string().as_str(),
                        description.timestamp,
                        description.src_dest_layer.source().as_ref(),
                        description.src_dest_layer.destination().as_ref(),
                        info.as_str(),
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
