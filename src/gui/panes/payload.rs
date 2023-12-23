use crate::packets::data_link::ethernet::EthernetFrame;
use crate::packets::packet_traits::Layer;
use crate::packets::shared_objs::LayerData;
use egui::{Context, FontFamily::Monospace, RichText, Sense, Ui, WidgetText};
use egui_extras::{Column, TableBody, TableBuilder};
use std::fmt::Write;
pub fn payload_ui(ui: &mut Ui, packet: &EthernetFrame) {
    let mut layer_data = packet.get_next();
    let payload = 'payload: loop {
        match layer_data {
            LayerData::Layer(layer) => {
                layer_data = layer.get_next();
            }
            LayerData::Application(app_layer) => break 'payload layer_data,
            LayerData::Data(payload) => {
                break 'payload layer_data;
            }
        }
    };

    TableBuilder::new(ui)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::auto())
        .column(Column::auto())
        .column(Column::auto())
        .header(20.0, |mut header| {
            header.col(|ui| {
                ui.strong("Address:");
            });
            header.col(|ui| {
                ui.strong("Hex:");
            });
            header.col(|ui| {
                ui.strong("String Data:");
            });
        })
        .body(|body| match payload {
            LayerData::Layer(_) => {}
            LayerData::Application(app_layer) => todo!(),
            LayerData::Data(payload) => display_payload(body, payload),
        });
}

/*


Privates


*/

fn display_payload(body: TableBody, payload: &[u8]) {
    let chunks = payload.chunks(16);
    body.rows(18.0, chunks.clone().count(), |index, mut row| {
        let chunk = chunks.clone().nth(index).unwrap();

        row.col(|ui| {
            let address = format!("{index:07x}0:");
            ui.label(RichText::new(address).family(Monospace));
        });

        row.col(|ui| {
            let mut hex_string = String::new();
            let mut crumbs = chunk.chunks(2);

            // Write the first "crumb" separately,
            for b in crumbs.next().unwrap().iter() {
                write!(hex_string, "{b:02x}").unwrap();
            }
            // then write the following "crumbs" with a leading space
            for crumb in crumbs {
                write!(hex_string, " ").unwrap();
                for b in crumb {
                    write!(hex_string, "{b:02x}").unwrap();
                }
            }

            ui.label(RichText::new(hex_string).family(Monospace));
        });

        row.col(|ui| {
            let string = { chunk.iter() }
                .map(|&b| if b.is_ascii_graphic() { b as char } else { '.' })
                .collect::<String>();
            ui.label(RichText::new(string).family(Monospace));
        });
    });
}
