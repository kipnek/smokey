use crate::packets::data_link::ethernet::EthernetFrame;
use chrono::{DateTime, Utc};
use egui::Ui;
use egui_plot::{Legend, Line, Plot, PlotPoints};
use std::collections::BTreeMap;

pub fn graph_ui(ui: &mut Ui, captured_packets: &[EthernetFrame]) {
    let plot = Plot::new("lines")
        .legend(Legend::default())
        .include_y(0.0)
        .allow_boxed_zoom(false)
        .allow_double_click_reset(false)
        .allow_drag(false)
        .allow_scroll(false)
        .allow_zoom(false);

    let mut distribution = BTreeMap::<i64, [f64; 2]>::new();
    for p in captured_packets.iter().rev() {
        let ts = p.timestamp.parse::<DateTime<Utc>>().unwrap();

        let ts = (ts.timestamp() as f64) + (ts.timestamp_subsec_micros() as f64) / 1e6;
        // Multiply each second by a number to get that many entries per second.
        distribution.entry((ts * 10.0) as i64).or_insert([ts, 0.0])[1] += 1.0;
        if distribution.len() >= (10 * 10 + 2) {
            break;
        }
    }
    // Get rid of first and last time periods so they don't shrink and grow as time goes on.
    distribution.pop_first();
    distribution.pop_last();

    plot.show(ui, |plot_ui| {
        let series = PlotPoints::from_iter(distribution.into_values());
        plot_ui.line(Line::new(series).fill(0.0));
    });
}
