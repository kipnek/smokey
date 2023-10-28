mod packets;
mod sniffer;
//mod basic_traits;
mod gui;


use crate::packets::data_link::ethernet::EthernetFrame;
use crate::packets::traits::Describable;
use chrono::Duration;
use chrono::{DateTime, Utc};
use std::io::Write;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::{io, panic, thread};
use iced::Application;
use crate::sniffer::LiveCapture;

fn main()-> iced::Result {
    panic::set_hook(Box::new(custom_panic_handler));

    LiveCapture::run(iced::Settings::default())
}

fn custom_panic_handler(info: &panic::PanicInfo) {
    // Handle the panic, e.g., log it or perform some cleanup.
    println!("Panic occurred: {:?}", info);
}

/*
fn get_describable(vectors: &[Vec<EthernetFrame>], id_to_find: i32) -> Option<&EthernetFrame> {
    for vector in vectors {
        if let Some(frame) = vector.iter().find(|frame| frame.id == id_to_find) {
            return Some(frame);
        }
    }
    None
}

*/
/*
fn find_udp_packets(frames: &[EthernetFrame]) -> Vec<&EthernetFrame> {
    //frames.iter().filter(|&frame| frame.is_udp_packet()).collect()
}
 */
fn get_duration_from_string(timestamp: &str) -> Option<Duration> {
    timestamp.parse::<DateTime<Utc>>().ok()
        .map(|time| Utc::now().signed_duration_since(time))
}
