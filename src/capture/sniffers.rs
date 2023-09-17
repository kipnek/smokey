use crate::packet_objects::raw::RawPacket;
use std::sync::{Arc, Mutex,};
use std::sync::atomic::{AtomicBool, Ordering};
use std::{panic, thread};
use circular_buffer::CircularBuffer;
use pcap::Device;

#[derive(Debug, Clone, Default)]
pub struct LiveCap {
    pub interface: Vec<String>,
    pub live_buffer: Arc<Mutex<CircularBuffer<30, RawPacket>>>,
    pub stop: Arc<AtomicBool>,
}

impl LiveCap {
    pub fn new() -> Self {
        LiveCap {
            interface: vec![],
            live_buffer: Arc::new(Mutex::new(CircularBuffer::new())),
            stop: Arc::new(AtomicBool::new(false)),
        }
    }
    pub fn live_capture(&mut self){//, interfaces:Vec<String>) {
        let stop = self.stop.clone();
        let live_buffer = self.live_buffer.clone();
        thread::spawn(move || {
            let mut index = 0;
            let device = Device::lookup()
                .and_then(|dev_result| {
                    match dev_result {
                        Some(dev) => Ok(dev),
                        None => Err(pcap::Error::PcapError("no device".to_string())),
                    }
                })
                .unwrap_or_else(|err| panic!("Device lookup failed: {}", err));

            if let Ok(mut cap) = pcap::Capture::from_device(device)
                .and_then(|cap| cap.immediate_mode(true).open())
            {
                while let Ok(packet) = cap.next_packet() {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    if let Ok(mut buffer_lock) = live_buffer.lock() {
                        buffer_lock.push_back(RawPacket::new(index, packet.data.to_vec()));
                        index += 1;
                    }
                }
                stop.store(false, Ordering::Release);
                drop(live_buffer);
            }
        });

    }
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

