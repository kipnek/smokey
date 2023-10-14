use crate::packets::datalink::ethernet::EthernetFrame;
use pcap::Device;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::{panic, thread};

#[derive(Clone, Default)]
pub struct LiveCapture {
    pub interfaces: Vec<String>,
    pub captured_packets: Arc<Mutex<Vec<Vec<EthernetFrame>>>>,
    pub stop: Arc<AtomicBool>,
}

impl LiveCapture {
    pub fn capture(&mut self) {
        let stop = self.stop.clone();
        let vec_deque = self.captured_packets.clone();
        let mut vec_indexer = 0;
        thread::spawn(move || {
            let mut index = 0;

            //only for development
            let device = Device::lookup()
                .and_then(|dev_result| match dev_result {
                    Some(dev) => Ok(dev),
                    None => Err(pcap::Error::PcapError("no device".to_string())),
                })
                .unwrap_or_else(|err| panic!("Device lookup failed: {}", err));

            if let Ok(mut cap) =
                pcap::Capture::from_device(device).and_then(|cap| cap.immediate_mode(true).open())
            {
                while let Ok(packet) = cap.next_packet() {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    if let Ok(mut buffer_lock) = vec_deque.lock() {
                        if buffer_lock[buffer_lock.len() - 1].len() >= 1000 {
                            buffer_lock.push(vec![]);
                            vec_indexer += 1;
                        }
                        buffer_lock[vec_indexer].push(EthernetFrame::new(index, packet.data));
                        index += 1;
                    }
                }
                stop.store(false, Ordering::Release);
                drop(vec_deque);
            }
        });
    }

    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}
