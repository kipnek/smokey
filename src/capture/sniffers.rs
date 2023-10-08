use crate::packet_objects::basics::BasePacket;
use pcap::Device;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::{panic, thread};

/*
for gui implementation
 */
#[derive(Debug, Clone, Default)]
pub struct LiveCapture {
    pub interfaces: Vec<String>,
    pub cli_buffer: Arc<Mutex<VecDeque<Vec<BasePacket>>>>,
    pub stop: Arc<AtomicBool>,
}

impl LiveCapture {
    pub fn capture(&mut self) -> Result<(), String> {
        let stop = self.stop.clone();
        let cli_buffer = self.cli_buffer.clone();
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
                    if let Ok(mut buffer_lock) = cli_buffer.lock() {
                        if buffer_lock[vec_indexer].len() >= 1000{
                            buffer_lock.push_back(vec![]);
                            vec_indexer+=1;
                        }
                        buffer_lock[vec_indexer].push(BasePacket::new(index, packet.data.to_vec()));
                        index += 1;
                    }
                }
                stop.store(false, Ordering::Release);
                drop(cli_buffer);
            }
        });
        Ok(())
    }

    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}
