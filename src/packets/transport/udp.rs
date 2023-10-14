use crate::traits::Layer;
use pnet::packet::Packet;
use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
pub struct UdpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub payload: Vec<u8>,
    pub malformed: bool,
}

#[derive(Default, Debug)]
pub struct UdpPacket {
    pub header: UdpHeader,
    pub payload: Option<Box<dyn Layer>>,
}

impl Layer for UdpPacket {
    fn deserialize(&mut self, packet: &[u8]) {
        let packet_header = match pnet::packet::udp::UdpPacket::new(packet) {
            None => UdpHeader::malformed(packet),
            Some(header) => UdpHeader {
                source_port: header.get_source(),
                destination_port: header.get_destination(),
                length: header.get_length(),
                checksum: header.get_checksum(),
                payload: header.payload().to_vec(),
                malformed: false,
            },
        };
        self.header = packet_header;
        self.payload = None;
    }

    fn get_summary(&self) -> HashMap<String, String> {
        let mut map: HashMap<String, String> = HashMap::new();

        map.insert(
            "source_port".to_string(),
            self.header.source_port.to_string(),
        );
        map.insert(
            "destination_port".to_string(),
            self.header.destination_port.to_string(),
        );
        map.insert("length".to_string(), self.header.length.to_string());
        map.insert("checksum".to_string(), self.header.checksum.to_string());
        map.insert("malformed".to_string(), self.header.malformed.to_string());

        map
    }

    fn get_next(&self) -> &Option<Box<dyn Layer>> {
        &self.payload
    }
}

impl UdpHeader {
    fn malformed(payload: &[u8]) -> UdpHeader {
        UdpHeader {
            source_port: 0,
            destination_port: 0,
            length: 0,
            checksum: 0,
            payload: payload.to_vec(),
            malformed: true,
        }
    }
}
