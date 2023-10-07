use crate::traits::Processable;
use pnet::packet::{udp, Packet};

#[derive(Debug, Clone)]
pub struct UdpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub payload: Vec<u8>,
    pub malformed: bool,
}

impl UdpHeader {
    pub fn deformed_packet(payload: Vec<u8>) -> Self {
        UdpHeader {
            source_port: 0,
            destination_port: 0,
            length: 0,
            checksum: 0,
            payload,
            malformed: true,
        }
    }
}

impl<'a> Processable<'a, UdpHeader> for udp::UdpPacket<'a> {
    fn process(&self) -> UdpHeader {
        UdpHeader {
            source_port: self.get_source(),
            destination_port: self.get_destination(),
            length: self.get_length(),
            checksum: self.get_checksum(),
            payload: self.payload().to_vec(),
            malformed: false,
        }
    }
}
