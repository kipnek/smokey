use crate::traits::Processable;
use pnet::packet::{udp, Packet};

#[derive(Debug, Clone)]
pub struct UdpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub payload: Vec<u8>,
}

impl<'a> Processable<'a, UdpHeader> for udp::UdpPacket<'a> {
    fn process(&self) -> UdpHeader {
        let source_port = self.get_source();
        let destination_port = self.get_destination();
        let length = self.get_length();
        let checksum = self.get_checksum();
        let payload = self.payload().to_vec();

        UdpHeader {
            source_port,
            destination_port,
            length,
            checksum,
            payload,
        }
    }
}
