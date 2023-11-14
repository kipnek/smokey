use crate::packets::packet_traits::Layer;
use crate::packets::shared_objs::LayerData;
use pnet::packet::Packet;
use std::borrow::Cow;
use std::fmt::{Display, Write};

#[derive(Debug, Clone, Default)]
pub struct UdpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub malformed: bool,
}

#[derive(Default, Debug, Clone)]
pub struct UdpPacket {
    pub header: UdpHeader,
    pub payload: Box<[u8]>,
}

impl UdpPacket {
    pub fn new(packet: &[u8]) -> Option<UdpPacket> {
        let packet = pnet::packet::udp::UdpPacket::new(packet)?;

        let header = UdpHeader {
            source_port: packet.get_source(),
            destination_port: packet.get_destination(),
            length: packet.get_length(),
            checksum: packet.get_checksum(),
            malformed: false,
        };

        Some(UdpPacket {
            header,
            payload: packet.payload().to_vec().into_boxed_slice(),
        })
    }
}

impl Layer for UdpPacket {
    fn append_summary(&self, target: &mut String) {
        let UdpHeader {
            source_port,
            destination_port,
            length,
            checksum,
            malformed,
        } = &self.header;

        let _ = write!(
            target,
            "protocol: udp
source_port: {source_port}
destination_port: {destination_port}
length: {length}
checksum: {checksum}
malformed: {malformed}"
        );
    }

    fn get_next(&self) -> LayerData {
        LayerData::Data(&self.payload)
    }

    fn source(&self) -> Cow<'_, str> {
        Cow::from(self.header.source_port.to_string())
    }

    fn destination(&self) -> Cow<'_, str> {
        Cow::from(self.header.destination_port.to_string())
    }

    fn info(&self) -> String {
        format!(
            "UDP src {} -> dest {}",
            self.header.source_port, self.header.destination_port
        )
    }
}
