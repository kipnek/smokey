use crate::packet_objects::layers::link::LinkLayer;
use crate::traits::Processable;
use pnet::packet::ethernet::EthernetPacket;

pub struct LinkProcessor {}

impl LinkProcessor {
    pub fn link_process(raw_packet: &[u8]) -> LinkLayer {
        return if let Some(ethernet_packet) = EthernetPacket::new(raw_packet) {
            LinkLayer::Ethernet(ethernet_packet.process())
        } else {
            LinkLayer::Unknown
        };
    }
}
