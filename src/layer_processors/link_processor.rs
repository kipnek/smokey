use crate::packet_objects::layers::link::LinkLayer;
use crate::traits::Processable;
use pnet::packet::ethernet::EthernetPacket;

pub struct LinkProcessor {}

impl LinkProcessor {
    pub fn link_process(raw_packet: &[u8]) -> Option<LinkLayer> {
        let mut layer = None;
        if let Some(ethernet_packet) = EthernetPacket::new(raw_packet) {
            layer = Some(LinkLayer::Ethernet(ethernet_packet.process()));
        }
        layer
    }
}
