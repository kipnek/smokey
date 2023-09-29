use crate::packet_objects::headers::tcp::TcpHeader;
use crate::packet_objects::headers::udp::UdpHeader;
use crate::packet_objects::layers::transport::TransportLayer;
use crate::traits::Processable;
use pnet::packet::{tcp, udp};

pub struct TransportProcessor {}

impl TransportProcessor {
    pub fn process_transport(payload: &[u8], next_header: &u16) -> Option<TransportLayer> {
        match next_header {
            6 => Some(process_tcp(payload)),
            17 => Some(process_udp(payload)),
            _ => None,
        }
    }
}

fn process_tcp(payload: &[u8]) -> TransportLayer {
    if let Some(tcp_packet) = tcp::TcpPacket::new(payload) {
        TransportLayer::Tcp(tcp_packet.process())
    } else {
        TransportLayer::Tcp(TcpHeader::deformed_packet(payload.to_vec()))
    }
}

fn process_udp(payload: &[u8]) -> TransportLayer {
    if let Some(udp_packet) = udp::UdpPacket::new(payload) {
        TransportLayer::Udp(udp_packet.process())
    } else {
        TransportLayer::Udp(UdpHeader::deformed_packet(payload.to_vec()))
    }
}
