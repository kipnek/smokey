use crate::packet_objects::headers::ip;
use crate::packet_objects::layers::internet::InternetLayer;
use crate::traits::Processable;
use pnet::packet::ipv4;

pub struct InternetProcessor {}

impl InternetProcessor {
    pub fn process_internet(payload: &[u8], next_header: &u16) -> InternetLayer {
        match next_header {
            0x0800 => process_ipv4(payload),
            0x0806 => {
                //EtherType::Arp,
                return InternetLayer::Empty;
            }
            0x86DD => {
                //EtherType::Ipv6,
                return InternetLayer::Empty;
            }
            _ => {
                return InternetLayer::Empty;
            }
        }
    }
}
fn process_ipv4(payload: &[u8]) -> InternetLayer {
    if let Some(ipv4) = ipv4::Ipv4Packet::new(payload) {
        InternetLayer::IPv4(ipv4.process())
    } else {
        InternetLayer::IPv4(ip::Ipv4Header::deformed_packet(payload.to_vec()))
    }
}
