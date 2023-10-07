use crate::packet_objects::headers::ip;
use crate::packet_objects::layers::internet::InternetLayer;
use crate::traits::Processable;
use pnet::packet::ipv4;

pub struct InternetProcessor {}

impl InternetProcessor {
    pub fn process_internet(payload: &[u8], next_header: &u16) -> Option<InternetLayer> {
        match next_header {
            0x0800 => {//ipv4
                Some(process_ipv4(payload))
            },
            0x0806 => {
                //EtherType::Arp,
                return Some(InternetLayer::Unknown);
            }
            0x86DD => {
                //EtherType::Ipv6,
                return Some(InternetLayer::Unknown);
            }
            _ => {
                return Some(InternetLayer::Unknown);
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
