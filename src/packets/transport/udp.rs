use crate::packets::application::app_parser::parse_app_layer;
use crate::packets::packet_traits::Layer;
use crate::packets::shared_objs::{Application, LayerData, Protocol};
use pnet::packet::Packet;
use std::borrow::Cow;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default)]
pub struct UdpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
}

#[derive(Debug, Clone)]
pub struct UdpPacket {
    pub header: UdpHeader,
    pub payload: Application,
}

impl UdpPacket {
    pub fn new(packet: &[u8]) -> Option<UdpPacket> {
        let packet = pnet::packet::udp::UdpPacket::new(packet)?;

        let header = UdpHeader {
            source_port: packet.get_source(),
            destination_port: packet.get_destination(),
            length: packet.get_length(),
            checksum: packet.get_checksum(),
        };

        let payload = parse_app_layer(packet.payload());

        Some(UdpPacket { header, payload })
    }
}

impl Layer for UdpPacket {
    fn get_summary(&self) -> BTreeMap<String, String> {
        let mut btree = BTreeMap::new();
        let UdpHeader {
            source_port,
            destination_port,
            length,
            checksum,
        } = &self.header;

        btree.insert("source_port".to_string(), source_port.to_string());
        btree.insert("destination_port".to_string(), destination_port.to_string());
        btree.insert("length".to_string(), length.to_string());
        btree.insert("checksum".to_string(), checksum.to_string());

        btree
    }

    fn protocol(&self) -> Protocol {
        Protocol::UDP
    }

    fn get_next(&self) -> LayerData {
        match &self.payload {
            //Application::HttpRequest(_) => todo!(),
            //Application::HttpResponse(_) => todo!(),
            Application::Dns(dns_message) => LayerData::Application(dns_message),
            Application::Other(bytes) => LayerData::Data(bytes),
            //Application::Tls(_) => todo!(),
        }
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
