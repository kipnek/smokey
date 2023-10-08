use crate::layer_processors::internet_processor::InternetProcessor;
use crate::layer_processors::link_processor::LinkProcessor;
use crate::layer_processors::protocol_processor::TransportProcessor;
use crate::packet_objects::layers::data::ApplicationLayer;
use crate::packet_objects::layers::internet::InternetLayer;
use crate::packet_objects::layers::link::LinkLayer;
use crate::packet_objects::layers::protocol::ProtocolLayer;
use crate::traits::NextHeaderTrait;
use serde::{Deserialize, Serialize};
use std::iter::Sum;

#[derive(Debug, Clone)]
pub struct BasePacket {
    pub id: i32,
    pub date: String,
    pub link_layer: LinkLayer,
    pub internet_layer: InternetLayer,
    pub protocol_layer: ProtocolLayer,
    pub application_layer: Option<ApplicationLayer>,
    pub summary: Summary,
    pub packet_data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FieldType {
    pub field_name: String,
    pub num: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    pub protocol: String,
    pub source: String,
    pub destination: String,
    pub info: String,
}

/*


impl base packet


 */

impl BasePacket {
    //New for BasePacket {
    pub fn new(id: i32, packet_data: Vec<u8>) -> Self {
        BasePacket {
            id,
            date: chrono::offset::Local::now().to_string(),
            link_layer: LinkLayer::Unknown,
            internet_layer: InternetLayer::Unknown,
            protocol_layer: ProtocolLayer::Unknown,
            application_layer: None,
            summary: Summary {
                protocol: "".to_string(),
                source: "".to_string(),
                destination: "".to_string(),
                info: "".to_string(),
            },
            packet_data,
        }
        .datalink_parse()
        .network_parse()
        .protocol_parse()
        .set_summary()
        .to_owned()
    }

    /*

    packet summary and other function associated with setting the summary

     */

    pub fn set_summary(&mut self) -> &mut Self {
        let (mut source, mut destination, mut protocol, mut info) = (
            "unknown".to_string(),
            "unknown".to_string(),
            "Unknown".to_string(),
            "unknown".to_string(),
        );
        match self.internet_layer {
            InternetLayer::IPv4(ref header) => {
                source = header.source_address.to_string();
                destination = header.destination_address.to_string();
                protocol = "IPv4".to_string();
            }
            InternetLayer::IPv6(ref header) => {
                source = header.source.to_string();
                destination = header.destination.to_string();
                protocol = "IPv4".to_string();
            }
            InternetLayer::Unknown => match &self.link_layer {
                LinkLayer::Ethernet(ref header) => {
                    source = header.source_mac.to_string();
                    destination = header.destination_mac.to_string();
                    info = format!("{} is connecting to {}", source, destination);
                }
                LinkLayer::Unknown => {}
            },
        }
        match &self.protocol_layer {
            ProtocolLayer::Tcp(ref header) => {
                protocol = "TCP".to_string();
                info = format!(
                    "{} is connecting to port {}",
                    header.source_port.to_string(),
                    header.destination_port.to_string()
                );
            }
            ProtocolLayer::Udp(ref header) => {
                protocol = "UDP".to_string();
                info = format!(
                    "{} is connecting to port {}",
                    header.source_port.to_string(),
                    header.destination_port.to_string()
                );
            }
            ProtocolLayer::Icmp(ref header) => {
                protocol = "ICMP".to_string();
                info = format!(
                    "{} icmp code, {} icmp type",
                    header.icmp_code, header.icmp_type
                )
            }
        }

        self.summary = Summary {
            protocol,
            source,
            destination,
            info,
        };
        self
    }

    /*

    parse layers

     */
    pub fn datalink_parse(&mut self) -> &mut Self {
        self.link_layer = LinkProcessor::link_process(&self.packet_data);
        self
    }

    pub fn network_parse(&mut self) -> &mut Self {
        let header_trait: &dyn NextHeaderTrait = match &self.link_layer {
            LinkLayer::Ethernet(header) => header,
            LinkLayer::Unknown => return self,
        };
        self.internet_layer = InternetProcessor::process_internet(
            header_trait.payload(),
            &header_trait.next_header(),
        );
        self
    }

    pub fn protocol_parse(&mut self) -> &mut Self {
        let header_trait: &dyn NextHeaderTrait = match &self.internet_layer {
            InternetLayer::IPv4(ref header) => header,
            InternetLayer::IPv6(ref header) => header,
            InternetLayer::Unknown => return self,
        };
        self.protocol_layer = TransportProcessor::process_protocol(
            header_trait.payload(),
            &header_trait.next_header(),
        );
        self
    }
}
