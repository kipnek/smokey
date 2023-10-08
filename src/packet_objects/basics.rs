use crate::layer_processors::internet_processor::InternetProcessor;
use crate::layer_processors::link_processor::LinkProcessor;
use crate::layer_processors::protocol_processor::TransportProcessor;
use crate::packet_objects::layers::data::DataLayer;
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
    pub application_layer: Option<DataLayer>,
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
                protocol: "unknown".to_string(),
                source: "unknown".to_string(),
                destination: "unknown".to_string(),
                info: "unknown".to_string(),
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
        match self.internet_layer {
            InternetLayer::IPv4(ref header) => {
                self.summary.source = header.source_address.to_string();
                self.summary.destination = header.destination_address.to_string();
                self.summary.protocol = "IPv4".to_string();
                self.summary.info = format!("{} is connecting to {}", self.summary.source, self.summary.destination);
            }
            InternetLayer::IPv6(ref header) => {
                self.summary.source = header.source.to_string();
                self.summary.destination = header.destination.to_string();
                self.summary.protocol = "IPv4".to_string();
                self.summary.info = format!("{} is connecting to {}", self.summary.source, self.summary.destination);
            }
            InternetLayer::Unknown => match &self.link_layer {
                LinkLayer::Ethernet(ref header) => {
                    self.summary.source = header.source_mac.to_string();
                    self.summary.destination = header.destination_mac.to_string();
                    self.summary.info = format!("{} is connecting to {}", self.summary.source, self.summary.destination);
                }
                LinkLayer::Unknown => {}
            },
        }
        match &self.protocol_layer {
            ProtocolLayer::Tcp(ref header) => {
                self.summary.protocol = "TCP".to_string();
                self.summary.info = format!(
                    "{} is connecting to port {}",
                    header.source_port.to_string(),
                    header.destination_port.to_string()
                );
            }
            ProtocolLayer::Udp(ref header) => {
                self.summary.protocol = "UDP".to_string();
                self.summary.info = format!(
                    "{} is connecting to port {}",
                    header.source_port.to_string(),
                    header.destination_port.to_string()
                );
            }
            ProtocolLayer::Icmp(ref header) => {
                self.summary.protocol = "ICMP".to_string();
                self.summary.info = format!(
                    "{} icmp code, {} icmp type",
                    header.icmp_code, header.icmp_type
                )
            }
            ProtocolLayer::Unknown=>{}
        }
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

