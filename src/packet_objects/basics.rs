use crate::layer_processors::internet_processor::InternetProcessor;
use crate::layer_processors::link_processor::LinkProcessor;
use crate::layer_processors::protocol_processor::TransportProcessor;
use crate::packet_objects::layers::application::ApplicationLayer;
use crate::packet_objects::layers::internet::InternetLayer;
use crate::packet_objects::layers::link::LinkLayer;
use crate::packet_objects::layers::protocol::ProtocolLayer;
use crate::traits::NextHeaderTrait;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct BasePacket {
    pub id: i32,
    pub date: String,
    pub link_header: LinkLayer,
    pub internet_header: InternetLayer,
    pub protocol_header: ProtocolLayer,
    pub application_layer: Option<ApplicationLayer>,
    pub packet_data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FieldType {
    pub field_name: String,
    pub num: u16,
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
            link_header: LinkLayer::Unknown,
            internet_header: InternetLayer::Unknown,
            protocol_header: ProtocolLayer::Unknown,
            application_layer: None,
            packet_data,
        }
        .datalink_parse()
        .network_parse()
        .protocol_parse()
        .to_owned()
    }

    /*



    parse layers



     */
    pub fn datalink_parse(&mut self) -> &mut Self {
        self.link_header = LinkProcessor::link_process(&self.packet_data);
        self
    }

    pub fn network_parse(&mut self) -> &mut Self {
        let header_trait: &dyn NextHeaderTrait = match &self.link_header {
            LinkLayer::Ethernet(header) => header,
            LinkLayer::Unknown => return self,
        };
        self.internet_header = InternetProcessor::process_internet(
            header_trait.payload(),
            &header_trait.next_header(),
        );
        self
    }

    pub fn protocol_parse(&mut self) -> &mut Self {
        let header_trait: &dyn NextHeaderTrait = match &self.internet_header {
            InternetLayer::IPv4(ref header) => header,
            InternetLayer::IPv6(ref header) => header,
            InternetLayer::Unknown => return self,
        };
        self.protocol_header = TransportProcessor::process_protocol(
            header_trait.payload(),
            &header_trait.next_header(),
        );
        self
    }
}
