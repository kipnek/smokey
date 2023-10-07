use crate::layer_processors::internet_processor::InternetProcessor;
use crate::layer_processors::link_processor::LinkProcessor;
use crate::layer_processors::protocol_processor::TransportProcessor;
use crate::packet_objects::layers::internet::InternetLayer;
use crate::packet_objects::layers::link::LinkLayer;
use crate::packet_objects::layers::protocol::ProtocolLayer;
use serde::{Deserialize, Serialize};
use crate::traits::InternetHeaderTrait;

#[derive(Debug, Clone)]
pub struct BasePacket {
    pub id: i32,
    pub date: String,
    pub link_header: Option<LinkLayer>,
    pub internet_header: Option<InternetLayer>,
    pub protocol_header: Option<ProtocolLayer>,
    pub packet_data: Vec<u8>,
    pub protocol : Protocol,
}

#[derive(Debug, Clone, Serialize)]
pub struct FieldType {
    pub field_name: String,
    pub num: u16,
}

#[derive(Debug, Clone, Serialize)]
pub enum Protocol {
    IPv4,
    IPv6,
    TCP,
    UDP,
    ETHERNET,
    HTTP,
    UNKNOWN
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
            link_header: None,
            internet_header: None,
            protocol_header: None,
            packet_data,
            protocol: Protocol::UNKNOWN
        }
        .datalink_parse()
        .network_parse()
        .protocol_parse()
        .update_protocol()
        .to_owned()
    }

    /*

    update protocol

     */
    fn update_protocol(&mut self) -> &mut Self {

        if let Some(ref header) = &self.protocol_header {
            match header {
                ProtocolLayer::Tcp(_) => {
                    self.protocol = Protocol::TCP;
                }
                ProtocolLayer::Udp(_) => {
                    self.protocol = Protocol::UDP;
                }
                _=>{}
            }
        }else if let Some(ref header) = &self.internet_header {
            match header {
                InternetLayer::IPv4(_) => {
                    self.protocol = Protocol::IPv4;
                }
                InternetLayer::IPv6(_) => {
                    self.protocol = Protocol::IPv6
                }
                _=>{}
            }
        }else if let Some(ref header) = &self.link_header {
            match header {
                LinkLayer::Ethernet(_) => {
                    self.protocol = Protocol::ETHERNET;
                }
                _=>{}
            }
        }
        self
    }




    /*



    parse layers



     */
    pub fn datalink_parse(&mut self) -> &mut Self {
        self.link_header = LinkProcessor::link_process(&self.packet_data);
        self
    }

    pub fn network_parse(&mut self) -> &mut Self {
        if let Some(eh) = &self.link_header {
            match eh {
                LinkLayer::Ethernet(eh) => {
                    self.internet_header =
                        InternetProcessor::process_internet(&eh.payload, &eh.ether_type.num);
                }
            }
        }

        self
    }

    pub fn protocol_parse(&mut self) -> &mut Self {
        if let Some(iheader) = &self.internet_header {
            let header_trait: &dyn InternetHeaderTrait = match iheader {
                InternetLayer::IPv4(ref header) => header,
                InternetLayer::IPv6(ref header) => header,
            };
            self.protocol_header =
                TransportProcessor::process_protocol(&header_trait.payload(), &header_trait.next_header());
        }
        self
    }
}
