use crate::layer_processors::internet_processor::InternetProcessor;
use crate::layer_processors::link_processor::LinkProcessor;
use crate::layer_processors::transport_processor::TransportProcessor;
use crate::packet_objects::layers::internet::InternetLayer;
use crate::packet_objects::layers::link::LinkLayer;
use crate::packet_objects::layers::transport::TransportLayer;

#[derive(Debug, Clone)]
pub struct BasePacket {
    pub id: i32,
    pub date: String,
    pub link_header: LinkLayer,
    pub internet_header: InternetLayer,
    pub transport_header: TransportLayer,
    pub packet_data: Vec<u8>,
}
#[derive(Debug, Clone)]
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
            link_header: LinkLayer::Empty,
            internet_header: InternetLayer::Empty,
            transport_header: TransportLayer::Empty,
            packet_data,
        }
        .datalink_parse()
        .network_parse()
        .transport_parse()
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
        match self.link_header {
            LinkLayer::Ethernet(ref eh) => {
                self.internet_header =
                    InternetProcessor::process_internet(&eh.payload, &eh.ether_type.num);
            }
            _ => {}
        }

        self
    }

    pub fn transport_parse(&mut self) -> &mut Self {
        match self.internet_header {
            InternetLayer::IPv4(ref header) => {
                self.transport_header =
                    TransportProcessor::process_transport(&header.payload, &header.next_header.num);
            }
            InternetLayer::IPv6(ref header) => {
                self.transport_header =
                    TransportProcessor::process_transport(&header.payload, &header.next_header.num);
            }
            InternetLayer::Empty => {}
        }

        self
    }
}
