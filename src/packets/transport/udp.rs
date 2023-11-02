use crate::packets::shared_objs::ProtocolType;
use crate::packets::traits::Layer;
use linked_hash_map::LinkedHashMap;
use pnet::packet::Packet;

/*


Udp Header


 */
#[derive(Debug, Clone, Default)]
pub struct UdpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub malformed: bool,
}

/*


UDP Packet


 */

#[derive(Default, Debug, Clone)]
pub struct UdpPacket {
    pub header: UdpHeader,
    pub payload: Vec<u8>,
}

impl UdpPacket {
    pub fn new(packet: &[u8]) -> Option<UdpPacket> {
        let packet = pnet::packet::udp::UdpPacket::new(packet)?;

        let header = UdpHeader {
            source_port: packet.get_source(),
            destination_port: packet.get_destination(),
            length: packet.get_length(),
            checksum: packet.get_checksum(),
            malformed: false,
        };

        Some(UdpPacket {
            header,
            payload: packet.payload().to_vec(),
        })
    }
}

impl Layer for UdpPacket {
    fn get_summary(&self) -> LinkedHashMap<String, String> {
        LinkedHashMap::<String, String>::from_iter([
            ("protocol".to_owned(), "udp".to_owned()),
            (
                "source_port".to_owned(),
                self.header.source_port.to_string(),
            ),
            (
                "destination_port".to_owned(),
                self.header.destination_port.to_string(),
            ),
            ("length".to_owned(), self.header.length.to_string()),
            ("checksum".to_owned(), self.header.checksum.to_string()),
            ("malformed".to_owned(), self.header.malformed.to_string()),
        ])
    }

    fn get_next(&self) -> Option<&dyn Layer> {
        None
    }

    fn protocol_type(&self) -> ProtocolType {
        ProtocolType::Udp
    }

    fn source(&self) -> String {
        self.header.source_port.to_string()
    }

    fn destination(&self) -> String {
        self.header.destination_port.to_string()
    }

    fn box_clone(&self) -> Box<dyn Layer> {
        Box::new(self.clone())
    }

    fn info(&self) -> String {
        format!(
            "UDP src {} -> dest {}",
            self.header.source_port, self.header.destination_port
        )
    }
}
