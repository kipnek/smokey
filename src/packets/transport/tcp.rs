use crate::packets::shared_objs::ProtocolType;
use crate::packets::traits::Layer;
use linked_hash_map::LinkedHashMap;
use pnet::packet::Packet;

/*


TCP header


 */

#[derive(Debug, Clone, Default)]
pub struct TcpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub data_offset_reserved_flags: u8,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub flags: TcpFlags,
}

#[derive(Debug, Clone, Default)]
pub struct TcpFlags {
    urg: bool,
    ack: bool,
    psh: bool,
    rst: bool,
    syn: bool,
    fin: bool,
}

impl TcpHeader {
    fn set_tcp_flags(flags_byte: u8) -> TcpFlags {
        TcpFlags {
            urg: (flags_byte & 0b10_0000) != 0,
            ack: (flags_byte & 0b01_0000) != 0,
            psh: (flags_byte & 0b00_1000) != 0,
            rst: (flags_byte & 0b00_0100) != 0,
            syn: (flags_byte & 0b00_0010) != 0,
            fin: (flags_byte & 0b00_0001) != 0,
        }
    }
}

/*


TCP Packet


 */

#[derive(Default, Debug, Clone)]
pub struct TcpPacket {
    pub header: TcpHeader,
    pub payload: Vec<u8>,
}

impl TcpPacket {
    pub fn new(packet: &[u8]) -> Option<TcpPacket> {
        let packet = pnet::packet::tcp::TcpPacket::new(packet)?;

        let header = TcpHeader {
            source_port: packet.get_source(),
            destination_port: packet.get_destination(),
            sequence_number: packet.get_sequence(),
            acknowledgment_number: packet.get_acknowledgement(),
            data_offset_reserved_flags: packet.get_data_offset(),
            window_size: packet.get_window(),
            checksum: packet.get_checksum(),
            urgent_pointer: packet.get_urgent_ptr(),
            flags: TcpHeader::set_tcp_flags(packet.get_flags()),
        };

        Some(TcpPacket {
            header,
            payload: packet.payload().to_vec(),
        })
    }
}

impl Layer for TcpPacket {
    fn get_summary(&self) -> LinkedHashMap<String, String> {
        LinkedHashMap::<String, String>::from_iter([
            ("protocol".to_owned(), "tcp".to_owned()),
            (
                "source_port".to_owned(),
                self.header.source_port.to_string(),
            ),
            (
                "destination_port".to_owned(),
                self.header.destination_port.to_string(),
            ),
            (
                "acknowledgment_number".to_owned(),
                self.header.acknowledgment_number.to_string(),
            ),
            (
                "data_offset_reserved_flags".to_owned(),
                self.header.data_offset_reserved_flags.to_string(),
            ),
            (
                "window_size".to_owned(),
                self.header.window_size.to_string(),
            ),
            ("checksum".to_owned(), self.header.checksum.to_string()),
            (
                "urgent_pointer".to_owned(),
                self.header.urgent_pointer.to_string(),
            ),
            (
                "flags".to_owned(),
                format!(
                    "ack : {}, psh : {}, rst : {}, syn : {}, fin : {}",
                    u8::from(self.header.flags.ack),
                    u8::from(self.header.flags.psh),
                    u8::from(self.header.flags.rst),
                    u8::from(self.header.flags.syn),
                    u8::from(self.header.flags.fin),
                ),
            ),
        ])
    }

    fn get_next(&self) -> Option<&dyn Layer> {
        None
    }
    fn protocol_type(&self) -> ProtocolType {
        ProtocolType::Tcp
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
            "TCP Source Port {} -> Destination {}",
            self.header.source_port, self.header.destination_port
        )
    }
}
