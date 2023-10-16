use crate::packets::shared_objs::ProtocolType;
use crate::packets::traits::Layer;
use pnet::packet::Packet;
use std::collections::HashMap;
use linked_hash_map::LinkedHashMap;

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
    pub payload: Vec<u8>,
    pub malformed: bool,
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
            urg: (flags_byte & 0b100000) != 0,
            ack: (flags_byte & 0b010000) != 0,
            psh: (flags_byte & 0b001000) != 0,
            rst: (flags_byte & 0b000100) != 0,
            syn: (flags_byte & 0b000010) != 0,
            fin: (flags_byte & 0b000001) != 0,
        }
    }

    fn malformed(payload: &[u8]) -> TcpHeader {
        TcpHeader {
            source_port: 0,
            destination_port: 0,
            sequence_number: 0,
            acknowledgment_number: 0,
            data_offset_reserved_flags: 0,
            window_size: 0,
            checksum: 0,
            urgent_pointer: 0,
            flags: Default::default(),
            payload: payload.to_vec(),
            malformed: false,
        }
    }
}


/*


TCP Packet


 */


#[derive(Default, Debug)]
pub struct TcpPacket {
    pub header: TcpHeader,
    pub payload: Option<Box<dyn Layer>>,
}

impl Layer for TcpPacket {
    fn deserialize(&mut self, packet: &[u8]) {
        let header = match pnet::packet::tcp::TcpPacket::new(packet) {
            None => TcpHeader::malformed(packet),
            Some(header) => TcpHeader {
                source_port: header.get_source(),
                destination_port: header.get_destination(),
                sequence_number: header.get_sequence(),
                acknowledgment_number: header.get_acknowledgement(),
                data_offset_reserved_flags: header.get_data_offset(),
                window_size: header.get_window(),
                checksum: header.get_checksum(),
                urgent_pointer: header.get_urgent_ptr(),
                flags: TcpHeader::set_tcp_flags(header.get_flags()),
                payload: header.payload().to_vec(),
                malformed: false,
            },
        };
        self.header = header;
        self.payload = None;
    }

    fn get_summary(&self) -> LinkedHashMap<String, String> {
        let mut map: LinkedHashMap<String, String> = LinkedHashMap::new();
        map.insert("protocol".to_string(), "tcp".to_string());
        map.insert(
            "source_port".to_string(),
            self.header.source_port.to_string(),
        );
        map.insert(
            "destination_port".to_string(),
            self.header.destination_port.to_string(),
        );
        map.insert(
            "acknowledgment_number".to_string(),
            self.header.acknowledgment_number.to_string(),
        );
        map.insert(
            "data_offset_reserved_flags".to_string(),
            self.header.data_offset_reserved_flags.to_string(),
        );
        map.insert(
            "window_size".to_string(),
            self.header.window_size.to_string(),
        );
        map.insert("checksum".to_string(), self.header.checksum.to_string());
        map.insert(
            "urgent_pointer".to_string(),
            self.header.urgent_pointer.to_string(),
        );
        map.insert(
            "flags".to_string(),
            format!(
                "ack : {}, psh : {}, rst : {}, syn : {}, fin : {}",
                self.header.flags.ack as u8,
                self.header.flags.psh as u8,
                self.header.flags.rst as u8,
                self.header.flags.syn as u8,
                self.header.flags.fin as u8,
            ),
        );
        map.insert("malformed".to_string(), self.header.malformed.to_string());
        map
    }

    fn get_next(&self) -> &Option<Box<dyn Layer>> {
        &self.payload
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

    fn info(&self) -> String {
        format!(
            "TCP Source Port {} -> Destination {}",
            self.header.source_port, self.header.destination_port
        )
    }
}
