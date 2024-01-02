use crate::packets::{
    application::app_parser::parse_app_layer,
    packet_traits::Layer,
    shared_objs::{Application, LayerData, Protocol},
};
use pnet::packet::Packet;
use std::{borrow::Cow, collections::BTreeMap};

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

#[derive(Debug, Clone)]
pub struct TcpPacket {
    pub header: TcpHeader,
    pub payload: Application,
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

        let payload = parse_app_layer(packet.payload());

        Some(TcpPacket { header, payload })
    }
}

impl Layer for TcpPacket {
    fn get_summary(&self) -> BTreeMap<String, String> {
        let mut btree = BTreeMap::new();
        let TcpHeader {
            source_port,
            destination_port,
            sequence_number,
            acknowledgment_number,
            data_offset_reserved_flags,
            window_size,
            checksum,
            urgent_pointer,
            flags:
                TcpFlags {
                    urg,
                    ack,
                    psh,
                    rst,
                    syn,
                    fin,
                },
        } = &self.header;
        let [urg, ack, psh, rst, syn, fin] = [*urg, *ack, *psh, *rst, *syn, *fin].map(u8::from);
        let flags_string = format!(
            "urg {}, ack {}, psh {}, rst {}, syn {}, fin {}",
            urg, ack, psh, rst, syn, fin
        );

        btree.insert("source_port".to_string(), source_port.to_string());
        btree.insert("destination_port".to_string(), destination_port.to_string());
        btree.insert("sequence_number".to_string(), sequence_number.to_string());
        btree.insert(
            "acknowledgment_number".to_string(),
            acknowledgment_number.to_string(),
        );
        btree.insert(
            "source_port".to_string(),
            data_offset_reserved_flags.to_string(),
        );
        btree.insert("window_size".to_string(), window_size.to_string());
        btree.insert("checksum".to_string(), checksum.to_string());
        btree.insert("urgent_pointer".to_string(), urgent_pointer.to_string());
        btree.insert("flags".to_string(), flags_string);

        btree
    }
    fn protocol(&self) -> Protocol {
        Protocol::TCP
    }

    fn get_next(&self) -> LayerData {
        match &self.payload {
            //Application::HttpRequest(d) => {},
            //Application::HttpResponse(d) => {},
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
            "TCP Source Port {} -> Destination {}",
            self.header.source_port, self.header.destination_port
        )
    }
}
