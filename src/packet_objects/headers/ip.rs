use crate::packet_objects::basics::FieldType;
use crate::traits::Processable;
use pnet::packet::{ipv4, ipv6, Packet};
#[derive(Debug, Clone)]
pub struct Ipv4Header {
    pub version_ihl: u8,
    pub dscp_ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags_fragment_offset: u16,
    pub time_to_live: u8,
    pub header_checksum: u16,
    pub source_address: String,
    pub destination_address: String,
    pub next_header: FieldType,
    pub payload: Vec<u8>,
    pub malformed: bool,
}

#[derive(Debug, Clone)]
pub struct Ipv6Header {
    pub payload: Vec<u8>,
    pub traffic_class: u8,
    pub flow_label: u16,
    pub payload_length: u16,
    pub next_header: FieldType,
    pub hop_limit: u8,
    pub source: String,
    pub destination: String,
    pub version: u8,
}

impl Ipv4Header {
    pub fn deformed_packet(payload: Vec<u8>) -> Self {
        Ipv4Header {
            version_ihl: 0,
            dscp_ecn: 0,
            total_length: 0,
            identification: 0,
            flags_fragment_offset: 0,
            time_to_live: 0,
            header_checksum: 0,
            source_address: String::from(""),
            destination_address: String::from(""),
            next_header: FieldType {
                field_name: "malformed".to_string(),
                num: 0,
            },
            payload,
            malformed: true,
        }
    }
}

impl<'a> Processable<'a, Ipv4Header> for ipv4::Ipv4Packet<'a> {
    fn process(&self) -> Ipv4Header {
        Ipv4Header {
            version_ihl: self.get_version(),
            dscp_ecn: self.get_dscp(),
            total_length: self.get_total_length(),
            identification: self.get_identification(),
            flags_fragment_offset: self.get_fragment_offset(),
            time_to_live: self.get_ttl(),
            header_checksum: self.get_checksum(),
            source_address: self.get_source().to_string(),
            destination_address: self.get_destination().to_string(),
            next_header: set_protocol_field(self.get_next_level_protocol().0),
            payload: self.payload().to_vec(),
            malformed: false,
        }
    }
}

impl<'a> Processable<'a, Ipv6Header> for ipv6::Ipv6Packet<'a> {
    fn process(&self) -> Ipv6Header {
        Ipv6Header {
            payload :self.payload().to_vec(),
            traffic_class:self.get_traffic_class(),
            flow_label: self.get_flow_label() as u16,
            payload_length : self.get_payload_length(),
            next_header : set_protocol_field(self.get_next_header().0),
            hop_limit : self.get_hop_limit(),
            source : self.get_source().to_string(),
            destination : self.get_destination().to_string(),
            version : self.get_version(),
        }
    }
}

pub fn set_protocol_field(number: u8) -> FieldType {
    let name: String = match &number {
        4 => {
            //ipv4
            "IPv4".to_string()
        }
        6 => {
            //tcp
            "Tcp".to_string()
        }
        41 => {
            //ipv6
            "IPv6".to_string()
        }
        _ => "n/a".to_string(),
    };

    FieldType {
        field_name: name,
        num: number as u16,
    }
}
