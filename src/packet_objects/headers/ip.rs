use crate::packet_objects::raw::FieldType;
use crate::traits::Processable;
use pnet::packet::{ipv4, ipv6, Packet};
use std::net::{Ipv4Addr, Ipv6Addr};
#[derive(Debug, Clone)]
pub struct Ipv4Header {
    pub version_ihl: u8,
    pub dscp_ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags_fragment_offset: u16,
    pub time_to_live: u8,
    pub header_checksum: u16,
    pub source_address: Ipv4Addr,
    pub destination_address: Ipv4Addr,
    pub next_header: FieldType,
    pub payload: Vec<u8>,
}
/*
let payload = self.payload().to_vec();
let traffic_class = self.get_traffic_class();
let flow_label =  self.get_flow_label();
let payload_length = self.get_payload_length();
let next_header = set_protocol_field(self.get_next_header().0);
let hop_limit = self.get_hop_limit();
let source = self.get_source();
let destination = self.get_destination();
let version = self.get_version();
*/
#[derive(Debug, Clone)]
pub struct Ipv6Header {
    pub payload: Vec<u8>,
    pub traffic_class: u8,
    pub flow_label: u16,
    pub payload_length: u16,
    pub next_header: FieldType,
    pub hop_limit: u8,
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub version: u8,
}

impl<'a> Processable<'a, Ipv4Header> for ipv4::Ipv4Packet<'a> {
    fn process(&self) -> Ipv4Header {
        let destination_address = self.get_destination();
        let source_address = self.get_source();
        let header_checksum = self.get_checksum();
        let time_to_live = self.get_ttl();
        let flags_fragment_offset = self.get_fragment_offset();
        let identification = self.get_identification();
        let total_length = self.get_total_length();
        let dscp_ecn = self.get_dscp();
        let version_ihl = self.get_version();
        let next_header = set_protocol_field(self.get_next_level_protocol().0);
        let payload = self.payload().to_vec();

        Ipv4Header {
            version_ihl,
            dscp_ecn,
            total_length,
            identification,
            flags_fragment_offset,
            time_to_live,
            header_checksum,
            source_address,
            destination_address,
            next_header,
            payload,
        }
    }
}

impl<'a> Processable<'a, Ipv6Header> for ipv6::Ipv6Packet<'a> {
    fn process(&self) -> Ipv6Header {
        let payload = self.payload().to_vec();
        let traffic_class = self.get_traffic_class();
        let flow_label = self.get_flow_label();
        let payload_length = self.get_payload_length();
        let next_header = set_protocol_field(self.get_next_header().0);
        let hop_limit = self.get_hop_limit();
        let source = self.get_source();
        let destination = self.get_destination();
        let version = self.get_version();

        Ipv6Header {
            payload,
            traffic_class,
            flow_label: flow_label as u16,
            payload_length,
            next_header,
            hop_limit,
            source,
            destination,
            version,
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
