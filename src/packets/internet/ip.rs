use crate::packets::shared_objs::{ExtendedType, ProtocolDescriptor, ProtocolType};
use crate::packets::traits::Layer;
use crate::packets::transport::{tcp::TcpPacket, udp::UdpPacket};
use linked_hash_map::LinkedHashMap;
use pnet::packet::Packet;
use pnet::packet::{
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::Ipv4OptionIterable,
};

use std::fmt::{Debug, Formatter};

/*



IPV4 Header



 */
#[derive(Default, Debug, Clone)]
pub struct Ipv4Header {
    pub version_ihl: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub options: Vec<Ipv4Options>,
    pub flags_fragment_offset: u16,
    pub time_to_live: u8,
    pub header_checksum: u16,
    pub source_address: String,
    pub destination_address: String,
    pub next_header: ProtocolDescriptor<ExtendedType<IpNextHeaderProtocol>>,
    pub flags: Ipv4Flags,
}

#[derive(Clone, Default, Debug)]
pub struct Ipv4Flags {
    reserved: bool,
    dontfrag: bool,
    morefrag: bool,
}

#[derive(Clone, Debug)]
pub enum Ipv4Options {
    Eol,
    Nop,
    Lsrr,
    Ssrr,
    Rr,
    Timestamp,
    Unknown(String),
}

impl Ipv4Header {
    pub fn malformed(packet: &[u8]) -> Ipv4Header {
        Ipv4Header {
            version_ihl: 4,
            dscp: 0,
            ecn: 0,
            total_length: 0,
            identification: 0,
            options: vec![],
            flags_fragment_offset: 0,
            time_to_live: 0,
            header_checksum: 0,
            source_address: String::new(),
            destination_address: String::new(),
            next_header: ProtocolDescriptor {
                protocol_name: "malformed".to_owned(),
                protocol_type: ExtendedType::Malformed,
            },
            flags: Ipv4Flags {
                reserved: false,
                dontfrag: false,
                morefrag: false,
            },
        }
    }
    pub fn set_flags(number: u8) -> Ipv4Flags {
        Ipv4Flags {
            reserved: (number & 0b100) != 0,
            dontfrag: (number & 0b010) != 0,
            morefrag: (number & 0b001) != 0,
        }
    }

    pub fn set_options(options: Ipv4OptionIterable) -> Vec<Ipv4Options> {
        options
            .map(|option| {
                match option.get_number().0 {
                    // End of Options List
                    0x00 => Ipv4Options::Eol,
                    // No Operation
                    0x01 => Ipv4Options::Nop,
                    // Loose Source and Record Route
                    0x83 => Ipv4Options::Lsrr,
                    // Strict Source and Record Route
                    0x89 => Ipv4Options::Ssrr,
                    // Record Route
                    0x07 => Ipv4Options::Rr,
                    // Timestamp
                    0x44 => Ipv4Options::Timestamp,
                    // ... add other options as needed
                    _ => Ipv4Options::Unknown(format!(
                        "Unknown Option: {:#X}",
                        option.get_number().0
                    )),
                }
            })
            .collect()
    }
}

impl Ipv4Options {
    fn description(&self) -> &str {
        match self {
            Ipv4Options::Eol => "End of Options List",
            Ipv4Options::Nop => "No Operation",
            Ipv4Options::Lsrr => "Loose Source and Record Route",
            Ipv4Options::Ssrr => "Strict Source and Record Route",
            Ipv4Options::Rr => "Record Route",
            Ipv4Options::Timestamp => "Timestamp",
            Ipv4Options::Unknown(desc) => desc,
        }
    }
}

/*



IPv4 Packets



 */

#[derive(Default, Clone)]
pub struct Ipv4Packet {
    pub header: Ipv4Header,
    pub payload: Option<Box<dyn Layer>>,
}

//impls for ipv4 packet
impl Debug for Ipv4Packet {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ipv4Packet")
            .field("header", &self.header)
            .field("payload", &self.payload)
            .finish()
    }
}

impl Ipv4Packet {
    pub fn new(packet: &[u8]) -> Option<Ipv4Packet> {
        let packet = pnet::packet::ipv4::Ipv4Packet::new(packet)?;

        let header = Ipv4Header {
            version_ihl: packet.get_version(),
            dscp: packet.get_dscp(),
            ecn: packet.get_ecn(),
            total_length: packet.get_total_length(),
            identification: packet.get_total_length(),
            options: Ipv4Header::set_options(packet.get_options_iter()),
            flags_fragment_offset: packet.get_fragment_offset(),
            time_to_live: packet.get_ttl(),
            header_checksum: packet.get_checksum(),
            source_address: packet.get_source().to_string(),
            destination_address: packet.get_destination().to_string(),
            next_header: set_next_header(packet.get_next_level_protocol()),
            flags: Ipv4Header::set_flags(packet.get_flags()),
        };

        let payload = match header.next_header.protocol_type {
            ExtendedType::Known(IpNextHeaderProtocols::Tcp) => {
                TcpPacket::new(packet.payload()).map(|x| Box::new(x) as _)
            }
            ExtendedType::Known(IpNextHeaderProtocols::Udp) => {
                UdpPacket::new(packet.payload()).map(|x| Box::new(x) as _)
            }
            ExtendedType::Known(_) | ExtendedType::Malformed => None,
        };

        Some(Ipv4Packet { header, payload })
    }
}

impl Layer for Ipv4Packet {
    fn get_summary(&self) -> LinkedHashMap<String, String> {
        let options_string = { self.header.options.iter() }
            .map(Ipv4Options::description)
            .collect::<Vec<&str>>()
            .join("\n");

        LinkedHashMap::<String, String>::from_iter([
            ("protocol".to_owned(), "ipv4".to_owned()),
            ("version".to_owned(), self.header.version_ihl.to_string()),
            ("dscp".to_owned(), self.header.dscp.to_string()),
            ("ecn".to_owned(), self.header.ecn.to_string()),
            (
                "total_length".to_owned(),
                self.header.total_length.to_string(),
            ),
            (
                "identification".to_owned(),
                self.header.identification.to_string(),
            ),
            (
                "flags_fragment_offset".to_owned(),
                self.header.flags_fragment_offset.to_string(),
            ),
            (
                "time_to_live".to_owned(),
                self.header.time_to_live.to_string(),
            ),
            (
                "header_checksum".to_owned(),
                self.header.header_checksum.to_string(),
            ),
            (
                "source_address".to_owned(),
                self.header.source_address.clone(),
            ),
            (
                "destination_address".to_owned(),
                self.header.destination_address.clone(),
            ),
            (
                "next_header".to_owned(),
                format!("protocol : {}", self.header.next_header.protocol_name,),
            ),
            (
                "flags".to_owned(),
                format!(
                    "reserved : {}, dont fragment : {},  more fragment : {}",
                    self.header.flags.reserved,
                    self.header.flags.dontfrag,
                    self.header.flags.morefrag
                ),
            ),
            ("options".to_owned(), options_string),
        ])
    }

    fn get_next(&self) -> Option<&dyn Layer> {
        self.payload.as_deref()
    }

    fn protocol_type(&self) -> ProtocolType {
        ProtocolType::Ipv4
    }

    fn source(&self) -> String {
        self.header.source_address.clone()
    }

    fn destination(&self) -> String {
        self.header.destination_address.clone()
    }

    fn box_clone(&self) -> Box<dyn Layer> {
        Box::new(self.clone())
    }

    fn info(&self) -> String {
        format!(
            "flags: MoreFrag: {} DontFrag: {} Reserved: {}",
            self.header.flags.morefrag, self.header.flags.dontfrag, self.header.flags.reserved
        )
    }
}

/*



IPV6



 */
#[derive(Debug, Clone)]
pub struct Ipv6Header {
    pub payload: Vec<u8>,
    pub traffic_class: u8,
    pub flow_label: u16,
    pub payload_length: u16,
    //pub next_header: ProtocolDescriptor,
    pub hop_limit: u8,
    pub source: String,
    pub destination: String,
    pub version: u8,
}

/*


Helper functions


 */
fn protocol_to_string(proto: IpNextHeaderProtocol) -> String {
    match proto {
        IpNextHeaderProtocols::Ipv4 => "IPv4".to_owned(),
        IpNextHeaderProtocols::Tcp => "Tcp".to_owned(),
        IpNextHeaderProtocols::Udp => "Udp".to_owned(),
        IpNextHeaderProtocols::Ipv6 => "IPv6".to_owned(),
        _ => "Unknown".to_owned(),
    }
}

fn set_next_header(
    next_header: IpNextHeaderProtocol,
) -> ProtocolDescriptor<ExtendedType<IpNextHeaderProtocol>> {
    ProtocolDescriptor {
        protocol_name: protocol_to_string(next_header),
        protocol_type: ExtendedType::Known(next_header),
    }
}

#[derive(Debug, Clone, Default)]
pub enum ExtendedNextHeader {
    Known(IpNextHeaderProtocol),
    #[default]
    Malformed,
}
