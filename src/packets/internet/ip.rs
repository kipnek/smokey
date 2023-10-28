use crate::packets::shared_objs::{ExtendedType, ProtocolDescriptor, ProtocolType};
use crate::packets::traits::Layer;
use crate::packets::transport::{tcp::TcpPacket, udp::UdpPacket};
use linked_hash_map::LinkedHashMap;
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
    pub payload: Vec<u8>,
    pub malformed: bool,
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
            source_address: "".to_string(),
            destination_address: "".to_string(),
            next_header: ProtocolDescriptor {
                protocol_name: "malformed".to_string(),
                protocol_type: ExtendedType::Malformed,
            },
            flags: Ipv4Flags {
                reserved: false,
                dontfrag: false,
                morefrag: false,
            },
            payload: packet.to_vec(),
            malformed: true,
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
        let mut results = vec![];
        for option in options {
            match option.get_number().0 {
                0x00 => {
                    // End of Options List
                    results.push(Ipv4Options::Eol);
                }
                0x01 => {
                    // No Operation
                    results.push(Ipv4Options::Nop);
                }
                0x83 => {
                    // Loose Source and Record Route
                    results.push(Ipv4Options::Lsrr);
                }
                0x89 => {
                    // Strict Source and Record Route
                    results.push(Ipv4Options::Ssrr);
                }
                0x07 => {
                    // Record Route
                    results.push(Ipv4Options::Rr);
                }
                0x44 => {
                    // Timestamp
                    results.push(Ipv4Options::Timestamp);
                }
                // ... add other options as needed
                _ => {
                    results.push(Ipv4Options::Unknown(format!(
                        "Unknown Option: {:#X}",
                        option.get_number().0
                    )));
                }
            }
        }
        results
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

impl Layer for Ipv4Packet {
    fn deserialize(&mut self, packet: &[u8]) {
        let packet_header = match pnet::packet::ipv4::Ipv4Packet::new(packet) {
            None => Ipv4Header::malformed(packet),
            Some(header) => Ipv4Header {
                version_ihl: header.get_version(),
                dscp: header.get_dscp(),
                ecn: header.get_ecn(),
                total_length: header.get_total_length(),
                identification: header.get_total_length(),
                options: Ipv4Header::set_options(header.get_options_iter()),
                flags_fragment_offset: header.get_fragment_offset(),
                time_to_live: header.get_ttl(),
                header_checksum: header.get_checksum(),
                source_address: header.get_source().to_string(),
                destination_address: header.get_destination().to_string(),
                next_header: set_next_header(header.get_next_level_protocol()),
                flags: Ipv4Header::set_flags(header.get_flags()),
                payload: packet.to_vec(),
                malformed: false,
            },
        };

        let payload: Option<Box<dyn Layer>> = matches!(
            &packet_header.next_header.protocol_type,
            ExtendedType::Known(IpNextHeaderProtocols::Tcp)
                | ExtendedType::Known(IpNextHeaderProtocols::Udp)
        )
        .then(|| Box::new(parse_udp(&packet_header.payload)) as _);

        self.header = packet_header;
        self.payload = payload;
    }

    fn get_summary(&self) -> LinkedHashMap<String, String> {
        let options_string = self
            .header
            .options
            .iter()
            .map(|option| option.description())
            .collect::<Vec<&str>>()
            .join("\n");

        LinkedHashMap::<String, String>::from_iter([
            ("protocol".to_string(), "ipv4".to_string()),
            ("version".to_string(), self.header.version_ihl.to_string()),
            ("dscp".to_string(), self.header.dscp.to_string()),
            ("ecn".to_string(), self.header.ecn.to_string()),
            (
                "total_length".to_string(),
                self.header.total_length.to_string(),
            ),
            (
                "identification".to_string(),
                self.header.identification.to_string(),
            ),
            (
                "flags_fragment_offset".to_string(),
                self.header.flags_fragment_offset.to_string(),
            ),
            (
                "time_to_live".to_string(),
                self.header.time_to_live.to_string(),
            ),
            (
                "header_checksum".to_string(),
                self.header.header_checksum.to_string(),
            ),
            (
                "source_address".to_string(),
                self.header.source_address.to_string(),
            ),
            (
                "destination_address".to_string(),
                self.header.destination_address.to_string(),
            ),
            (
                "next_header".to_string(),
                format!("protocol : {}", self.header.next_header.protocol_name,),
            ),
            (
                "flags".to_string(),
                format!(
                    "reserved : {}, dont fragment : {},  more fragment : {}",
                    self.header.flags.reserved,
                    self.header.flags.dontfrag,
                    self.header.flags.morefrag
                ),
            ),
            ("malformed".to_string(), self.header.malformed.to_string()),
            ("options".to_string(), options_string),
        ])
    }

    fn get_next(&self) -> &Option<Box<dyn Layer>> {
        &self.payload
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
            "malformed {}, flags: MoreFrag: {} DontFrag: {} Reserved: {}",
            self.header.malformed,
            self.header.flags.morefrag,
            self.header.flags.dontfrag,
            self.header.flags.reserved
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
        IpNextHeaderProtocols::Ipv4 => "IPv4".to_string(),
        IpNextHeaderProtocols::Tcp => "Tcp".to_string(),
        IpNextHeaderProtocols::Udp => "Udp".to_string(),
        IpNextHeaderProtocols::Ipv6 => "IPv6".to_string(),
        _ => "Unknown".to_string(),
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

fn parse_tcp(payload: &[u8]) -> TcpPacket {
    let mut packet = TcpPacket::default();
    packet.deserialize(payload);
    packet
}

fn parse_udp(payload: &[u8]) -> UdpPacket {
    let mut packet = UdpPacket::default();
    packet.deserialize(payload);
    packet
}

#[derive(Debug, Clone, Default)]
pub enum ExtendedNextHeader {
    Known(IpNextHeaderProtocol),
    #[default]
    Malformed,
}
