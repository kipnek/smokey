use crate::packets::packet_traits::Layer;
use crate::packets::shared_objs::{LayerData, Transport};
use crate::packets::transport::{tcp::TcpPacket, udp::UdpPacket};
use pnet::packet::Packet;
use pnet::packet::{
    ip::{IpNextHeaderProtocol, IpNextHeaderProtocols},
    ipv4::Ipv4OptionIterable,
};
use std::borrow::Cow;
use std::fmt::{Display, Write};

#[derive(Debug, Clone)]
pub struct Ipv4Header {
    pub version_ihl: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub options: Box<[Ipv4Options]>,
    pub flags_fragment_offset: u16,
    pub time_to_live: u8,
    pub header_checksum: u16,
    pub source_address: Box<str>,
    pub destination_address: Box<str>,
    pub next_header: IpNextHeaderProtocol,
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
    Unknown(Box<str>),
}

impl Ipv4Header {
    pub fn set_flags(number: u8) -> Ipv4Flags {
        Ipv4Flags {
            reserved: (number & 0b100) != 0,
            dontfrag: (number & 0b010) != 0,
            morefrag: (number & 0b001) != 0,
        }
    }

    pub fn set_options(options: Ipv4OptionIterable) -> Box<[Ipv4Options]> {
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
                    _ => Ipv4Options::Unknown(
                        format!("Unknown Option: {:#X}", option.get_number().0).into_boxed_str(),
                    ),
                }
            })
            .collect::<Vec<_>>()
            .into_boxed_slice()
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

#[derive(Debug)]
pub struct Ipv4Packet {
    pub header: Ipv4Header,
    pub payload: Transport,
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
            source_address: packet.get_source().to_string().into_boxed_str(),
            destination_address: packet.get_destination().to_string().into_boxed_str(),
            next_header: packet.get_next_level_protocol(),
            flags: Ipv4Header::set_flags(packet.get_flags()),
        };

        let payload = match header.next_header {
            IpNextHeaderProtocols::Tcp => TcpPacket::new(packet.payload()).map(Transport::TCP),
            IpNextHeaderProtocols::Udp => UdpPacket::new(packet.payload()).map(Transport::UDP),
            _ => None,
        }
        .unwrap_or_else(|| Transport::Other(packet.payload().to_vec().into_boxed_slice()));

        Some(Ipv4Packet { header, payload })
    }
}

impl Layer for Ipv4Packet {
    fn append_summary(&self, target: &mut String) {
        let Ipv4Header {
            version_ihl,
            dscp,
            ecn,
            total_length,
            identification,
            options,
            flags_fragment_offset,
            time_to_live,
            header_checksum,
            source_address,
            destination_address,
            next_header,
            flags:
                Ipv4Flags {
                    reserved,
                    dontfrag,
                    morefrag,
                },
        } = &self.header;

        let options_string = { options.iter() }
            .map(Ipv4Options::description)
            .collect::<Vec<&str>>()
            .join("\n");

        let _ = write!(
            target,
            "protocol: ipv4
version: {version_ihl}
dscp: {dscp}
ecn: {ecn}
total_length: {total_length}
identification: {identification}
flags_fragment_offset: {flags_fragment_offset}
time_to_live: {time_to_live}
header_checksum: {header_checksum}
source_address: {source_address}
destination_address: {destination_address}
next_header: protocol : {next_header}
flags: reserved : {reserved}, dont fragment : {dontfrag},  more fragment : {morefrag}
options: {options_string}"
        );
    }

    fn get_next(&self) -> LayerData {
        match &self.payload {
            Transport::TCP(x) => LayerData::Layer(x as _),
            Transport::UDP(x) => LayerData::Layer(x as _),
            Transport::Other(x) => LayerData::Data(x),
        }
    }

    fn source(&self) -> Cow<'_, str> {
        Cow::from(self.header.source_address.to_string())
    }

    fn destination(&self) -> Cow<'_, str> {
        Cow::from(self.header.destination_address.to_string())
    }

    fn info(&self) -> String {
        format!(
            "flags: MoreFrag: {} DontFrag: {} Reserved: {}",
            self.header.flags.morefrag, self.header.flags.dontfrag, self.header.flags.reserved
        )
    }
}

#[derive(Debug, Clone)]
pub struct Ipv6Header {
    pub payload: Box<[u8]>,
    pub traffic_class: u8,
    pub flow_label: u16,
    pub payload_length: u16,
    //pub next_header: ProtocolDescriptor,
    pub hop_limit: u8,
    pub source: Box<str>,
    pub destination: Box<str>,
    pub version: u8,
}
