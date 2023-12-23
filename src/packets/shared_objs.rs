use std::fmt;
use std::path::Display;

use super::packet_traits::AppLayer;
use crate::packets::application::{
    dns::DnsMessage, http_request::HttpRequest, http_response::HttpResponse, tls::Tls,
};
use crate::packets::data_link::ethernet::EthernetFrame;
use crate::packets::internet::ip::Ipv4Packet;
use crate::packets::packet_traits::Layer;
use crate::packets::transport::tcp::TcpPacket;
use crate::packets::transport::udp::UdpPacket;

#[derive(Debug, Clone)]
pub struct Description<'a> {
    pub id: i32,
    pub timestamp: &'a str,
    pub src_dest_layer: &'a dyn Layer,
    pub info_layer: &'a dyn Layer,
}

pub enum Data {
    Ethernet(EthernetFrame),
    Other(Box<[u8]>),
}

#[derive(Debug)]
pub enum Transport {
    UDP(UdpPacket),
    TCP(TcpPacket),
    Other(Box<[u8]>),
}
#[derive(Debug, Clone)]
pub enum Application {
    HttpRequest(HttpRequest),
    HttpResponse(HttpResponse),
    Dns(DnsMessage),
    Tls(Tls),
    Other(Box<[u8]>),
}
// enum Physical {}

#[derive(Debug)]
pub enum Network {
    IPv4(Ipv4Packet),
    // IPv6(Ipv6Packet),
    Other(Box<[u8]>),
}

pub enum LayerData<'a> {
    Layer(&'a dyn Layer),
    Application(&'a dyn AppLayer),
    Data(&'a [u8]),
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Protocol {
    Ethernet,
    IPv4,
    IPv6,
    TCP,
    UDP,
    DNS,
    HTTP,
    TLS,
}
impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Ethernet => write!(f, "Ethernet"),
            Protocol::IPv4 => write!(f, "IPv4"),
            Protocol::IPv6 => write!(f, "IPv6"),
            Protocol::TCP => write!(f, "Tcp"),
            Protocol::UDP => write!(f, "Udp"),
            Protocol::DNS => write!(f, "Dns"),
            Protocol::HTTP => write!(f, "Http"),
            Protocol::TLS => write!(f, "Tls"),
        }
    }
}
