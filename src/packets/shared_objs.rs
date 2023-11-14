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
pub enum Application {}
// enum Physical {}

#[derive(Debug)]
pub enum Network {
    IPv4(Ipv4Packet),
    // IPv6(Ipv6Packet),
    Other(Box<[u8]>),
}

pub enum LayerData<'a> {
    Layer(&'a dyn Layer),
    Data(&'a [u8]),
}
