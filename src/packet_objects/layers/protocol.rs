use crate::packet_objects::headers::protocol_headers::{tcp::TcpHeader,udp::UdpHeader,icmp::IcmpHeader};


//can encompass things like icmp since the way pnet packet modules are set up
#[derive(Debug, Clone)]
pub enum ProtocolLayer {
    Tcp(TcpHeader),
    Udp(UdpHeader),
    Icmp(IcmpHeader),
    Unknown,
}
