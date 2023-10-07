use crate::packet_objects::headers::protocol_headers::tcp::TcpHeader;
use crate::packet_objects::headers::protocol_headers::udp::UdpHeader;

#[derive(Debug, Clone)]
pub enum ProtocolLayer {
    Tcp(TcpHeader),
    Udp(UdpHeader),
    Unknown,
}
