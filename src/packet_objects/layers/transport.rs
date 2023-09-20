use crate::packet_objects::headers::tcp::TcpHeader;
use crate::packet_objects::headers::udp::UdpHeader;

#[derive(Debug, Clone)]
pub enum TransportLayer {
    TransportControlProtocol(TcpHeader),
    UserDatagramProtocol(UdpHeader),
}
