use crate::packet_objects::headers::link_headers::ethernet::EthernetHeader;

#[derive(Debug, Clone)]
pub enum LinkLayer {
    Ethernet(EthernetHeader),
    Unknown,
}


