use crate::packet_objects::headers::internet_headers::ip::{Ipv4Header, Ipv6Header};

#[derive(Debug, Clone)]
pub enum InternetLayer {
    IPv4(Ipv4Header),
    IPv6(Ipv6Header),
    Unknown,
}


