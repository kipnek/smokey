use std::borrow::Cow;

#[derive(Debug, Clone, Default)]
pub struct ProtocolDescriptor<T> {
    pub protocol_name: String,
    pub protocol_type: T,
}

#[derive(Debug)]
pub struct Summary {
    pub protocol: ProtocolType,
    pub source: String,
    pub destination: String,
    pub info: String,
}

#[derive(Debug)]
pub struct Description<'a> {
    pub id: i32,
    pub timestamp: Cow<'a, str>,
    pub protocol: ProtocolType,
    pub source: Cow<'a, str>,
    pub destination: Cow<'a, str>,
    pub info: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProtocolType {
    Ethernet,
    Ipv4,
    Udp,
    Tcp,
    Unknown,
    // ... other protocols
}

#[derive(Default, Clone, Debug)]
pub enum ExtendedType<T> {
    Known(T),
    #[default]
    Malformed,
}
