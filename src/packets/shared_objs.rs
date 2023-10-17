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
pub struct Description {
    pub id: i32,
    pub timestamp: String,
    pub protocol: ProtocolType,
    pub source: String,
    pub destination: String,
    pub info: String,
}
impl Default for Description{
    fn default() -> Self {
        Description {
            id: 0,
            timestamp: String::new(),
            protocol: ProtocolType::Unknown,  // Assuming ProtocolType also implements Default
            source: String::new(),
            destination: String::new(),
            info: String::new(),
        }
    }
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
