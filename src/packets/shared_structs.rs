#[derive(Debug, Clone, Default)]
pub struct FieldType {
    pub field_name: String,
    pub num: u16,
}

#[derive(Debug, Clone, Default)]
pub struct Summary {
    pub protocol: String,
    pub source: String,
    pub destination: String,
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