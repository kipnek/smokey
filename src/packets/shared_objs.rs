use std::fmt;

#[derive(Debug, Clone, Default)]
pub struct ProtocolDescriptor<T> {
    pub protocol_name: &'static str,
    pub protocol_type: T,
}

#[derive(Debug)]
pub struct Summary {
    pub protocol: ProtocolType,
    pub source: String,
    pub destination: String,
    pub info: String,
}

#[derive(Debug, Clone)]
pub struct Description {
    pub id: i32,
    pub id_string: String,
    pub timestamp: String,
    pub protocol: ProtocolType,
    pub source: String,
    pub destination: String,
    pub info: String,
}
impl Default for Description {
    fn default() -> Self {
        Description {
            id: 0,
            id_string: String::new(),
            timestamp: String::new(),
            protocol: ProtocolType::Unknown, // Assuming ProtocolType also implements Default
            source: String::new(),
            destination: String::new(),
            info: String::new(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ProtocolType {
    Ethernet,
    Ipv4,
    Udp,
    Tcp,
    Unknown,
    // ... other protocols
}

impl fmt::Display for ProtocolType {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        fmt.write_str(match self {
            ProtocolType::Tcp => "TCP",
            ProtocolType::Udp => "UDP",
            ProtocolType::Ipv4 => "Ipv4",
            ProtocolType::Ethernet => "Ethernet",
            ProtocolType::Unknown => "Unknown",
        })
    }
}

#[derive(Default, Clone, Debug)]
pub enum ExtendedType<T> {
    Known(T),
    #[default]
    Malformed,
}
