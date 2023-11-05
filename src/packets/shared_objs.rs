use pcap::ConnectionStatus;
use std::net::IpAddr;

#[derive(Debug, Clone, Default)]
pub struct Description {
    pub id: i32,
    pub id_string: String,
    pub timestamp: String,
    pub source: String,
    pub destination: String,
    pub info: String,
}

/*
       Device{
           name: "".to_string(),
           desc: None,
           addresses: vec![],
           flags: DeviceFlags { if_flags: IfFlags {
               bits: 0,
           }, connection_status: ConnectionStatus::Unknown },
       };
*/
