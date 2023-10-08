use pnet::packet::{icmp, Packet};
use crate::traits::Processable;

#[derive(Debug, Clone)]
pub struct IcmpHeader {
    pub icmp_type : u8,
    pub icmp_code : u8,
    pub checksum : u16,
    pub payload : Vec<u8>,
}

impl<'a> Processable<'a, IcmpHeader> for icmp::IcmpPacket<'a> {
    fn process(&self) -> IcmpHeader {
        IcmpHeader{
            icmp_type : self.get_icmp_type().0,
            icmp_code : self.get_icmp_code().0,
            checksum : self.get_checksum(),
            payload : self.payload().into(),
        }
    }
}