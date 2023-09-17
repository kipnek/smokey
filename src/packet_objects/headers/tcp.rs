use crate::traits::Processable;
use pnet::packet::{tcp, Packet};

#[derive(Debug, Clone)]
pub struct TcpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub data_offset_reserved_flags: u8,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub flags: Flags,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Flags {
    urg: bool,
    ack: bool,
    psh: bool,
    rst: bool,
    syn: bool,
    fin: bool,
}
impl<'a> Processable<'a, TcpHeader> for tcp::TcpPacket<'a> {
    fn process(&self) -> TcpHeader {
        let source_port = self.get_source();
        let destination_port = self.get_destination();
        let sequence_number = self.get_sequence();
        let acknowledgment_number = self.get_acknowledgement();
        let data_offset_reserved_flags = self.get_data_offset();
        let window_size = self.get_window();
        let checksum = self.get_checksum();
        let urgent_pointer = self.get_urgent_ptr();
        let flags = TcpHeader::process_flags(self.get_flags().try_into().unwrap());
        let payload = self.payload().to_vec();

        TcpHeader {
            source_port,
            destination_port,
            sequence_number,
            acknowledgment_number,
            data_offset_reserved_flags,
            window_size,
            checksum,
            urgent_pointer,
            flags,
            payload,
        }
    }
}

impl TcpHeader {
    pub fn process_flags(flags_byte: u8) -> Flags {
        // Extract individual flag values using bitwise operations
        let urg = (flags_byte & 0b100000) != 0;
        let ack = (flags_byte & 0b010000) != 0;
        let psh = (flags_byte & 0b001000) != 0;
        let rst = (flags_byte & 0b000100) != 0;
        let syn = (flags_byte & 0b000010) != 0;
        let fin = (flags_byte & 0b000001) != 0;
        Flags {
            urg,
            ack,
            psh,
            rst,
            syn,
            fin,
        }
    }
}
