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
    pub malformed: bool,
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
        TcpHeader {
            source_port: self.get_source(),
            destination_port: self.get_destination(),
            sequence_number: self.get_sequence(),
            acknowledgment_number: self.get_acknowledgement(),
            data_offset_reserved_flags: self.get_data_offset(),
            window_size: self.get_window(),
            checksum: self.get_checksum(),
            urgent_pointer: self.get_urgent_ptr(),
            flags: TcpHeader::process_flags(self.get_flags()),
            payload: self.payload().to_vec(),
            malformed: false,
        }
    }
}

impl TcpHeader {
    pub fn process_flags(flags_byte: u8) -> Flags {
        // Extract individual flag values using bitwise operations
        Flags {
            urg: (flags_byte & 0b100000) != 0,
            ack: (flags_byte & 0b010000) != 0,
            psh: (flags_byte & 0b001000) != 0,
            rst: (flags_byte & 0b000100) != 0,
            syn: (flags_byte & 0b000010) != 0,
            fin: (flags_byte & 0b000001) != 0,
        }
    }
    pub fn deformed_packet(payload: Vec<u8>) -> Self {
        TcpHeader {
            source_port: 0,
            destination_port: 0,
            sequence_number: 0,
            acknowledgment_number: 0,
            data_offset_reserved_flags: 0,
            window_size: 0,
            checksum: 0,
            urgent_pointer: 0,
            flags: Flags {
                urg: false,
                ack: false,
                psh: false,
                rst: false,
                syn: false,
                fin: false,
            },
            payload,
            malformed: true,
        }
    }
}
