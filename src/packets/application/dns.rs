use crate::packets::{packet_traits::AppLayer, shared_objs::Protocol};
use core::fmt;
use trust_dns_proto::{
    error::ProtoError,
    op::{op_code, Header, Message, MessageParts, MessageType, Query},
    rr::Record,
    serialize::binary::BinDecodable,
};

#[derive(Debug, Clone)]
pub struct DnsMessage {
    pub header: Header,
    pub questions: Vec<Query>,
    pub answers: Vec<Record>,
}

impl DnsMessage {
    pub fn new(bytes: &[u8]) -> Result<DnsMessage, ProtoError> {
        match DnsMessage::from_bytes(bytes) {
            Ok(dns_message) => {
                let dns_message = MessageParts::from(dns_message);
                Ok(DnsMessage {
                    header: dns_message.header,
                    questions: dns_message.queries,
                    answers: dns_message.answers,
                })
            }
            Err(e) => Err(e),
        }
    }
}

impl DnsMessage {
    pub fn from_bytes(bytes: &[u8]) -> Result<Message, ProtoError> {
        match parse_dns_message(bytes) {
            Ok(message) => Ok(message),
            Err(e) => Err(e),
        }
    }
}

fn parse_dns_message(data: &[u8]) -> Result<Message, trust_dns_proto::error::ProtoError> {
    let dns_message = Message::from_bytes(data)?;
    Ok(dns_message)
}

impl AppLayer for DnsMessage {
    fn get_summary(&self) -> String {
        format!("")
    }

    fn protocol(&self) -> Protocol {
        Protocol::DNS
    }

    fn info(&self) -> String {
        format!("dns")
    }

    fn payload(&self) -> Vec<u8> {
        vec![]
    }
}

struct DnsMessageType(MessageType);

impl fmt::Display for DnsMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            MessageType::Query => write!(f, "query"),
            MessageType::Response => write!(f, "response"),
        }
    }
}

struct DnsOpCode(op_code::OpCode);

impl fmt::Display for DnsOpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            op_code::OpCode::Query => write!(f, "query"),
            op_code::OpCode::Status => write!(f, "status"),
            op_code::OpCode::Notify => write!(f, "notify"),
            op_code::OpCode::Update => write!(f, "update"),
        }
    }
}
