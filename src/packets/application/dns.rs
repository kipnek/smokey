use core::fmt;
use std::borrow::Cow;

use crate::packets::packet_traits::AppLayer;
use crate::packets::shared_objs::Protocol;
use trust_dns_proto::op::{op_code, Header, Message, MessageParts, MessageType, Query};
use trust_dns_proto::rr::Record;
use trust_dns_proto::serialize::binary::BinDecodable;

#[derive(Debug, Clone)]
pub struct DnsMessage {
    pub header: Header,
    pub questions: Vec<Query>,
    pub answers: Vec<Record>,
}

impl DnsMessage {
    pub fn new(dns_message: Message) -> DnsMessage {
        let dns_message = MessageParts::from(dns_message);
        DnsMessage {
            header: dns_message.header,
            questions: dns_message.queries,
            answers: dns_message.answers,
        }
    }
}

impl DnsMessage {
    pub fn from_bytes(bytes: &[u8]) -> Result<DnsMessage, String> {
        match parse_dns_message(&bytes) {
            Ok(message) => Ok(DnsMessage::new(message)),
            Err(e) => Err(e.to_string()),
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
}

struct MyMessageType(MessageType);

impl fmt::Display for MyMessageType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            MessageType::Query => write!(f, "query"),
            MessageType::Response => write!(f, "response"),
        }
    }
}

struct MyOpCode(op_code::OpCode);

impl fmt::Display for MyOpCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            op_code::OpCode::Query => write!(f, "query"),
            op_code::OpCode::Status => write!(f, "status"),
            op_code::OpCode::Notify => write!(f, "notify"),
            op_code::OpCode::Update => write!(f, "update"),
        }
    }
}
