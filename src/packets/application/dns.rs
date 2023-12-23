use std::borrow::Cow;

use crate::packets::packet_traits::AppLayer;
use trust_dns_proto::op::{Header, Message, MessageParts, Query};
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

/*impl AppLayer for DnsMessage {
    fn get_summary(&self) -> String {
        todo!()
    }

    fn info(&self) -> String {
        format!()
    }

    fn protocol(&self) -> Cow<'_, str> {
        Cow::from("dns")
    }
}*/
