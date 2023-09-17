use crate::packet_objects::headers::http::HttpHeader;

pub enum ApplicationLayer {
    Http(HttpHeader),
    Empty
}
