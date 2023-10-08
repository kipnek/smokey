use crate::packet_objects::headers::data_headers::http::HttpHeader;

#[derive(Debug, Clone)]
pub enum ApplicationLayer {
    Http(HttpHeader),
}
