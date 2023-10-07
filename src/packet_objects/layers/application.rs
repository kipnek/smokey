use crate::packet_objects::headers::application_headers::http::HttpHeader;

#[derive(Debug, Clone)]
pub enum ApplicationLayer {
    Http(HttpHeader),
}
