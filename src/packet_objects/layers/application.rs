use crate::packet_objects::headers::application_headers::http::HttpHeader;

pub enum ApplicationLayer {
    Http(HttpHeader),
}
