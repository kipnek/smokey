use core::fmt;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: HttpRequestType,
    pub uri: String,
    pub headers: HashMap<String, String>,
    pub body: String,
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status_code: u16,
    pub reason_phrase: String,
    pub headers: HashMap<String, String>,
    pub body: String,
}

#[derive(Debug, Clone)]
pub enum HttpRequestType {
    Head,
    Connect,
    Get,
    Post,
    Put,
    Patch,
    Trace,
}

impl fmt::Display for HttpRequestType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpRequestType::Head => write!(f, "head"),
            HttpRequestType::Connect => write!(f, "connect"),
            HttpRequestType::Get => write!(f, "get"),
            HttpRequestType::Post => write!(f, "post"),
            HttpRequestType::Put => write!(f, "put"),
            HttpRequestType::Patch => write!(f, "patch"),
            HttpRequestType::Trace => write!(f, "trace"),
        }
    }
}
