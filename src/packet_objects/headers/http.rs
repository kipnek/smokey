pub struct HttpHeader {
    pub request: Option<HttpRequest>,
    pub response: Option<HttpResponse>,
}

impl HttpHeader {}

pub struct HttpRequest {
    pub user_agent: String,
    pub host: String,
    pub accept: String,
    pub authorization: String,
    pub cookie: String,
    pub referer: String,
    pub cache_control: String,
    pub connection: String,
    pub security_headers: Option<SecurityHeaders>,
}
pub struct HttpResponse {
    pub content_type: String,
    pub content_length: u64,
    pub location: String,
    pub set_cookie: String,
    pub www_authenticate: String,
    pub date: String,
    pub expires: String,
    pub last_modified: String,
}

pub struct SecurityHeaders {
    pub strict_transport_security: Hsts,
    pub content_security_policy: Csp,
    pub x_content_type: String,
    pub x_frame_options: String,
    pub xss_protection: String,
}

pub struct Hsts {
    pub max_age: u64,
    pub include_subdomains: bool,
    pub preload: bool,
}

pub struct Csp {
    default_src: String,
    script_src: String,
    style_src: String,
    img_src: String,
    connect_src: String,
    font_src: String,
    frame_src: String,
}
