use core::fmt;

#[derive(Debug, Clone)]
pub struct Tls {
    pub version: TlsVersion,
    pub cipher_suite: CipherSuite,
    pub server_certificates: Vec<Certificate>,
    pub client_certificates: Vec<Certificate>,
    pub is_handshake_complete: bool,
}

#[derive(Debug, Clone)]
pub enum TlsVersion {
    Tls1_0,
    Tls1_1,
    Tls1_2,
    Tls1_3,
}

impl fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TlsVersion::Tls1_0 => write!(f, "tls v1.0"),
            TlsVersion::Tls1_1 => write!(f, "tls v1.1"),
            TlsVersion::Tls1_2 => write!(f, "tls v1.2"),
            TlsVersion::Tls1_3 => write!(f, "tls v1.3"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CipherSuite {
    pub name: String,
    pub key_exchange_algorithm: KeyExchangeAlgorithm,
    pub encryption_algorithm: EncryptionAlgorithm,
    pub hash_algorithm: HashAlgorithm,
}

#[derive(Debug, Clone)]
pub struct Certificate {
    pub subject: String,
    pub issuer: String,
    pub validity_period: ValidityPeriod,
    // Other certificate details like public key, signature, etc.
}

#[derive(Debug, Clone)]
pub struct ValidityPeriod {
    pub not_before: String, // or use a date-time
    pub not_after: String,
}

#[derive(Debug, Clone)]
pub enum KeyExchangeAlgorithm {
    Rsa,
    DiffieHellman,
    Ecdh,
    // Others...
}

impl fmt::Display for KeyExchangeAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyExchangeAlgorithm::Rsa => write!(f, "rsa"),
            KeyExchangeAlgorithm::DiffieHellman => write!(f, "diffe-hellman"),
            KeyExchangeAlgorithm::Ecdh => write!(f, "ecdh"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum EncryptionAlgorithm {
    Aes128,
    Aes256,
    Chacha20,
    // Others...
}

impl fmt::Display for EncryptionAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncryptionAlgorithm::Aes128 => write!(f, "aes128"),
            EncryptionAlgorithm::Aes256 => write!(f, "aes256"),
            EncryptionAlgorithm::Chacha20 => write!(f, "Chacha20"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
    // Others...
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashAlgorithm::Sha256 => write!(f, "sha256"),
            HashAlgorithm::Sha384 => write!(f, "sha384"),
            HashAlgorithm::Sha512 => write!(f, "sha512"),
        }
    }
}
