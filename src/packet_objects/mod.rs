pub mod headers;
pub mod layers;
pub mod raw;


trait LinkLayer{
    type Frame;
    fn process_layer(&self, raw: &[u8]) -> Self::Frame;
}

trait InternetLayer{
    fn process_layer(&self, raw: &[u8]) -> Self;
}

// Transport Layer

trait TransportLayer{
    fn process_layer(&self, raw: &[u8]) -> Self;
}

trait ApplicationLayer{
    fn process_layer(&self, raw: &[u8]) -> Self;
}


#[derive(Debug, Clone, Default)]
struct TCPIPPacket<L, I, T, A>
    where
        L: LinkLayer,
        I: InternetLayer,
        T: TransportLayer,
        A: ApplicationLayer,
{
    link: Box<L>,
    internet: Option<Box<I>>,
    transport: Option<Box<T>>,
    application: Option<Box<A>>,
}
