pub trait Processable<'a, T> {
    fn process(&self) -> T;
}

//cant add this in processable since the base packet
pub trait Parsable<T> {
    fn parse(&self) -> T;
}
pub trait NextHeaderTrait {
    fn payload(&self) -> &[u8];
    fn next_header(&self) -> u16;
}
