pub trait Processable<'a, T> {
    fn process(&self) -> T;
}
