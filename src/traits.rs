use std::collections::HashMap;
use std::fmt::Debug;

pub trait Layer: Send + Debug {
    fn deserialize(&mut self, packet: &[u8]);

    fn get_summary(&self) -> HashMap<String, String>;

    fn get_next(&self) -> &Option<Box<dyn Layer>>;
}
