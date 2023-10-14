use std::collections::HashMap;

pub trait Layer : Send{
    fn deserialize(&mut self, packet: &[u8]);

    fn get_summary(&self) -> HashMap<String, String>;
}

