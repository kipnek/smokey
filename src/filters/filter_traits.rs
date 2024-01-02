use crate::packets::shared_objs::LayerData;

pub trait Filter {
    fn passes(&self, flattened: &[LayerData]) -> bool;
}
