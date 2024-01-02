use crate::packets::shared_objs::LayerData;

#[allow(clippy::ptr_arg)]
pub trait Filter {
    fn passes(&self, flattened: &Vec<LayerData>) -> bool;
}
