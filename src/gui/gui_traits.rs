use egui::Ui;

pub trait View<T> {
    fn ui(&mut self, ui: &mut Ui, data: &mut T);
}
