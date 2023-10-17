use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use crate::sniffer::LiveCapture;
use iced::{Alignment, Application, Command, Element, executor, Length, Renderer, Subscription, Theme, time};
use iced::application::StyleSheet;
use iced::widget::{Button, button, Column, container, row, Scrollable, scrollable, text, Text};
use crate::packets::traits::Describable;

#[derive(Debug, Clone)]
pub enum Message {
    Tick,
    Start,
    Stop,
    NextPage,
    PreviousPage,
    FrameSelected(i32)
}

impl Application for LiveCapture {
    type Executor = executor::Default;
    type Message = Message;
    type Theme = Theme;
    type Flags = ();

    fn new(_flags: Self::Flags) -> (Self, iced::Command<Self::Message>) {
        let app = LiveCapture {
            interfaces: Vec::new(), // or some default interfaces
            page: 0,
            selected: None,
            captured_packets: Arc::new(Mutex::new(vec![vec![]])),
            stop: Arc::new(AtomicBool::new(false)),
        };

        (app, iced::Command::none())
    }

    fn title(&self) -> String {
        "cnote".to_string()
    }

    fn update(&mut self, message: Self::Message) -> Command<Self::Message> {
        match message {
            Message::Tick => {

            },
            Message::Start => {
                self.capture()
            },
            Message::Stop => {
                self.stop()
            },
            Message::NextPage => {
                if let Ok(lock) = self.captured_packets.lock(){
                    if self.page < lock.len() - 1 {
                        self.page += 1;
                    }
                }
            },
            Message::PreviousPage => {
                if self.page > 0 {
                    self.page -= 1;
                }
            },
            Message::FrameSelected(frame_id) =>{
                 self.selected = Some(frame_id);
            },
        }
        Command::none()
    }

    fn view(&self) -> Element<'_, Self::Message, Renderer<Self::Theme>> {
        let mut column = Column::new().spacing(10);
        column = column.push(button("start").on_press(Message::Start));
        column = column.push(button("stop").on_press(Message::Stop));


        // Lock once here
        if let Ok(lock) = self.captured_packets.lock() {
            let prev_disabled = self.page == 0;

            if !prev_disabled {
                column = column.push(
                    Button::new(Text::new("Previous"))
                        .on_press(Message::PreviousPage)
                );
            }else{
                column = column.push(
                    Button::new(Text::new("Previous"))
                );
            }


            let next_disabled = self.page + 1 >= lock.len();
            if !next_disabled {
                column = column.push(
                    Button::new(Text::new("Next"))
                        .on_press(Message::NextPage)
                );
            }else{
                column = column.push(
                    Button::new(Text::new("Next"))
                );
            }
            if let Some(data) = lock.get(self.page) {
                /*for item in data.iter() {
                    column = column.push(Text::new(item.get_short().info));
                }*/
                let scroll = scrollable(data.iter().fold(
                    Column::new().padding(13).spacing(5),
                    |scroll_adapters, frame| {
                        let short =frame.get_short();
                        let description = format!("{} {} {} {} {}", short.id, short.timestamp, short.source,short.destination, short.info);
                        scroll_adapters.push(
                            Button::new(Text::new(description))
                                .padding([5, 5])
                                .width(Length::Fill)
                                .on_press(Message::FrameSelected(frame.get_id())),
                        )
                    },
                )).height(Length::Fill);
                column = column.push(scroll);
            }

            if let Some(selected_id) = self.selected {
                if let Some(frame) = get_describable(&lock, selected_id){
                    let scroll = scrollable(
                        frame.get_long().iter().fold(
                            Column::new().padding(13).spacing(5),
                            |column, map| {
                                map.iter().fold(column, |inner_column, (key, value)| {
                                    // You can format the key and value however you want.
                                    let description = format!("{}: {}", key, value);
                                    inner_column.push(Text::new(description))

                                })
                            },
                        )).height(Length::Fill);
                    column = column.push(scroll);
                }
            }
            /*
            if self.page > 0 {
                column = column.push(Button::new(Text::new("Previous")).on_press(Message::PreviousPage));
            }
            if self.page + 1 < lock.len() {
                column = column.push(Button::new(Text::new("Next")).on_press(Message::NextPage));
            }*/
        } else {
            // Handle the lock error if needed. For instance, you could display an error message:
            // column = column.push(Text::new("Failed to lock captured packets."));
        }

        column.into()
    }


    /*fn theme(&self) -> Self::Theme {

    }

    fn style(&self) -> <Self::Theme as StyleSheet>::Style {

    }*/

    fn subscription(&self) -> Subscription<Self::Message> {
        time::every(Duration::from_millis(300)).map(|_| Message::Tick)
    }
}

fn get_describable(vectors: &[Vec<Box<dyn Describable>>], id_to_find: i32) -> Option<&Box<dyn Describable>> {
    for vector in vectors {
        if let Some(frame) = vector.iter().find(|frame| frame.get_id() == id_to_find) {
            return Some(frame);
        }
    }
    None
}