use std::sync::{Arc, Mutex};
use std::sync::atomic::AtomicBool;
use tokio;
use std::time::Duration;
use crossbeam::channel::Receiver;
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
    FrameSelected(i32),
    //DataReceived(Vec<Box<dyn Describable>>)
    NoOp
}

impl Application for LiveCapture {
    type Executor = executor::Default;
    type Message = Message;
    type Theme = Theme;
    type Flags = ();

    fn new(_flags: Self::Flags) -> (Self, iced::Command<Self::Message>) {
        let app = LiveCapture::default();
        (app, iced::Command::perform(async {}, |_| Message::Tick))
    }

    fn title(&self) -> String {
        "cnote".to_string()
    }

    fn update(&mut self, message: Self::Message) -> Command<Self::Message> {
        match message {
            Message::Tick => {
                tokio::spawn(fetch_data_from_channel(self.channel.1.clone(), self.captured_packets.clone()));
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
            Message::FrameSelected(frame_id) => {
                self.selected = Some(frame_id);
            },
            Message::NoOp =>{}
        };
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
                let scroll = scrollable(data.iter().fold(
                    Column::new().padding(13).spacing(5),
                    |scroll_adapters, frame| {
                        let short = frame.get_description();
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
        time::every(Duration::from_millis(1000)).map(|_| Message::NoOp)
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

fn append_describables(main_vector: &mut Vec<Vec<Box<dyn Describable>>>, describables: Vec<Box<dyn Describable>>) {
    if main_vector.is_empty() || main_vector.last().unwrap().len() == 1000 {
        main_vector.push(Vec::with_capacity(1000));
    }

    let last_vector = main_vector.last_mut().unwrap();

    let available_space = 1000 - last_vector.len();
    let items_to_append = std::cmp::min(describables.len(), available_space);

    let mut iter = describables.into_iter();
    for item in iter.by_ref().take(items_to_append) {
        last_vector.push(item);
    }

    let leftover_describables: Vec<_> = iter.collect();

    if !leftover_describables.is_empty() {
        append_describables(main_vector, leftover_describables);
    }
}

async fn fetch_data_from_channel(receiver: Receiver<Box<dyn Describable>>, packets: Arc<Mutex<Vec<Vec<Box<dyn Describable>>>>>) {
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let mut batch = Vec::with_capacity(100);
        for _ in 0..100 {
            match receiver.try_recv() {
                Ok(data) => batch.push(data),
                Err(_) => break,  // Exit the loop if there's no more data in the channel
            }
        }
        if let Ok(mut lock) = packets.lock() {
            append_describables(&mut lock, batch);
        }
    }
}



/*
//this is just boilerplate for the cache
use iced::{Cache, Column, Text};

let mut cache = Cache::new();

let ui = cache.draw(|| {
    Column::new().push(Text::new("This layout is cached!"))
});

 */