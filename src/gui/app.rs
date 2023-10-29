use crate::packets::shared_objs::Description;
use crate::packets::traits::Describable;
use crate::sniffer::LiveCapture;
use crossbeam::channel::Receiver;

use iced::widget::{self, button, row, scrollable, Button, Column, Scrollable, Text};
use iced::{
    executor, time, Alignment, Application, Command, Element, Length, Renderer, Subscription, Theme,
};

use iced::widget::scrollable::Direction;
use std::time::Duration;

#[derive(Debug, Clone)]
pub enum Message {
    Tick,
    Start,
    Stop,
    NextPage,
    PreviousPage,
    FrameSelected(i32),
    //DataReceived(Vec<Box<dyn Describable>>)
    NoOp,
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
        "cnote".to_owned()
    }

    fn update(&mut self, message: Self::Message) -> Command<Self::Message> {
        match message {
            Message::Tick => {
                fetch_data_from_channel(self.channel.1.clone(), &mut self.captured_packets);
            }
            Message::Start => self.capture(),
            Message::Stop => self.stop(),
            Message::NextPage => {
                //if let Ok(lock) = self.captured_packets.lock(){
                if self.page < self.captured_packets.len() - 1 {
                    self.page += 1;
                }
                //}
            }
            Message::PreviousPage => {
                if self.page > 0 {
                    self.page -= 1;
                }
            }
            Message::FrameSelected(frame_id) => {
                self.selected = Some(frame_id);
            }
            Message::NoOp => {}
        };
        Command::none()
    }

    fn view(&self) -> Element<'_, Self::Message, Renderer<Self::Theme>> {
        let mut column = Column::new()
            .spacing(10)
            .push(button("start").on_press(Message::Start))
            .push(button("stop").on_press(Message::Stop));

        // Lock once here
        column = column.push({
            let prev_disabled = self.page == 0;

            let button = Button::new(Text::new("Previous"));
            if !prev_disabled {
                button.on_press(Message::PreviousPage)
            } else {
                button
            }
        });

        column = column.push({
            let next_disabled = self.page + 1 >= self.captured_packets.len();

            let button = Button::new(Text::new("Next"));
            if !next_disabled {
                button.on_press(Message::NextPage)
            } else {
                button
            }
        });

        if let Some(data) = self.captured_packets.get(self.page) {
            /*for item in data.iter() {
                column = column.push(Text::new(item.get_short().info));
            }*/
            let scroll_children = { data.iter() }
                .map(|frame| frame.get_description().view())
                .collect();

            let scroll = scrollable(widget::column(scroll_children).padding(13).spacing(5))
                .height(Length::Fill)
                .width(Length::Fill);

            column = column.push(scroll);
        }

        if let Some(frame) = { self.selected }
            .and_then(|selected_id| get_describable(&self.captured_packets, selected_id))
        {
            let children = { frame.get_long().iter().flatten() }
                .map(|(key, value)| Text::new(format!("{}: {}", key, value)).into())
                .collect();
            let scroll = scrollable(Column::with_children(children).padding(13).spacing(5))
                .height(Length::Fill);
            column = column.push(scroll);
        }

        column.into()
    }

    /*fn theme(&self) -> Self::Theme {

    }

    fn style(&self) -> <Self::Theme as StyleSheet>::Style {

    }*/

    fn subscription(&self) -> Subscription<Self::Message> {
        time::every(Duration::from_millis(1500)).map(|_| Message::Tick)
    }
}

impl Description {
    pub fn view(&self) -> Element<Message> {
        row![
            Text::new(self.id.to_string()).width(Length::FillPortion(90)),
            Text::new(&self.timestamp).width(Length::FillPortion(250)),
            Text::new(&self.source).width(Length::FillPortion(230)),
            Text::new(&self.destination).width(Length::FillPortion(230)),
            Text::new(&self.info).width(Length::FillPortion(250)),
            button(Text::new("Details")).on_press(Message::FrameSelected(self.id))
        ]
        .align_items(Alignment::Start)
        .width(Length::Fill)
        .height(50.00)
        .into()
    }
}
/*

helper functions

 */

fn flatten_descriptions(descriptions: Vec<&Description>) -> Vec<String> {
    { descriptions.into_iter() }
        .flat_map(|desc| {
            [
                desc.id.to_string(),
                desc.timestamp.clone(),
                desc.protocol.to_string(),
                desc.source.clone(),
                desc.destination.clone(),
                desc.info.clone(),
            ]
        })
        .collect()
}

fn get_describable(
    vectors: &[Vec<Box<dyn Describable>>],
    id_to_find: i32,
) -> Option<&dyn Describable> {
    vectors
        .iter()
        .flatten()
        .find_map(|frame| (frame.get_id() == id_to_find).then_some(&**frame))
}

fn append_describables(
    main_vector: &mut Vec<Vec<Box<dyn Describable>>>,
    describables: Vec<Box<dyn Describable>>,
) {
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

fn fetch_data_from_channel(
    receiver: Receiver<Box<dyn Describable>>,
    packets: &mut Vec<Vec<Box<dyn Describable>>>,
) {
    if packets.is_empty() || packets.last().unwrap().len() == 1000 {
        packets.push(Vec::with_capacity(1000));
    }

    let last_vector = packets.last_mut().unwrap();
    let limit = 100.min(1000 - last_vector.len());
    last_vector.extend(receiver.try_iter().take(limit));
}

/*
async fn fetch_data_from_channel(receiver: Receiver<Box<dyn Describable>>, packets: Arc<Mutex<Vec<Vec<Box<dyn Describable>>>>>) {
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let mut batch = Vec::with_capacity(100);
        for _ in 0..100 {
            match receiver.try_recv() {
                Ok(data) => batch.push(data),
                Err(_) => break,
            }
        }
        if let Ok(mut lock) = packets.lock() {
            append_describables(&mut lock, batch);
        }
    }
}
*/

/*
//this is just boilerplate for the cache
use iced::{Cache, Column, Text};

let mut cache = Cache::new();

let ui = cache.draw(|| {
    Column::new().push(Text::new("This layout is cached!"))
});

 */
