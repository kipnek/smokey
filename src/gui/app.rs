use crate::packets::shared_objs::Description;
use crate::packets::traits::Describable;
use crate::sniffer::LiveCapture;

use iced::widget::{self, button, row, scrollable, Text};
use iced::{
    executor, time, Alignment, Application, Command, Element, Length, Renderer, Subscription, Theme,
};

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
        (app, iced::Command::perform(async {}, |()| Message::Tick))
    }

    fn title(&self) -> String {
        "cnote".to_owned()
    }

    fn update(&mut self, message: Self::Message) -> Command<Self::Message> {
        match message {
            Message::Tick => {
                if let Some(receiver) = self.receiver.as_mut() {
                    self.captured_packets.extend(receiver.try_iter());
                }
            }
            Message::Start => self.capture(),
            Message::Stop => self.stop(),
            Message::NextPage => {
                //if let Ok(lock) = self.captured_packets.lock(){
                if (self.page + 1) * 1000 < self.captured_packets.len() {
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
        let page_button = |text, enable_press, message| {
            let button = button(text);
            if enable_press {
                button.on_press(message)
            } else {
                button
            }
        };

        let mut column = widget::column!(
            button("Start").on_press(Message::Start),
            button("Stop").on_press(Message::Stop),
            page_button("Previous", self.page != 0, Message::PreviousPage),
            page_button(
                "Next",
                (self.page + 1) * 1000 < self.captured_packets.len(),
                Message::NextPage
            ),
        )
        .spacing(10);

        if let Some(data) = self.captured_packets.chunks(1000).nth(self.page) {
            let column_children = { data.iter() }
                .map(|frame| frame.get_description().view())
                .collect();
            let content = widget::column(column_children).padding(13).spacing(5);
            column = column.push(scrollable(content).height(Length::Fill).width(Length::Fill));
        }

        if let Some(frame) = { self.selected }.and_then(|selected_id| {
            { self.captured_packets.iter() }.find(|frame| frame.get_id() == selected_id)
        }) {
            let text = Text::new(frame.get_long());
            let content = widget::column!(text).padding(13).spacing(5);
            column = column.push(scrollable(content).height(Length::Fill));
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
            Text::new(&self.id_string).width(Length::FillPortion(90)),
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
//this is just boilerplate for the cache
use iced::{Cache, Column, Text};

let mut cache = Cache::new();

let ui = cache.draw(|| {
    Column::new().push(Text::new("This layout is cached!"))
});
 */
