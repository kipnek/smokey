use crate::packets::traits::Describable;
use crate::sniffer::LiveCapture;
use std::fmt;

use iced::widget::{self, button, container, scrollable, text, Text};
use iced::{
    executor, time, Application, Command, Element, Length, Renderer, Subscription, Theme,
};
use iced_table::table;

use crate::packets::data_link::ethernet::EthernetFrame;
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
    SyncHeader(scrollable::AbsoluteOffset),
}

pub struct CaptureApp {
    pub header: scrollable::Id,
    pub footer: scrollable::Id,
    pub body: scrollable::Id,
    pub sniffer: LiveCapture,
    pub selected: Option<i32>,
    pub page: usize,
}

impl CaptureApp {
    pub fn new() -> Self {
        Self {
            header: scrollable::Id::unique(),
            footer: scrollable::Id::unique(),
            body: scrollable::Id::unique(),
            sniffer: Default::default(),
            selected: None,
            page: 0,
        }
    }
}

impl Application for CaptureApp {
    type Executor = executor::Default;
    type Message = Message;
    type Theme = Theme;
    type Flags = ();

    fn new(_flags: Self::Flags) -> (Self, iced::Command<Self::Message>) {
        let app = CaptureApp::new();
        (app, iced::Command::perform(async {}, |()| Message::Tick))
    }

    fn title(&self) -> String {
        "cnote".to_owned()
    }

    fn update(&mut self, message: Self::Message) -> Command<Self::Message> {
        match message {
            Message::Tick => {
                if let Some(receiver) = self.sniffer.receiver.as_mut() {
                    self.sniffer.captured_packets.extend(receiver.try_iter());
                }
            }
            Message::Start => self.sniffer.capture(),
            Message::Stop => self.sniffer.stop(),
            Message::NextPage => {
                //if let Ok(lock) = self.captured_packets.lock(){
                if (self.page + 1) * 1000 < self.sniffer.captured_packets.len() {
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
            Message::SyncHeader(offset) => {
                return Command::batch(vec![
                    scrollable::scroll_to(self.header.clone(), offset),
                    scrollable::scroll_to(self.footer.clone(), offset),
                ])
            }
        };
        Command::none()
    }

    fn view(&self) -> Element<'_, Self::Message, Renderer<Self::Theme>> {
        let desc_columns: Vec<DescriptionColumn> = vec![
            DescriptionColumn::new(DescriptionTable::Id, 100.0),
            DescriptionColumn::new(DescriptionTable::Timestamp, 200.0),
            DescriptionColumn::new(DescriptionTable::Source, 200.0),
            DescriptionColumn::new(DescriptionTable::Destination, 200.0),
            DescriptionColumn::new(DescriptionTable::Info, 350.0),
            DescriptionColumn::new(DescriptionTable::Details, 100.0),
        ];

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
                (self.page + 1) * 1000 < self.sniffer.captured_packets.len(),
                Message::NextPage
            ),
        )
        .spacing(10);

        if let Some(data) = self.sniffer.captured_packets.chunks(1000).nth(self.page) {
            let table = iced::widget::responsive(move |size| {
                iced_table::table(
                    self.header.clone(),
                    self.body.clone(),
                    &desc_columns,
                    data,
                    Message::SyncHeader,
                )
                .min_width(size.width)
                .into()
            });
            column = column.push(table)
        }

        if let Some(frame) = { self.selected }.and_then(|selected_id| {
            { self.sniffer.captured_packets.iter() }.find(|frame| frame.get_id() == selected_id)
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

struct DescriptionColumn {
    field: DescriptionTable,
    width: f32,
    resize_offset: Option<f32>,
}

impl DescriptionColumn {
    fn new(dt: DescriptionTable, width: f32) -> Self {
        Self {
            field: dt,
            width,
            resize_offset: None,
        }
    }
}

pub enum DescriptionTable {
    Id,
    Timestamp,
    Source,
    Destination,
    Info,
    Details,
}

impl fmt::Display for DescriptionTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                DescriptionTable::Id => "Id",
                DescriptionTable::Timestamp => "Timestamp",
                DescriptionTable::Source => "Source",
                DescriptionTable::Destination => "Destination",
                DescriptionTable::Info => "Info",
                DescriptionTable::Details => "Details",
            }
        )
    }
}

impl<'a, 'b> table::Column<'a, 'b, Message, Renderer> for DescriptionColumn {
    type Row = EthernetFrame;

    fn header(&'b self, col_index: usize) -> Element<'a, Message, Renderer> {
        container(text(format!("{}", self.field)))
            .height(24)
            .center_y()
            .into()
    }

    fn cell(
        &'b self,
        col_index: usize,
        row_index: usize,
        row: &'b Self::Row,
    ) -> Element<'a, Message, Renderer> {
        let row = row.get_description();
        let cell_content: Element<Message> = match self.field {
            DescriptionTable::Id => text(row.id.to_string()).into(),
            DescriptionTable::Timestamp => text(row.timestamp.to_owned()).into(),
            DescriptionTable::Source => text(row.source.to_owned()).into(),
            DescriptionTable::Destination => text(row.destination.to_owned()).into(),
            DescriptionTable::Info => text(row.info.to_owned()).into(),
            DescriptionTable::Details => button(Text::new("Details"))
                .on_press(Message::FrameSelected(row.id))
                .into(),
        };
        container(cell_content).height(24).center_y().into()
    }

    fn width(&self) -> f32 {
        self.width
    }

    fn resize_offset(&self) -> Option<f32> {
        self.resize_offset
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
