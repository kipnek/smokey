use crate::packets::traits::Describable;
use crate::sniffer::LiveCapture;
use std::fmt;

use iced::widget::{self, button, container, row, scrollable, text, Column, Text};
use iced::{executor, time, Application, Command, Element, Length, Renderer, Subscription, Theme};
use iced_table::table;

use crate::gui::modal::Modal;
use crate::packets::data_link::ethernet::EthernetFrame;
use std::time::Duration;
use pcap::Device;

#[derive(Debug, Clone)]
pub enum Message {
    Tick,
    Start,
    Stop,
    NextPage,
    PreviousPage,
    FrameSelected(i32),
    DeviceSelected(Device),
    ToggleModal,
    NoOp,
    SyncHeader(scrollable::AbsoluteOffset),
}

pub struct CaptureApp {
    pub header: scrollable::Id,
    pub footer: scrollable::Id,
    pub body: scrollable::Id,
    pub sniffer: LiveCapture,
    pub show_dev_modal: bool,
    pub running: bool,
    pub selected: Option<i32>,
    pub page: usize,
    pub per_page: usize,
}

impl CaptureApp {
    pub fn new() -> Self {
        Self {
            header: scrollable::Id::unique(),
            footer: scrollable::Id::unique(),
            body: scrollable::Id::unique(),
            sniffer: Default::default(),
            running: false,
            show_dev_modal: false,
            selected: None,
            page: 0,
            per_page: 500,
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
            Message::Start => {
                self.running = true;
                self.sniffer.capture();
            }
            Message::Stop => {
                self.running = false;
                self.sniffer.stop();
            }
            Message::NextPage => {
                if (self.page + 1) * self.per_page < self.sniffer.captured_packets.len() {
                    self.page += 1;
                }
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
            Message::DeviceSelected(interface) => {
                self.sniffer.interface = Some(interface);
                self.show_dev_modal = !self.show_dev_modal
            }
            Message::ToggleModal => self.show_dev_modal = !self.show_dev_modal,
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

        let button_row = row![
            page_button("Start", !self.running && self.sniffer.interface.is_some(), Message::Start),
            page_button("Stop", self.running, Message::Stop),
            page_button("Previous", self.page != 0, Message::PreviousPage),
            page_button(
                "Next",
                (self.page + 1) * self.per_page < self.sniffer.captured_packets.len(),
                Message::NextPage
            ),
            page_button("Pick Device", !self.running, Message::ToggleModal),
        ]
        .spacing(25);

        let mut column = widget::column!(button_row).spacing(10);

        if let Some(data) = self
            .sniffer
            .captured_packets
            .chunks(self.per_page)
            .nth(self.page)
        {
            let desc_columns: Vec<DescriptionColumn> = vec![
                DescriptionColumn::new(DescriptionTable::Id, 100.0),
                DescriptionColumn::new(DescriptionTable::Timestamp, 200.0),
                DescriptionColumn::new(DescriptionTable::Source, 200.0),
                DescriptionColumn::new(DescriptionTable::Destination, 200.0),
                DescriptionColumn::new(DescriptionTable::Info, 350.0),
                DescriptionColumn::new(DescriptionTable::Details, 100.0),
            ];
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
        } else {
            let device = if let Some(interface) = &self.sniffer.interface{
                interface.name.clone()
            }else{
              "None".to_string()
            };
            column = column.push(
                row!(
                    text(format!("Selected Device: {:?}", device)),
                )
                    .height(Length::Fill)
                    .width(Length::Fill),
            )
        }

        if let Some(frame) = { self.selected }.and_then(|selected_id| {
            { self.sniffer.captured_packets.iter() }.find(|frame| frame.get_id() == selected_id)
        }) {
            let text = Text::new(frame.get_long());
            let content = widget::column!(text).padding(13).spacing(5);
            column = column.push(scrollable(content).height(Length::Fill).width(Length::Fill));
        }

        if self.show_dev_modal {
            let interfaces = match LiveCapture::get_interfaces() {
                Ok(interfaces) => interfaces,
                Err(_) => vec![], // Handle the error appropriately
            };

            let interface_buttons: Vec<Element<_>> = interfaces
                .iter()
                .map(|interface| {
                    button(Text::new(format!(
                        "{} {:?}",
                        interface.name, interface.addresses
                    )))
                    .on_press(Message::DeviceSelected(interface.clone()))
                    .into()
                })
                .collect();

            // Then create the scrollable content
            let scrollable_content: Element<_> = interface_buttons
                .into_iter()
                .fold(Column::new().spacing(10), |column, button| {
                    column.push(button)
                })
                .into();

            let scrollable_modal = scrollable(scrollable_content)
                .width(Length::Fill)
                .height(Length::Fill);
            let s_container = container(scrollable_modal).width(300).padding(10);
            Modal::new(column, s_container)
                .on_blur(Message::ToggleModal)
                .into()
        } else {
            column.into()
        }
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

    fn header(&'b self, _col_index: usize) -> Element<'a, Message, Renderer> {
        container(text(format!("{}", self.field)))
            .height(24)
            .center_y()
            .into()
    }

    fn cell(
        &'b self,
        _col_index: usize,
        _row_index: usize,
        row: &'b Self::Row,
    ) -> Element<'a, Message, Renderer> {
        let row = row.get_description();
        let cell_content: Element<Message> = match self.field {
            DescriptionTable::Id => text(row.id).into(),
            DescriptionTable::Timestamp => text(row.timestamp).into(),
            DescriptionTable::Source => text(row.src_dest_layer.source()).into(),
            DescriptionTable::Destination => text(row.src_dest_layer.destination()).into(),
            DescriptionTable::Info => text(row.info_layer.info()).into(),
            DescriptionTable::Details => button("Details")
                .on_press(Message::FrameSelected(row.id))
                .into(),
        };
        container(cell_content).height(30).center_y().into()
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
