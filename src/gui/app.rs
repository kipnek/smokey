use crate::packets::shared_objs::Description;
use crate::packets::traits::Describable;
use crate::sniffer::LiveCapture;
use crossbeam::channel::Receiver;
use std::fmt;
use std::fmt::Debug;

use iced::widget::scrollable::Direction;
use iced::widget::{
    self, button, container, row, scrollable, text, Button, Column, Scrollable, Text,
};
use iced::{
    executor, time, Alignment, Application, Command, Element, Length, Renderer, Subscription, Theme,
};
use iced_table::{table, Table};
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
                if let Some(receiver) = self.receiver.as_mut() {
                    fetch_data_from_channel(receiver, &mut self.captured_packets);
                }
            }
            Message::Start => self.capture(),
            Message::Stop => self.stop(),
            Message::NextPage => {
                if self.page < self.captured_packets.len() - 1 {
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
        };
        Command::none()
    }

    fn view(&self) -> Element<'_, Self::Message, Renderer<Self::Theme>> {

        let desc_columns: Vec<DescriptionColumn> = vec![
            DescriptionColumn::new(DescriptionTable::Id),
            DescriptionColumn::new(DescriptionTable::Timestamp),
            DescriptionColumn::new(DescriptionTable::Source),
            DescriptionColumn::new(DescriptionTable::Destination),
            DescriptionColumn::new(DescriptionTable::Info),
            DescriptionColumn::new(DescriptionTable::Details),
        ];

        let mut column = Column::with_children(vec![
            button("Start").on_press(Message::Start).into(),
            button("Stop").on_press(Message::Stop).into(),
            {
                let prev_disabled = self.page == 0;

                let button = Button::new("Previous");
                if !prev_disabled {
                    button.on_press(Message::PreviousPage)
                } else {
                    button
                }
                .into()
            },
            {
                let next_disabled = self.page + 1 >= self.captured_packets.len();

                let button = Button::new("Next");
                if !next_disabled {
                    button.on_press(Message::NextPage)
                } else {
                    button
                }
                .into()
            },
        ])
        .spacing(10);

        if let Some(data) = self.captured_packets.get(self.page) {
            /*for item in data.iter() {
                column = column.push(Text::new(item.get_short().info));
            }*/
            let mut table:Table<'_, DescriptionColumn, Box<dyn Describable>, Message, Renderer> = table(
                self.header.clone(),
                self.body.clone(),
                &desc_columns,
                data.as_slice(),
                Message::SyncHeader,
            );
            /*
            let scroll_children = { data.iter() }
                .map(|frame| frame.get_description().view())
                .collect();

            let scroll = scrollable(widget::column(scroll_children).padding(13).spacing(5))
                .height(Length::Fill)
                .width(Length::Fill);*/

            column = column.push(table);
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
    { vectors.iter().flatten() }
        .find_map(|frame| (frame.get_id() == id_to_find).then_some(&**frame))
}

fn append_describables(
    main_vector: &mut Vec<Vec<Box<dyn Describable>>>,
    mut describables: Vec<Box<dyn Describable>>,
) {
    if main_vector.is_empty() || main_vector.last().unwrap().len() == 1000 {
        main_vector.push(Vec::with_capacity(1000));
    }

    let last_vector = main_vector.last_mut().unwrap();
    let items_to_append = describables.len().min(1000 - last_vector.len());
    last_vector.extend(describables.drain(0..items_to_append));

    while !describables.is_empty() {
        let mut new_vec = Vec::with_capacity(1000);
        new_vec.extend(describables.drain(0..describables.len().min(1000)));
        main_vector.push(new_vec);
    }
}

fn fetch_data_from_channel(
    receiver: &mut Receiver<Box<dyn Describable>>,
    packets: &mut Vec<Vec<Box<dyn Describable>>>,
) {
    if packets.is_empty() || packets.last().unwrap().len() == 1000 {
        packets.push(Vec::with_capacity(1000));
    }

    let last_vector = packets.last_mut().unwrap();
    let limit = 100.min(1000 - last_vector.len());
    last_vector.extend(receiver.try_iter().take(limit));
}

struct DescriptionColumn {
    field: DescriptionTable,
    width: f32,
    resize_offset: Option<f32>,
}

impl DescriptionColumn {
    fn new(dt: DescriptionTable) -> Self {
        Self {
            field: dt,
            width: 100.0,
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
    type Row = Box<dyn Describable>;

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
