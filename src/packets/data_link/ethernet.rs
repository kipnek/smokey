use crate::packets::packet_traits::{Describable, Layer};
use crate::packets::shared_objs::Protocol;
use crate::packets::{
    internet::ip::Ipv4Packet,
    shared_objs::{LayerData, Network},
};
use chrono::Utc;
use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket};
use pnet::packet::Packet;
use std::borrow::Cow;
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct EthernetHeader {
    pub source_mac: Box<str>,
    pub destination_mac: Box<str>,
    pub ether_type: EtherType,
}

#[derive(Debug)]
pub struct EthernetFrame {
    pub id: i32,
    pub timestamp: Box<str>,
    pub header: EthernetHeader,
    pub payload: Network,
}

impl EthernetFrame {
    pub fn new(id: i32, packet: &pcap::Packet) -> Option<Self> {
        let packet = EthernetPacket::new(packet.data)?;

        let header = EthernetHeader {
            source_mac: packet.get_source().to_string().into_boxed_str(),
            destination_mac: packet.get_destination().to_string().into_boxed_str(),
            ether_type: packet.get_ethertype(),
        };

        let payload = match header.ether_type {
            EtherTypes::Ipv4 => Ipv4Packet::new(packet.payload()).map(Network::IPv4),
            // EtherTypes::Ipv6 => Ipv6Packet::new(packet.payload()).map(|x| Box::new(x) as _),
            _ => None,
        }
        .unwrap_or_else(|| Network::Other(packet.payload().to_vec().into_boxed_slice()));

        Some(EthernetFrame {
            id,
            timestamp: Utc::now().to_string().into_boxed_str(),
            header,
            payload,
        })
    }
}

//trait impls
impl Layer for EthernetFrame {
    fn get_summary(&self) -> String {
        format!(
            "Source Mac: {}
Destination Mac: {}
EtherType: {}",
            self.header.source_mac, self.header.destination_mac, self.header.ether_type,
        )
    }

    fn get_next(&self) -> LayerData {
        match &self.payload {
            Network::IPv4(x) => LayerData::Layer(x as _),
            Network::Other(x) => LayerData::Data(x),
        }
    }

    fn protocol(&self) -> Protocol {
        Protocol::Ethernet
    }

    fn source(&self) -> Cow<'_, str> {
        Cow::from(self.header.source_mac.to_string())
    }

    fn destination(&self) -> Cow<'_, str> {
        Cow::from(self.header.source_mac.to_string())
    }

    fn info(&self) -> String {
        format!("next header {}", self.header.ether_type)
    }
}

impl Describable for EthernetFrame {
    fn get_long(&self) -> BTreeMap<Protocol, String> {
        let mut map = BTreeMap::new();
        map.insert(self.protocol(), self.get_summary());
        let mut layer_data = self.get_next();
        while let LayerData::Layer(layer) = layer_data {
            map.insert(layer.protocol(), layer.get_summary());
            layer_data = layer.get_next();
        }
        match layer_data {
            LayerData::Layer(_) => {}
            LayerData::Application(app) => {
                map.insert(app.protocol(), app.get_summary());
            }
            LayerData::Data(_) => {}
        }
        map
    }

    fn get_id(&self) -> i32 {
        self.id
    }

    fn flatten(&self) -> Vec<LayerData<'_>> {
        let mut retvec = vec![];
        let mut layer = Some(self as &'_ dyn Layer);

        while let Some(current_layer) = layer {
            // Add the current layer to the result vector
            retvec.push(LayerData::Layer(current_layer));

            // Determine the next layer
            layer = match current_layer.get_next() {
                LayerData::Layer(l) => Some(l),
                LayerData::Application(a) => {
                    retvec.push(LayerData::Application(a));
                    None
                }
                _ => None,
            };
        }

        retvec
    }
}

/*
// helper function
fn get_innermost_layer<'a>(mut layer: LayerData<'a>) -> LayerData<'a> {
    let mut last_layer: Option<&'a dyn Layer> = None;

    while let LayerData::Layer(current_layer) = layer {
        last_layer = Some(current_layer);
        layer = current_layer.get_next();
    }

    match layer {
        LayerData::Data(_) => {
            if let Some(last) = last_layer {
                LayerData::Layer(last)
            } else {
                LayerData::Data(&[])
            }
        }
        _ => layer,
    }
}
*/
