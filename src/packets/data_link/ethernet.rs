use crate::packets::{
    internet::ip::Ipv4Packet,
    shared_objs::{Description, LayerData, Network},
    traits::{Describable, Layer},
};
use chrono::Utc;
use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket};
use pnet::packet::Packet;
use std::fmt::{Display, Write};

#[derive(Clone, Debug)]
pub struct EthernetHeader {
    pub source_mac: String,
    pub destination_mac: String,
    pub ether_type: EtherType,
}

#[derive(Debug)]
pub struct EthernetFrame {
    pub id: i32,
    pub timestamp: String,
    pub header: EthernetHeader,
    pub payload: Network,
}

impl EthernetFrame {
    pub fn new(id: i32, packet: &pcap::Packet) -> Option<Self> {
        let packet = EthernetPacket::new(packet.data)?;

        let header = EthernetHeader {
            source_mac: packet.get_source().to_string(),
            destination_mac: packet.get_destination().to_string(),
            ether_type: packet.get_ethertype(),
        };

        let payload = match header.ether_type {
            EtherTypes::Ipv4 => Ipv4Packet::new(packet.payload()).map(|x| Network::IPv4(x)),
            // EtherTypes::Ipv6 => Ipv6Packet::new(packet.payload()).map(|x| Box::new(x) as _),
            _ => None,
        };
        let payload = payload.unwrap_or_else(|| Network::Other(packet.payload().to_vec()));

        Some(EthernetFrame {
            id,
            timestamp: Utc::now().to_string(),
            header,
            payload,
        })
    }
}

//trait impls
impl Layer for EthernetFrame {
    fn append_summary(&self, target: &mut String) {
        let _ = write!(
            target,
            "protocol: ethernet
Source Mac: {}
Destination Mac: {}
EtherType: {}",
            self.header.source_mac, self.header.destination_mac, self.header.ether_type,
        );
    }

    fn get_next(&self) -> LayerData {
        match &self.payload {
            Network::IPv4(x) => LayerData::Layer(x as _),
            Network::Other(x) => LayerData::Data(x),
        }
    }

    fn source(&self) -> &dyn Display {
        &self.header.source_mac
    }

    fn destination(&self) -> &dyn Display {
        &self.header.destination_mac
    }

    fn info(&self) -> String {
        format!("next header {}", self.header.ether_type)
    }
}

impl Describable for EthernetFrame {
    fn get_long(&self) -> String {
        let mut ret = String::new();
        self.append_summary(&mut ret);

        while let LayerData::Layer(layer) = self.get_next() {
            ret.push_str("\n\n");
            layer.append_summary(&mut ret);
        }

        ret
    }

    fn get_id(&self) -> i32 {
        self.id
    }

    fn get_description(&self) -> Description<'_> {
        let next_else_self: &dyn Layer = match self.get_next() {
            LayerData::Layer(x) => x,
            _ => self as _,
        };

        let innermost_layer: &dyn Layer = get_innermost_layer(self);

        Description {
            id: self.id,
            timestamp: &self.timestamp,
            src_dest_layer: next_else_self,
            info_layer: innermost_layer,
        }
    }
}

// helper functions

fn get_innermost_layer(mut layer: &dyn Layer) -> &dyn Layer {
    while let LayerData::Layer(next) = layer.get_next() {
        layer = next;
    }
    layer
}
