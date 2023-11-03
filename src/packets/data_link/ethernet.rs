use crate::packets::{
    internet::ip::Ipv4Packet,
    shared_objs::{Description, ExtendedType, ProtocolDescriptor, ProtocolType},
    traits::{Describable, Layer, SetProtocolDescriptor},
};
use chrono::Utc;
use pnet::packet::ethernet::{EtherType, EtherTypes, EthernetPacket};
use pnet::packet::Packet;
use std::fmt::Write;

/*



Ethernet Header




 */
#[derive(Default, Clone, Debug)]
pub struct EthernetHeader {
    pub source_mac: String,
    pub destination_mac: String,
    pub ether_type: ProtocolDescriptor<ExtendedType<EtherType>>,
}
impl SetProtocolDescriptor<EtherType> for EthernetHeader {
    fn set_proto_descriptor(
        proto: ExtendedType<EtherType>,
    ) -> ProtocolDescriptor<ExtendedType<EtherType>> {
        let protocol_name = match proto {
            ExtendedType::Known(ether_type) => set_name(ether_type),
            ExtendedType::Malformed => "malformed",
        };

        ProtocolDescriptor {
            protocol_name,
            protocol_type: proto,
        }
    }
}

/*



Ethernet Frame



 */

#[derive(Default, Debug)]
pub struct EthernetFrame {
    pub id: i32,
    pub timestamp: String,
    pub header: EthernetHeader,
    pub description: Description,
    pub payload: Option<Box<dyn Layer>>,
}

impl EthernetFrame {
    pub fn new(id: i32, packet: &pcap::Packet) -> Option<Self> {
        let packet = EthernetPacket::new(packet.data)?;

        let header = EthernetHeader {
            source_mac: packet.get_source().to_string(),
            destination_mac: packet.get_destination().to_string(),
            ether_type: EthernetHeader::set_proto_descriptor(ExtendedType::Known(
                packet.get_ethertype(),
            )),
        };

        let payload = match &header.ether_type.protocol_type {
            ExtendedType::Known(EtherTypes::Ipv4) => {
                Ipv4Packet::new(packet.payload()).map(|x| Box::new(x) as _)
            }
            /* ExtendedType::Known(EtherTypes::Ipv6) => {
                Ipv6Packet::new(packet.payload()).map(|x| Box::new(x) as _)
            } */
            _ => None,
        };

        let mut frame = EthernetFrame {
            id,
            timestamp: Utc::now().to_string(),
            header,
            description: Description::default(),
            payload,
        };

        frame.description = frame.get_short();

        Some(frame)
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
            self.header.source_mac,
            self.header.destination_mac,
            self.header.ether_type.protocol_name,
        );
    }

    fn get_next(&self) -> Option<&dyn Layer> {
        self.payload.as_deref()
    }
    fn protocol_type(&self) -> ProtocolType {
        ProtocolType::Ethernet
    }

    fn source(&self) -> String {
        self.header.source_mac.clone()
    }

    fn destination(&self) -> String {
        self.header.destination_mac.clone()
    }

    fn info(&self) -> String {
        format!("next header {}", self.header.ether_type.protocol_name)
    }
}

impl Describable for EthernetFrame {
    fn get_short(&self) -> Description {
        let (s_addy, dest_addy) = match self.payload.as_deref() {
            None => (
                self.header.source_mac.clone(),
                self.header.destination_mac.clone(),
            ),
            Some(network_layer) => (network_layer.source(), network_layer.destination()),
        };

        let layer: &dyn Layer = match self.payload.as_deref() {
            Some(payload) => get_innermost_layer(payload),
            None => self as &dyn Layer,
        };

        Description {
            id: self.id,
            id_string: self.id.to_string(),
            timestamp: self.timestamp.clone(),
            protocol: layer.protocol_type(),
            source: s_addy,
            destination: dest_addy,
            info: layer.info(),
        }
    }

    fn get_long(&self) -> String {
        let mut ret = String::new();
        self.append_summary(&mut ret);

        let mut current_layer: Option<&dyn Layer> = self.payload.as_deref();
        while let Some(layer) = &current_layer {
            ret.push_str("\n\n");
            layer.append_summary(&mut ret);
            current_layer = layer.get_next();
        }

        ret
    }

    fn get_id(&self) -> i32 {
        self.id
    }

    fn get_description(&self) -> &Description {
        &self.description
    }
}

/*



helper functions



 */

//might be in another trait
fn get_innermost_info(mut layer: &dyn Layer) -> (ProtocolType, String) {
    layer = get_innermost_layer(layer);
    (layer.protocol_type(), layer.info())
}

fn get_innermost_layer(mut layer: &dyn Layer) -> &dyn Layer {
    while let Some(next) = layer.get_next() {
        layer = next;
    }
    layer
}

fn set_name(proto: EtherType) -> &'static str {
    match proto {
        EtherTypes::Ipv4 => "IPv4",
        EtherTypes::Arp => "ARP",
        EtherTypes::Ipv6 => "IPv6",
        _ => "Unknown",
    }
}
