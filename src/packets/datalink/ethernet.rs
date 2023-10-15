use crate::packets::internet::ip::Ipv4Packet;
use crate::packets::shared_structs::{Description, ExtendedType, ProtocolDescriptor, ProtocolType};
use crate::traits::{Describable, Layer, SetProtocolDescriptor};
use chrono::Utc;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::Packet;
use std::collections::HashMap;
use std::default::Default;
use pnet::packet::ethernet::EtherType;



/*

Ethernet Header

 */
#[derive(Default, Clone, Debug)]
pub struct EthernetHeader {
    pub source_mac: String,
    pub destination_mac: String,
    pub ether_type: ProtocolDescriptor<ExtendedType<EtherType>>,
    pub payload: Vec<u8>,
    pub malformed: bool,
}
impl SetProtocolDescriptor<EtherType> for EthernetHeader {
    fn set_proto_descriptor(proto: ExtendedType<EtherType>) -> ProtocolDescriptor<ExtendedType<EtherType>> {
        let protocol_name = match &proto {
            ExtendedType::Known(ether_type) => {
                set_name(ether_type)
            }
            ExtendedType::Malformed => {
                "malformed".to_string()
            }
        };

        ProtocolDescriptor {
            protocol_name,
            protocol_type: proto,
        }
    }
}


fn set_name(proto: &EtherType) -> String {
    let name: String = match proto {
        &EtherTypes::Ipv4 => "IPv4".to_string(),
        &EtherTypes::Arp => "ARP".to_string(),
        &EtherTypes::Ipv6=> "IPv6".to_string(),
        _ => "Unknown".to_string(),
    };
    name
}

impl EthernetHeader {
    pub fn malformed(packet: &[u8]) -> EthernetHeader {
        EthernetHeader {
            source_mac: "".to_string(),
            destination_mac: "".to_string(),
            ether_type: EthernetHeader::set_proto_descriptor(ExtendedType::Malformed),
            payload: packet.to_vec(),
            malformed: true,
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
    pub payload: Option<Box<dyn Layer>>,
}

impl Layer for EthernetFrame {
    fn deserialize(&mut self, packet: &[u8]) {



        let packet_header: EthernetHeader = match EthernetPacket::new(packet) {
            None => EthernetHeader::malformed(packet),
            Some(header) => {
                EthernetHeader {
                    source_mac: header.get_source().to_string(),
                    destination_mac: header.get_destination().to_string(),
                    ether_type: EthernetHeader::set_proto_descriptor(ExtendedType::Known(header.get_ethertype())),
                    payload: header.payload().to_vec(),
                    malformed: false,
                }
            },
        };
        let payload: Option<Box<dyn Layer>> = match &packet_header.ether_type.protocol_type.clone() {
            &ExtendedType::Known(EtherTypes::Ipv4) => {
                //ipv4
                Some(Box::new(parse_ipv4(&packet_header.payload)))
            }
            _ => None,
        };
        self.header = packet_header;
        self.payload = payload;
    }

    fn get_summary(&self) -> HashMap<String, String> {
        let mut map: HashMap<String, String> = HashMap::new();
        map.insert("protocol".to_string(), "ethernet".to_string());
        map.insert("Source Mac".to_string(), self.header.source_mac.to_string());
        map.insert(
            "Destination Mac".to_string(),
            self.header.destination_mac.to_string(),
        );
        map.insert(
            "Ethertype".to_string(),
            format!(
                "{}",
                self.header.ether_type.protocol_name
            ),
        );
        map.insert("malformed".to_string(), self.header.malformed.to_string());
        map
    }

    fn get_next(&self) -> &Option<Box<dyn Layer>> {
        &self.payload
    }
    fn protocol_type(&self) -> ProtocolType {
        ProtocolType::Ethernet
    }

    fn source(&self) -> String {
        self.header.source_mac.to_string()
    }

    fn destination(&self) -> String {
        self.header.destination_mac.to_string()
    }

    fn info(&self) -> String {
        format!(
            "next header {}",
            self.header.ether_type.protocol_name
        )
    }
}

impl EthernetFrame {
    pub fn new(id: i32, packet: &[u8]) -> Self {
        let mut frame = EthernetFrame {
            id,
            timestamp: Utc::now().to_string(),
            ..Default::default()
        };
        frame.deserialize(packet);
        frame
    }
}

impl Describable for EthernetFrame {
    fn get_short(&self) -> Description {
        let (source, destination) = if self.payload.as_ref().is_none() {
            (
                self.header.source_mac.clone(),
                self.header.destination_mac.clone(),
            )
        } else {
            let payload = self.payload.as_ref().unwrap();
            (payload.source(), payload.destination())
        };

        let (protocol, info) = if let Some(payload) = self.payload.as_ref() {
            get_innermost_info(payload.as_ref())
        } else {
            (ProtocolType::Ethernet, self.info())
        };

        Description {
            id: self.id,
            timestamp: self.timestamp.clone(),
            protocol,
            source,
            destination,
            info,
        }
    }

    fn get_long(&self) -> Vec<HashMap<String, String>> {
        let mut vec_map = vec![self.get_summary()];
        let mut current_layer: Option<Box<&dyn Layer>> = Some(Box::new(self));
        while let Some(layer) = &current_layer {
            vec_map.push(layer.get_summary());
            current_layer = layer
                .get_next()
                .as_ref()
                .map(|boxed_layer| Box::new(boxed_layer.as_ref() as &dyn Layer));
        }

        vec_map
    }
}

/*

helper functions

 */

//might be in another trait ]
fn get_innermost_info(layer: &dyn Layer) -> (ProtocolType, String) {
    match layer.get_next() {
        Some(next) => get_innermost_info(next.as_ref()),
        None => (layer.protocol_type(), layer.info()),
    }
}

fn parse_ipv4(payload: &[u8]) -> Ipv4Packet {
    let mut packet = Ipv4Packet::default();
    packet.deserialize(payload);
    packet
}



//might
#[derive(Default, Clone, Debug)]
pub enum ExtendedEtherType {
    Known(EtherType),
    #[default]
    Malformed,
}

/*

this is the different values for the next header protocol

   pub const Ipv4: EtherType = EtherType(0x0800);
   /// Address Resolution Protocol (ARP) \[RFC7042\].
   pub const Arp: EtherType = EtherType(0x0806);
   /// Wake on Lan.
   pub const WakeOnLan: EtherType = EtherType(0x0842);
   /// IETF TRILL Protocol \[IEEE\].
   pub const Trill: EtherType = EtherType(0x22F3);
   /// DECnet Phase IV.
   pub const DECnet: EtherType = EtherType(0x6003);
   /// Reverse Address Resolution Protocol (RARP) \[RFC903\].
   pub const Rarp: EtherType = EtherType(0x8035);
   /// AppleTalk - EtherTalk \[Apple\].
   pub const AppleTalk: EtherType = EtherType(0x809B);
   /// AppleTalk Address Resolution Protocol (AARP) \[Apple\].
   pub const Aarp: EtherType = EtherType(0x80F3);
   /// IPX \[Xerox\].
   pub const Ipx: EtherType = EtherType(0x8137);
   /// QNX Qnet \[QNX Software Systems\].
   pub const Qnx: EtherType = EtherType(0x8204);
   /// Internet Protocol version 6 (IPv6) \[RFC7042\].
   pub const Ipv6: EtherType = EtherType(0x86DD);
   /// Ethernet Flow Control \[IEEE 802.3x\].
   pub const FlowControl: EtherType = EtherType(0x8808);
   /// CobraNet \[CobraNet\].
   pub const CobraNet: EtherType = EtherType(0x8819);
   /// MPLS Unicast \[RFC 3032\].
   pub const Mpls: EtherType = EtherType(0x8847);
   /// MPLS Multicast \[RFC 5332\].
   pub const MplsMcast: EtherType = EtherType(0x8848);
   /// PPPOE Discovery Stage \[RFC 2516\].
   pub const PppoeDiscovery: EtherType = EtherType(0x8863);
   /// PPPoE Session Stage \[RFC 2516\].
   pub const PppoeSession: EtherType = EtherType(0x8864);
   /// VLAN-tagged frame (IEEE 802.1Q).
   pub const Vlan: EtherType = EtherType(0x8100);
   /// Provider Bridging \[IEEE 802.1ad / IEEE 802.1aq\].
   pub const PBridge: EtherType = EtherType(0x88a8);
   /// Link Layer Discovery Protocol (LLDP) \[IEEE 802.1AB\].
   pub const Lldp: EtherType = EtherType(0x88cc);
   /// Precision Time Protocol (PTP) over Ethernet \[IEEE 1588\].
   pub const Ptp: EtherType = EtherType(0x88f7);
   /// CFM / Y.1731 \[IEEE 802.1ag\].
   pub const Cfm: EtherType = EtherType(0x8902);
   /// Q-in-Q Vlan Tagging \[IEEE 802.1Q\].
   pub const QinQ: EtherType = EtherType(0x9100);

*/
