use crate::packets::internet::ip::Ipv4Packet;
use crate::packets::shared_structs::{FieldType, ProtocolType};
use crate::traits::Layer;
use pnet::packet::ethernet::{EtherType, EthernetPacket};
use pnet::packet::Packet;
use std::collections::HashMap;
use std::default::Default;

#[derive(Default, Clone, Debug)]
pub struct EthernetHeader {
    pub source_mac: String,
    pub destination_mac: String,
    pub ether_type: FieldType,
    pub payload: Vec<u8>,
    pub malformed: bool,
}

impl EthernetHeader {
    pub fn set_fieldtype(number: u16) -> FieldType {
        let name: String = match &number {
            0x0800 => "IPv4".to_string(),
            0x0806 => "ARP".to_string(),
            0x86DD => "IPv6".to_string(),
            _ => "Unknown".to_string(),
        };
        FieldType {
            field_name: name,
            num: number,
        }
    }
    pub fn malformed(packet: &[u8]) -> EthernetHeader {
        EthernetHeader {
            source_mac: "".to_string(),
            destination_mac: "".to_string(),
            ether_type: EthernetHeader::set_fieldtype(0),
            payload: packet.to_vec(),
            malformed: true,
        }
    }
}

#[derive(Default, Debug)]
pub struct EthernetFrame {
    pub id: i32,
    pub header: EthernetHeader,
    pub payload: Option<Box<dyn Layer>>,
}

impl Layer for EthernetFrame {
    fn deserialize(&mut self, packet: &[u8]) {
        let packet_header: EthernetHeader = match EthernetPacket::new(packet) {
            None => EthernetHeader::malformed(packet),
            Some(header) => EthernetHeader {
                source_mac: header.get_source().to_string(),
                destination_mac: header.get_destination().to_string(),
                ether_type: EthernetHeader::set_fieldtype(header.get_ethertype().0),
                payload: header.payload().to_vec(),
                malformed: false,
            },
        };
        let payload: Option<Box<dyn Layer>> = match &packet_header.ether_type.num.clone() {
            0x0800 => {
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
                "{} {}",
                self.header.ether_type.field_name, self.header.ether_type.num
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
}

impl EthernetFrame {
    pub fn new(id: i32, packet: &[u8]) -> Self {
        let mut frame = EthernetFrame {
            id,
            ..Default::default()
        };
        frame.deserialize(packet);
        frame
    }
}

fn parse_ipv4(payload: &[u8]) -> Ipv4Packet {
    let mut packet = Ipv4Packet::default();
    packet.deserialize(payload);
    packet
}

/*

looping to get layer

let mut current_layer: Option<&dyn Layer> = Some(initial_packet);
while let Some(layer) = current_layer {
    // Process the current layer
    // ...

    // Move to the next layer
    current_layer = layer.get_next_layer();
}

 */

/*

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
