use crate::packet_objects::layers::datalink::DatalinkLayer;
use crate::packet_objects::layers::network::NetworkLayer;
use crate::packet_objects::layers::transport::TransportLayer;
use crate::traits::Processable;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::{ipv4, tcp, udp};

#[derive(Debug, Clone)]
pub struct RawPacket {
    pub id: i32,
    pub date: String,
    pub datalink_header: Option<DatalinkLayer>,
    pub network_header: Option<NetworkLayer>,
    pub transport_header: Option<TransportLayer>,
    pub packet_data: Vec<u8>,
    pub malformed: bool,
    pub item_height : f32,
}
#[derive(Debug, Clone)]
pub struct FieldType {
    pub field_name: String,
    pub num: u16,
}

/*


impl raw packet


 */

impl RawPacket {
    //New for BasePacket {
    pub fn new(id: i32, packet_data: Vec<u8>) -> Self {
        RawPacket {
            id,
            date: chrono::offset::Local::now().to_string(),
            datalink_header: None,
            network_header: None,
            transport_header: None,
            packet_data,
            malformed: false,
            item_height:50.0,
        }
        .datalink_parse()
        .network_parse()
        .transport_parse()
        .to_owned()
    }

    /*



    parse layers



     */
    pub fn datalink_parse(&mut self) -> &mut Self {
        if let Some(ethernet_packet) = EthernetPacket::new(&self.packet_data) {
            self.datalink_header = Some(DatalinkLayer::Ethernet(ethernet_packet.process()));
        } else {
            self.malformed = true;
        }
        self
    }

    pub fn network_parse(&mut self) -> &mut Self {
        if let Some(ref etherned_header) = self.datalink_header {
            match etherned_header {
                DatalinkLayer::Ethernet(ref eh) => {
                    self.process_network(&eh.payload.clone(), &eh.ether_type.num.clone());
                }
            }
        }
        self
    }

    pub fn transport_parse(&mut self) -> &mut Self {
        if let Some(ref network_header) = self.network_header {
            match network_header {
                NetworkLayer::IPv4(ref header) => {
                    self.process_transport(
                        &header.payload.clone(),
                        &header.next_header.num.clone(),
                    );
                }
                NetworkLayer::IPv6(ref header) => {
                    self.process_transport(
                        &header.payload.clone(),
                        &header.next_header.num.clone(),
                    );
                }
            }
        }
        self
    }

    /*




    entry points to process protocols




     */

    fn process_network(&mut self, payload: &[u8], next_header: &u16) {
        match next_header {
            0x0800 => self.process_ipv4(payload),
            0x0806 => { //EtherType::Arp,
            }
            0x86DD => { //EtherType::Ipv6,
            }
            _ => {}
        }
    }

    fn process_transport(&mut self, payload: &[u8], next_header: &u16) {
        match next_header {
            6 => self.process_tcp(payload),
            17 => self.process_udp(payload),
            _ => self.transport_header = None,
        }
    }

    /*


    process protocols


     */

    fn process_ipv4(&mut self, payload: &[u8]) {
        if let Some(ipv4) = ipv4::Ipv4Packet::new(payload) {
            self.network_header = Some(NetworkLayer::IPv4(ipv4.process()));
        } else {
            self.malformed = true;
        }
    }

    fn process_tcp(&mut self, payload: &[u8]) {
        if let Some(tcp_packet) = tcp::TcpPacket::new(payload) {
            let transport_header = tcp_packet.process();
            self.transport_header =
                Some(TransportLayer::TransportControlProtocol(transport_header));
        } else {
            self.malformed = true;
        }
    }

    fn process_udp(&mut self, payload: &[u8]) {
        if let Some(udp_packet) = udp::UdpPacket::new(payload) {
            let transport_header = udp_packet.process();
            self.transport_header = Some(TransportLayer::UserDatagramProtocol(transport_header));
        } else {
            self.malformed = true;
        }
    }
}

fn get_description(ref raw_packet:&RawPacket)->String{
    let source = match &raw_packet.network_header{
        None => {
            if let Some(datalink) = &raw_packet.datalink_header{
                match &datalink{
                    DatalinkLayer::Ethernet(ethernet) => {
                        ethernet.source_mac.to_string()
                    }
                }
            }else{
                "unknown".to_string()
            }
        }
        Some(ip) => {
            let n_addr:String;
            if let NetworkLayer::IPv4(ip) = ip {
                n_addr = ip.source_address.to_string()
            }else if let NetworkLayer::IPv6(ip) = ip {
                n_addr = "ip.source_address.to_string()".to_string()
            }else{
                n_addr ="unknown".to_string()
            }
            n_addr
        }
    };

    let destination = match &raw_packet.network_header{
        None => {
            if let Some(datalink) = &raw_packet.datalink_header{
                match &datalink{
                    DatalinkLayer::Ethernet(ethernet) => {
                        ethernet.destination_mac.to_string()
                    }
                }
            }else{
                "unknown".to_string()
            }
        }
        Some(ip) => {
            let n_addr:String;
            if let NetworkLayer::IPv4(ip) = ip {
                n_addr = ip.destination_address.to_string()
            }else if let NetworkLayer::IPv6(ip) = ip {
                n_addr = "ip.source_address.to_string()".to_string()
            }else{
                n_addr ="unknown".to_string()
            }
            n_addr
        }
    };


    format!("{} : {}", source, destination)
}