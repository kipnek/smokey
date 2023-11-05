use crate::packets::data_link::ethernet::EthernetFrame;
use crate::packets::shared_objs::Interface;
use iced::widget::scrollable;
use iced::Error;
use pcap::{ConnectionStatus, Device, DeviceFlags, IfFlags, Linktype};
use pnet::datalink::interfaces;
use std::net::IpAddr;
use std::sync::mpsc::{self, Receiver};
use std::thread;

#[derive(Default)]
pub struct LiveCapture {
    pub interface: Option<Device>,
    pub receiver: Option<Receiver<EthernetFrame>>,
    pub captured_packets: Vec<EthernetFrame>,
}

impl LiveCapture {
    pub fn capture(&mut self) {
        let (sender, receiver) = mpsc::channel();
        self.receiver = Some(receiver);
        let interface = self.interface.clone();
        thread::spawn(move || {
            let mut index = 0;

            //only for development
            //let device = Device::lookup().unwrap().expect("Device Lookup failed");

            if let Some(int) = interface {
                let mut cap = pcap::Capture::from_device(int)
                    .unwrap()
                    .immediate_mode(true)
                    .promisc(true)
                    .open()
                    .unwrap();
                //use when more types are captured
                //let Linktype(_cap_type) = cap.get_datalink();

                while let Ok(packet) = cap.next_packet() {
                    let Some(eth_frame) = EthernetFrame::new(index, &packet) else {
                        continue;
                    };
                    let result = sender.send(eth_frame);
                    if result.is_err() {
                        // receiver was dropped
                        break;
                    }
                    index += 1;
                }
            }
        });
    }

    pub fn stop(&mut self) {
        self.receiver = None;
    }

    pub fn get_interfaces() -> Result<Vec<Device>, Error> {
        let devices = pcap::Device::list().expect("no devices");
        Ok(devices)
    }
}

/*

the different types from datatype to ensure it only parses legit ethernet etc..


   pub const NULL: Self = Self(0);
   pub const ETHERNET: Self = Self(1);
   pub const AX25: Self = Self(3);
   pub const IEEE802_5: Self = Self(6);
   pub const ARCNET_BSD: Self = Self(7);
   pub const SLIP: Self = Self(8);
   pub const PPP: Self = Self(9);
   pub const FDDI: Self = Self(10);
   pub const PPP_HDLC: Self = Self(50);
   pub const PPP_ETHER: Self = Self(51);
   pub const ATM_RFC1483: Self = Self(100);
   pub const RAW: Self = Self(101);
   pub const C_HDLC: Self = Self(104);
   pub const IEEE802_11: Self = Self(105);
   pub const FRELAY: Self = Self(107);
   pub const LOOP: Self = Self(108);
   pub const LINUX_SLL: Self = Self(113);
   pub const LTALK: Self = Self(114);
   pub const PFLOG: Self = Self(117);
   pub const IEEE802_11_PRISM: Self = Self(119);
   pub const IP_OVER_FC: Self = Self(122);
   pub const SUNATM: Self = Self(123);
   pub const IEEE802_11_RADIOTAP: Self = Self(127);
   pub const ARCNET_LINUX: Self = Self(129);
   pub const APPLE_IP_OVER_IEEE1394: Self = Self(138);
   pub const MTP2_WITH_PHDR: Self = Self(139);
   pub const MTP2: Self = Self(140);
   pub const MTP3: Self = Self(141);
   pub const SCCP: Self = Self(142);
   pub const DOCSIS: Self = Self(143);
   pub const LINUX_IRDA: Self = Self(144);
   pub const USER0: Self = Self(147);
   pub const USER1: Self = Self(148);
   pub const USER2: Self = Self(149);
   pub const USER3: Self = Self(150);
   pub const USER4: Self = Self(151);
   pub const USER5: Self = Self(152);
   pub const USER6: Self = Self(153);
   pub const USER7: Self = Self(154);
   pub const USER8: Self = Self(155);
   pub const USER9: Self = Self(156);
   pub const USER10: Self = Self(157);
   pub const USER11: Self = Self(158);
   pub const USER12: Self = Self(159);
   pub const USER13: Self = Self(160);
   pub const USER14: Self = Self(161);
   pub const USER15: Self = Self(162);
   pub const IEEE802_11_AVS: Self = Self(163);
   pub const BACNET_MS_TP: Self = Self(165);
   pub const PPP_PPPD: Self = Self(166);
   pub const GPRS_LLC: Self = Self(169);
   pub const GPF_T: Self = Self(170);
   pub const GPF_F: Self = Self(171);
   pub const LINUX_LAPD: Self = Self(177);
   pub const MFR: Self = Self(182);
   pub const BLUETOOTH_HCI_H4: Self = Self(187);
   pub const USB_LINUX: Self = Self(189);
   pub const PPI: Self = Self(192);
   pub const IEEE802_15_4_WITHFCS: Self = Self(195);
   pub const SITA: Self = Self(196);
   pub const ERF: Self = Self(197);
   pub const BLUETOOTH_HCI_H4_WITH_PHDR: Self = Self(201);
   pub const AX25_KISS: Self = Self(202);
   pub const LAPD: Self = Self(203);
   pub const PPP_WITH_DIR: Self = Self(204);
   pub const C_HDLC_WITH_DIR: Self = Self(205);
   pub const FRELAY_WITH_DIR: Self = Self(206);
   pub const LAPB_WITH_DIR: Self = Self(207);
   pub const IPMB_LINUX: Self = Self(209);
   pub const IEEE802_15_4_NONASK_PHY: Self = Self(215);
   pub const USB_LINUX_MMAPPED: Self = Self(220);
   pub const FC_2: Self = Self(224);
   pub const FC_2_WITH_FRAME_DELIMS: Self = Self(225);
   pub const IPNET: Self = Self(226);
   pub const CAN_SOCKETCAN: Self = Self(227);
   pub const IPV4: Self = Self(228);
   pub const IPV6: Self = Self(229);
   pub const IEEE802_15_4_NOFCS: Self = Self(230);
   pub const DBUS: Self = Self(231);
   pub const DVB_CI: Self = Self(235);
   pub const MUX27010: Self = Self(236);
   pub const STANAG_5066_D_PDU: Self = Self(237);
   pub const NFLOG: Self = Self(239);
   pub const NETANALYZER: Self = Self(240);
   pub const NETANALYZER_TRANSPARENT: Self = Self(241);
   pub const IPOIB: Self = Self(242);
   pub const MPEG_2_TS: Self = Self(243);
   pub const NG40: Self = Self(244);
   pub const NFC_LLCP: Self = Self(245);
   pub const INFINIBAND: Self = Self(247);
   pub const SCTP: Self = Self(248);
   pub const USBPCAP: Self = Self(249);
   pub const RTAC_SERIAL: Self = Self(250);
   pub const BLUETOOTH_LE_LL: Self = Self(251);
   pub const NETLINK: Self = Self(253);
   pub const BLUETOOTH_LINUX_MONITOR: Self = Self(254);
   pub const BLUETOOTH_BREDR_BB: Self = Self(255);
   pub const BLUETOOTH_LE_LL_WITH_PHDR: Self = Self(256);
   pub const PROFIBUS_DL: Self = Self(257);
   pub const PKTAP: Self = Self(258);
   pub const EPON: Self = Self(259);
   pub const IPMI_HPM_2: Self = Self(260);
   pub const ZWAVE_R1_R2: Self = Self(261);
   pub const ZWAVE_R3: Self = Self(262);
   pub const WATTSTOPPER_DLM: Self = Self(263);
   pub const ISO_14443: Self = Self(264);
   pub const RDS: Self = Self(265);
   pub const USB_DARWIN: Self = Self(266);
   pub const SDLC: Self = Self(268);
   pub const LORATAP: Self = Self(270);
   pub const VSOCK: Self = Self(271);
   pub const NORDIC_BLE: Self = Self(272);
   pub const DOCSIS31_XRA31: Self = Self(273);
   pub const ETHERNET_MPACKET: Self = Self(274);
   pub const DISPLAYPORT_AUX: Self = Self(275);
   pub const LINUX_SLL2: Self = Self(276);
   pub const OPENVIZSLA: Self = Self(278);
   pub const EBHSCR: Self = Self(279);
   pub const VPP_DISPATCH: Self = Self(280);
   pub const DSA_TAG_BRCM: Self = Self(281);
   pub const DSA_TAG_BRCM_PREPEND: Self = Self(282);
   pub const IEEE802_15_4_TAP: Self = Self(283);
   pub const DSA_TAG_DSA: Self = Self(284);
   pub const DSA_TAG_EDSA: Self = Self(285);
   pub const ELEE: Self = Self(286);
   pub const Z_WAVE_SERIAL: Self = Self(287);
   pub const USB_2_0: Self = Self(288);
   pub const ATSC_ALP: Self = Self(289);

*/

/*
use std::collections::HashMap;
use std::net::IpAddr;

#[derive(Hash, Eq, PartialEq, Debug)]
struct ConnectionKey {
    src_ip: IpAddr,
    dest_ip: IpAddr,
    src_port: u16,
    dest_port: u16,
    protocol: String,
}

struct Connection {
    packets: Vec<Packet>,  // Assuming you have a Packet struct defined elsewhere
    // Other connection-specific data
}

fn main() {
    let mut connections: HashMap<ConnectionKey, Connection> = HashMap::new();

    // Example: Adding a new connection
    let key = ConnectionKey {
        src_ip: "192.168.1.1".parse().unwrap(),
        dest_ip: "93.184.216.34".parse().unwrap(),
        src_port: 12345,
        dest_port: 80,
        protocol: "TCP".to_string(),
    };
    let connection = Connection {
        packets: vec![],  // Initialize with an empty packet list
        // Initialize other fields as necessary
    };
    connections.insert(key, connection);

    // Example: Accessing a connection
    if let Some(connection) = connections.get_mut(&key) {
        // Do something with the connection
        println!("Found a connection with {} packets", connection.packets.len());
    }
}


//comparing connection
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::cmp::Ordering;

#[derive(Debug, Clone)]
struct Connection {
    src: String,
    dest: String,
}

impl PartialEq for Connection {
    fn eq(&self, other: &Self) -> bool {
        (self.src == other.src && self.dest == other.dest) || (self.src == other.dest && self.dest == other.src)
    }
}

impl Eq for Connection {}

impl Hash for Connection {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let mut hasher = DefaultHasher::new();
        let mut v = vec![&self.src, &self.dest];
        v.sort(); // Ensure consistent ordering for hashing
        v.hash(&mut hasher);
        state.write_u64(hasher.finish());
    }
}

impl PartialOrd for Connection {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Connection {
    fn cmp(&self, other: &Self) -> Ordering {
        let mut v1 = vec![&self.src, &self.dest];
        let mut v2 = vec![&other.src, &other.dest];
        v1.sort();
        v2.sort();
        v1.cmp(&v2)
    }
}


 */
