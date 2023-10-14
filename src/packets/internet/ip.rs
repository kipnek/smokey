use crate::packets::shared_structs::FieldType;
use crate::packets::transport::tcp::TcpPacket;
use crate::packets::transport::udp::UdpPacket;
use crate::traits::Layer;
use std::collections::HashMap;

/*


IPV4


 */
#[derive(Debug, Clone, Default)]
pub struct Ipv4Header {
    pub version_ihl: u8,
    pub dscp_ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags_fragment_offset: u16,
    pub time_to_live: u8,
    pub header_checksum: u16,
    pub source_address: String,
    pub destination_address: String,
    pub next_header: FieldType,
    pub flags: Ipv4Flags,
    pub payload: Vec<u8>,
    pub malformed: bool,
}

#[derive(Debug, Clone, Default)]
pub struct Ipv4Flags {
    reserved: bool,
    dontfrag: bool,
    morefrag: bool,
}

#[derive(Default, Debug)]
pub struct Ipv4Packet {
    pub header: Ipv4Header,
    pub payload: Option<Box<dyn Layer>>,
}

impl Layer for Ipv4Packet {
    fn deserialize(&mut self, packet: &[u8]) {
        let packet_header = match pnet::packet::ipv4::Ipv4Packet::new(packet) {
            None => Ipv4Header::malformed(packet),
            Some(header) => Ipv4Header {
                version_ihl: header.get_version(),
                dscp_ecn: header.get_dscp(),
                total_length: header.get_total_length(),
                identification: header.get_total_length(),
                flags_fragment_offset: header.get_fragment_offset(),
                time_to_live: header.get_ttl(),
                header_checksum: header.get_checksum(),
                source_address: header.get_source().to_string(),
                destination_address: header.get_destination().to_string(),
                next_header: set_next_header(header.get_next_level_protocol().0),
                flags: Ipv4Header::set_flags(header.get_flags()),
                payload: packet.to_vec(),
                malformed: false,
            },
        };

        let payload: Option<Box<dyn Layer>> = match &packet_header.next_header.num.clone() {
            6 => Some(Box::new(parse_tcp(&packet_header.payload))),
            17 => {
                Some(Box::new(parse_udp(&packet_header.payload)))
            },
            _ => {
                None
            },
        };

        self.header = packet_header;
        self.payload = payload;
    }

    fn get_summary(&self) -> HashMap<String, String> {
        let mut map: HashMap<String, String> = HashMap::new();
        map.insert("version".to_string(), self.header.version_ihl.to_string());
        map.insert("dscp_ecn".to_string(), self.header.dscp_ecn.to_string());
        map.insert(
            "total_length".to_string(),
            self.header.total_length.to_string(),
        );
        map.insert(
            "identification".to_string(),
            self.header.identification.to_string(),
        );
        map.insert(
            "flags_fragment_offset".to_string(),
            self.header.flags_fragment_offset.to_string(),
        );
        map.insert(
            "time_to_live".to_string(),
            self.header.time_to_live.to_string(),
        );
        map.insert(
            "header_checksum".to_string(),
            self.header.header_checksum.to_string(),
        );
        map.insert(
            "source_address".to_string(),
            self.header.source_address.to_string(),
        );
        map.insert(
            "destination_address".to_string(),
            self.header.destination_address.to_string(),
        );
        map.insert(
            "next_header".to_string(),
            format!(
                "protocol : {} , number : {}",
                self.header.next_header.field_name, self.header.next_header.num
            ),
        );
        map.insert(
            "flags".to_string(),
            format!(
                "reserved : {}, dont fragment : {},  more fragment : {}",
                self.header.flags.reserved, self.header.flags.dontfrag, self.header.flags.morefrag
            ),
        );
        map.insert("malformed".to_string(), self.header.malformed.to_string());
        map
    }

    fn get_next(&self) -> &Option<Box<dyn Layer>> {
        &self.payload
    }
}

impl Ipv4Header {
    pub fn malformed(packet: &[u8]) -> Ipv4Header {
        Ipv4Header {
            version_ihl: 4,
            dscp_ecn: 0,
            total_length: 0,
            identification: 0,
            flags_fragment_offset: 0,
            time_to_live: 0,
            header_checksum: 0,
            source_address: "".to_string(),
            destination_address: "".to_string(),
            next_header: Default::default(),
            flags: Ipv4Flags {
                reserved: false,
                dontfrag: false,
                morefrag: false,
            },
            payload: packet.to_vec(),
            malformed: true,
        }
    }
    pub fn set_flags(number: u8) -> Ipv4Flags {
        Ipv4Flags {
            reserved: (number & 0b100) != 0,
            dontfrag: (number & 0b010) != 0,
            morefrag: (number & 0b001) != 0,
        }
    }
}

/*

IPV6

 */
#[derive(Debug, Clone)]
pub struct Ipv6Header {
    pub payload: Vec<u8>,
    pub traffic_class: u8,
    pub flow_label: u16,
    pub payload_length: u16,
    pub next_header: FieldType,
    pub hop_limit: u8,
    pub source: String,
    pub destination: String,
    pub version: u8,
}

fn set_next_header(number: u8) -> FieldType {
    let name: String = match &number {
        4 => {
            //ipv4
            "IPv4".to_string()
        }
        6 => {
            //tcp
            "Tcp".to_string()
        }
        17 => {
            //tcp
            "Udp".to_string()
        }
        41 => {
            //ipv6
            "IPv6".to_string()
        }
        _ => "n/a".to_string(),
    };

    FieldType {
        field_name: name,
        num: number as u16,
    }
}

fn parse_tcp(payload: &[u8]) -> TcpPacket {
    let mut packet = TcpPacket::default();
    packet.deserialize(payload);
    packet
}

fn parse_udp(payload: &[u8]) -> UdpPacket {
    let mut packet = UdpPacket::default();
    packet.deserialize(payload);
    packet
}

/*

               &IpNextHeaderProtocols::Hopopt => "Hopopt",         // 0
               &IpNextHeaderProtocols::Icmp => "Icmp",             // 1
               &IpNextHeaderProtocols::Igmp => "Igmp",             // 2
               &IpNextHeaderProtocols::Ggp => "Ggp",               // 3
               &IpNextHeaderProtocols::Ipv4 => "Ipv4",             // 4
               &IpNextHeaderProtocols::St => "St",                 // 5
               &IpNextHeaderProtocols::Tcp => "Tcp",               // 6
               &IpNextHeaderProtocols::Cbt => "Cbt",               // 7
               &IpNextHeaderProtocols::Egp => "Egp",               // 8
               &IpNextHeaderProtocols::Igp => "Igp",               // 9
               &IpNextHeaderProtocols::BbnRccMon => "BbnRccMon",   // 10
               &IpNextHeaderProtocols::NvpII => "NvpII",           // 11
               &IpNextHeaderProtocols::Pup => "Pup",               // 12
               &IpNextHeaderProtocols::Argus => "Argus",           // 13
               &IpNextHeaderProtocols::Emcon => "Emcon",           // 14
               &IpNextHeaderProtocols::Xnet => "Xnet",             // 15
               &IpNextHeaderProtocols::Chaos => "Chaos",           // 16
               &IpNextHeaderProtocols::Udp => "Udp",               // 17
               &IpNextHeaderProtocols::Mux => "Mux",               // 18
               &IpNextHeaderProtocols::DcnMeas => "DcnMeas",       // 19
               &IpNextHeaderProtocols::Hmp => "Hmp",               // 20
               &IpNextHeaderProtocols::Prm => "Prm",               // 21
               &IpNextHeaderProtocols::XnsIdp => "XnsIdp",         // 22
               &IpNextHeaderProtocols::Trunk1 => "Trunk1",         // 23
               &IpNextHeaderProtocols::Trunk2 => "Trunk2",         // 24
               &IpNextHeaderProtocols::Leaf1 => "Leaf1",           // 25
               &IpNextHeaderProtocols::Leaf2 => "Leaf2",           // 26
               &IpNextHeaderProtocols::Rdp => "Rdp",               // 27
               &IpNextHeaderProtocols::Irtp => "Irtp",             // 28
               &IpNextHeaderProtocols::IsoTp4 => "IsoTp4",         // 29
               &IpNextHeaderProtocols::Netblt => "Netblt",         // 30
               &IpNextHeaderProtocols::MfeNsp => "MfeNsp",         // 31
               &IpNextHeaderProtocols::MeritInp => "MeritInp",     // 32
               &IpNextHeaderProtocols::Dccp => "Dccp",             // 33
               &IpNextHeaderProtocols::ThreePc => "ThreePc",       // 34
               &IpNextHeaderProtocols::Idpr => "Idpr",             // 35
               &IpNextHeaderProtocols::Xtp => "Xtp",               // 36
               &IpNextHeaderProtocols::Ddp => "Ddp",               // 37
               &IpNextHeaderProtocols::IdprCmtp => "IdprCmtp",     // 38
               &IpNextHeaderProtocols::TpPlusPlus => "TpPlusPlus", // 39
               &IpNextHeaderProtocols::Il => "Il",                 // 40
               &IpNextHeaderProtocols::Ipv6 => "Ipv6",             // 41
               &IpNextHeaderProtocols::Sdrp => "Sdrp",             // 42
               &IpNextHeaderProtocols::Ipv6Route => "Ipv6Route",   // 43
               &IpNextHeaderProtocols::Ipv6Frag => "Ipv6Frag",     // 44
               &IpNextHeaderProtocols::Idrp => "Idrp",             // 45
               &IpNextHeaderProtocols::Rsvp => "Rsvp",             // 46
               &IpNextHeaderProtocols::Gre => "Gre",               // 47
               &IpNextHeaderProtocols::Dsr => "Dsr",               // 48
               &IpNextHeaderProtocols::Bna => "Bna",               // 49
               &IpNextHeaderProtocols::Esp => "Esp",               // 50
               &IpNextHeaderProtocols::Ah => "Ah",                 // 51
               &IpNextHeaderProtocols::INlsp => "INlsp",           // 52
               &IpNextHeaderProtocols::Swipe => "Swipe",           // 53
               &IpNextHeaderProtocols::Narp => "Narp",             // 54
               &IpNextHeaderProtocols::Mobile => "Mobile",         // 55
               &IpNextHeaderProtocols::Tlsp => "Tlsp",             // 56
               &IpNextHeaderProtocols::Skip => "Skip",             // 57
               &IpNextHeaderProtocols::Icmpv6 => "Icmpv6",         // 58
               &IpNextHeaderProtocols::Ipv6NoNxt => "Ipv6NoNxt",   // 59
               &IpNextHeaderProtocols::Ipv6Opts => "Ipv6Opts",     // 60
               &IpNextHeaderProtocols::HostInternal => "HostInternal", // 61
               &IpNextHeaderProtocols::Cftp => "Cftp",             // 62
               &IpNextHeaderProtocols::LocalNetwork => "LocalNetwork", // 63
               &IpNextHeaderProtocols::SatExpak => "SatExpak",     // 64
               &IpNextHeaderProtocols::Kryptolan => "Kryptolan",   // 65
               &IpNextHeaderProtocols::Rvd => "Rvd",               // 66
               &IpNextHeaderProtocols::Ippc => "Ippc",             // 67
               &IpNextHeaderProtocols::DistributedFs => "DistributedFs", // 68
               &IpNextHeaderProtocols::SatMon => "SatMon",         // 69
               &IpNextHeaderProtocols::Visa => "Visa",             // 70
               &IpNextHeaderProtocols::Ipcv => "Ipcv",             // 71
               &IpNextHeaderProtocols::Cpnx => "Cpnx",             // 72
               &IpNextHeaderProtocols::Cphb => "Cphb",             // 73
               &IpNextHeaderProtocols::Wsn => "Wsn",               // 74
               &IpNextHeaderProtocols::Pvp => "Pvp",               // 75
               &IpNextHeaderProtocols::BrSatMon => "BrSatMon",     // 76
               &IpNextHeaderProtocols::SunNd => "SunNd",           // 77
               &IpNextHeaderProtocols::WbMon => "WbMon",           // 78
               &IpNextHeaderProtocols::WbExpak => "WbExpak",       // 79
               &IpNextHeaderProtocols::IsoIp => "IsoIp",           // 80
               &IpNextHeaderProtocols::Vmtp => "Vmtp",             // 81
               &IpNextHeaderProtocols::SecureVmtp => "SecureVmtp", // 82
               &IpNextHeaderProtocols::Vines => "Vines",           // 83
               &IpNextHeaderProtocols::TtpOrIptm => "TtpOrIptm",   // 84
               &IpNextHeaderProtocols::NsfnetIgp => "NsfnetIgp",   // 85
               &IpNextHeaderProtocols::Dgp => "Dgp",               // 86
               &IpNextHeaderProtocols::Tcf => "Tcf",               // 87
               &IpNextHeaderProtocols::Eigrp => "Eigrp",           // 88
               &IpNextHeaderProtocols::OspfigP => "OspfigP",       // 89
               &IpNextHeaderProtocols::SpriteRpc => "SpriteRpc",   // 90
               &IpNextHeaderProtocols::Larp => "Larp",             // 91
               &IpNextHeaderProtocols::Mtp => "Mtp",               // 92
               &IpNextHeaderProtocols::Ax25 => "Ax25",             // 93
               &IpNextHeaderProtocols::IpIp => "IpIp",             // 94
               &IpNextHeaderProtocols::Micp => "Micp",             // 95
               &IpNextHeaderProtocols::SccSp => "SccSp",           // 96
               &IpNextHeaderProtocols::Etherip => "Etherip",       // 97
               &IpNextHeaderProtocols::Encap => "Encap",           // 98
               &IpNextHeaderProtocols::PrivEncryption => "PrivEncryption", // 99
               &IpNextHeaderProtocols::Gmtp => "Gmtp",             // 100
               &IpNextHeaderProtocols::Ifmp => "Ifmp",             // 101
               &IpNextHeaderProtocols::Pnni => "Pnni",             // 102
               &IpNextHeaderProtocols::Pim => "Pim",               // 103
               &IpNextHeaderProtocols::Aris => "Aris",             // 104
               &IpNextHeaderProtocols::Scps => "Scps",             // 105
               &IpNextHeaderProtocols::Qnx => "Qnx",               // 106
               &IpNextHeaderProtocols::AN => "AN",                 // 107
               &IpNextHeaderProtocols::IpComp => "IpComp",         // 108
               &IpNextHeaderProtocols::Snp => "Snp",               // 109
               &IpNextHeaderProtocols::CompaqPeer => "CompaqPeer", // 110
               &IpNextHeaderProtocols::IpxInIp => "IpxInIp",       // 111
               &IpNextHeaderProtocols::Vrrp => "Vrrp",             // 112
               &IpNextHeaderProtocols::Pgm => "Pgm",               // 113
               &IpNextHeaderProtocols::ZeroHop => "ZeroHop",       // 114
               &IpNextHeaderProtocols::L2tp => "L2tp",             // 115
               &IpNextHeaderProtocols::Ddx => "Ddx",               // 116
               &IpNextHeaderProtocols::Iatp => "Iatp",             // 117
               &IpNextHeaderProtocols::Stp => "Stp",               // 118
               &IpNextHeaderProtocols::Srp => "Srp",               // 119
               &IpNextHeaderProtocols::Uti => "Uti",               // 120
               &IpNextHeaderProtocols::Smp => "Smp",               // 121
               &IpNextHeaderProtocols::Sm => "Sm",                 // 122
               &IpNextHeaderProtocols::Ptp => "Ptp",               // 123
               &IpNextHeaderProtocols::IsisOverIpv4 => "IsisOverIpv4", // 124
               &IpNextHeaderProtocols::Fire => "Fire",             // 125
               &IpNextHeaderProtocols::Crtp => "Crtp",             // 126
               &IpNextHeaderProtocols::Crudp => "Crudp",           // 127
               &IpNextHeaderProtocols::Sscopmce => "Sscopmce",     // 128
               &IpNextHeaderProtocols::Iplt => "Iplt",             // 129
               &IpNextHeaderProtocols::Sps => "Sps",               // 130
               &IpNextHeaderProtocols::Pipe => "Pipe",             // 131
               &IpNextHeaderProtocols::Sctp => "Sctp",             // 132
               &IpNextHeaderProtocols::Fc => "Fc",                 // 133
               &IpNextHeaderProtocols::RsvpE2eIgnore => "RsvpE2eIgnore", // 134
               &IpNextHeaderProtocols::MobilityHeader => "MobilityHeader", // 135
               &IpNextHeaderProtocols::UdpLite => "UdpLite",       // 136
               &IpNextHeaderProtocols::MplsInIp => "MplsInIp",     // 137
               &IpNextHeaderProtocols::Manet => "Manet",           // 138
               &IpNextHeaderProtocols::Hip => "Hip",               // 139
               &IpNextHeaderProtocols::Shim6 => "Shim6",           // 140
               &IpNextHeaderProtocols::Wesp => "Wesp",             // 141
               &IpNextHeaderProtocols::Rohc => "Rohc",             // 142
               &IpNextHeaderProtocols::Test1 => "Test1",           // 253
               &IpNextHeaderProtocols::Test2 => "Test2",           // 254
               &IpNextHeaderProtocols::Reserved => "Reserved",     // 255

*/
