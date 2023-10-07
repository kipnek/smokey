use crate::packet_objects::headers::protocol_headers::{tcp::TcpHeader, udp::UdpHeader};
use crate::packet_objects::layers::protocol::ProtocolLayer;
use crate::traits::Processable;
use pnet::packet::{tcp, udp};

pub struct TransportProcessor {}

impl TransportProcessor {
    pub fn process_protocol(payload: &[u8], next_header: &u16) -> ProtocolLayer {
        match next_header {
            6 => process_tcp(payload),
            17 => process_udp(payload),
            _ => ProtocolLayer::Unknown,
        }
    }
}

fn process_tcp(payload: &[u8]) -> ProtocolLayer {
    if let Some(tcp_packet) = tcp::TcpPacket::new(payload) {
        ProtocolLayer::Tcp(tcp_packet.process())
    } else {
        ProtocolLayer::Tcp(TcpHeader::deformed_packet(payload.to_vec()))
    }
}

fn process_udp(payload: &[u8]) -> ProtocolLayer {
    if let Some(udp_packet) = udp::UdpPacket::new(payload) {
        ProtocolLayer::Udp(udp_packet.process())
    } else {
        ProtocolLayer::Udp(UdpHeader::deformed_packet(payload.to_vec()))
    }
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