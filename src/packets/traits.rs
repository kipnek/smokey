use crate::packets::shared_objs::{Description, ExtendedType, ProtocolDescriptor, ProtocolType};
use linked_hash_map::LinkedHashMap;

use std::fmt::Debug;

pub trait Layer: Send + Sync + Debug {
    fn deserialize(&mut self, packet: &[u8]);

    fn get_summary(&self) -> LinkedHashMap<String, String>;

    fn get_next(&self) -> &Option<Box<dyn Layer>>;

    fn protocol_type(&self) -> ProtocolType {
        ProtocolType::Unknown // or a suitable default
    }

    fn source(&self) -> String;
    fn destination(&self) -> String;

    fn box_clone(&self) -> Box<dyn Layer>;

    fn info(&self) -> String {
        "Unknown protocol, info not available".to_string()
    }
}

impl Clone for Box<dyn Layer> {
    fn clone(&self) -> Self {
        self.box_clone()
    }
}

pub trait Describable: Send + Sync + Debug + Layer {
    fn get_short(&self) -> Description;

    fn get_long(&self) -> Vec<LinkedHashMap<String, String>>;

    fn get_id(&self) -> i32;

    fn get_description(&self) -> &Description;
}

pub trait SetProtocolDescriptor<T>: Send + Debug {
    fn set_proto_descriptor(proto: ExtendedType<T>) -> ProtocolDescriptor<ExtendedType<T>>;
}
/*
If you want to filter or search packets based on specific criteria like port or
address, you would generally implement accessor methods in the Layer trait and
then implement them for each relevant protocol.

Here's a simple example of what it might look like:

    Add relevant methods to the Layer trait:

rust

pub trait Layer {
    // ... other methods ...

    // Default implementations that return None
    // Only the relevant layers (e.g., UDP, TCP for port) will override these
    fn source_port(&self) -> Option<u16> {
        None
    }

    fn destination_port(&self) -> Option<u16> {
        None
    }

    fn source_address(&self) -> Option<String> {
        None
    }

    fn destination_address(&self) -> Option<String> {
        None
    }
}

    Implement these methods for the relevant packet types:

rust

impl Layer for UdpPacket {
    // ... other implementations ...

    fn source_port(&self) -> Option<u16> {
        Some(self.header.source_port)
    }

    fn destination_port(&self) -> Option<u16> {
        Some(self.header.destination_port)
    }

    // ... and so on
}

    Use these methods to filter/search packets:

rust

let port_to_search: u16 = 8080;
let packets: Vec<EthernetFrame> = /* your list of packets */;
let matching_packets: Vec<&EthernetFrame> = packets.iter()
    .filter(|packet| {
        if let Some(layer) = &packet.payload {
            if let Some(port) = layer.destination_port() {
                return port == port_to_search;
            }
        }
        false
    })
    .collect();

This is a simple and direct way to achieve your goal.
Note that it involves looping through the list of packets and checking each one,
which may not be the most efficient approach for very large packet lists or when you need to perform frequent searches.

For more advanced or efficient searching/filtering mechanisms,
you might consider using data structures like trees, hashmaps, or
databases tailored for network analysis. But for many typical use cases,
the above method should be adequate.
 */
