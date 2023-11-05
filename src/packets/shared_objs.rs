use crate::packets::traits::Layer;

#[derive(Debug, Clone)]
pub struct Description<'a> {
    pub id: i32,
    pub timestamp: &'a str,
    pub src_dest_layer: &'a dyn Layer,
    pub info_layer: &'a dyn Layer,
}

/*
       Device{
           name: "".to_string(),
           desc: None,
           addresses: vec![],
           flags: DeviceFlags { if_flags: IfFlags {
               bits: 0,
           }, connection_status: ConnectionStatus::Unknown },
       };
*/
