# cnote
cli rust protocol analyzer

## CLI
Making it a cli first then a gui

lot of refactoring coming up too after this refactoring.

## How it works

### Basic Object
This is the basic packet. Since we wont always have all layers, each field is an option. The link layer may change
```rust
pub struct BasePacket {
    pub id: i32,
    pub date: String,
    pub link_header: Option<LinkLayer>,
    pub internet_header: Option<InternetLayer>,
    pub transport_header: Option<TransportLayer>,
    pub packet_data: Vec<u8>,
}
```
Each of these fields leads to

### Layers
In the ```layers``` directory, there are enums that represent the layers of the TCP/IP stack. I chose this because it 
more easily aligns with development. 
each layer enum variant leads to 

### Headers
Headers are the _packets_ themselves. Im thinking of further organizing packets into their perspective layers

### Layer Processors
_Layer Processors_ are the logic behind choosing which header gets built or _processed_

### Sniffers
Sniffers are the packet capture logic. 

This is just a rough outline for anyone who reads this/myself so i know what im doing.
