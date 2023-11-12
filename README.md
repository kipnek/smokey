# cnote
rust protocol analyzer (early dev)

## How it works

#### if not Open Suse (or maybe other linux variations)
first make sure rust is installed then clone the project then in the root of the 
project
```cargo run```
and the basic window should show up.

#### if OpenSuse (or maybe other linux variations)
```
cargo build --release \
&& sudo setcap cap_net_raw,cap_net_admin+eip target/release/cnote
```
### Supported protocols
Ethernet, IPv4, UDP, and TCP right now

### base frame
```rust
#[derive(Default, Debug)]
pub struct EthernetFrame {
    pub id: i32,
    pub timestamp: String,
    pub header: EthernetHeader,
    pub payload: Option<Box<dyn Layer>>,
}
```
Layer is a trait object that gets implemented further down the line. Ever protocol it encapsulates
implements the trait Layer <br />
so <br />
Ethernet -> IP -> TCP 

### Layers
Every packet implements the layer trait, layer implements the ```Send``` marker

### Sniffers
Sniffers are the packet capture logic. 

This is just a rough outline for anyone who reads this/myself so i know what im doing.


Each packet that implements layer handles the logic for the layer it encapsulates.

### Milestones
1. Establish a general framework for the backend that is a reasonable approach <br />
🔵🔵🔵🔵🔵⬜⬜⬜⬜⬜ 50%
2. Logging - <br />
⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜ 0 %
3. Set up basic gui - <br />
🔵🔵⬜⬜⬜⬜⬜⬜⬜⬜ 0 %
4. Figure out how to handle 802.11 frame - <br />
⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜ 0%
4. Figure out how to highlight problem packets - <br />
⬜⬜⬜⬜⬜⬜⬜⬜⬜⬜ 0%
