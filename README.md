# gfw-rs
Rewrite [OpenGFW](https://github.com/apernet/OpenGFW) in Rust.


> [!CAUTION]
> This project is still in very early stages of development. Use at your own risk.


## Features
* High concurrency and fast I/O processing speed: The core engine utilizes Rust's Tokio asynchronous runtime, ensuring excellent concurrency performance and rapid I/O processing capabilities.
* Multi-protocol support: Supports the parsing of multiple network protocols, providing rich packet information to meet diverse network analysis needs.
* Flexible rule definition: Rules are defined using the Rhai scripting language, allowing users to customize matching rules in various ways and apply corresponding actions to matched network packets.
* Streamlined frontend interface: Includes a user-friendly frontend interface that supports custom configuration and log visualization, enhancing the overall user experience.


## WIP
See [this issue](https://github.com/tkob-vh/net-guardian/issues/22)

##  Requriements
* The kernel modules about the connection tracking system should be loaded.
* Need root permission to modify the nftables/iptables and `conntrack` system.
