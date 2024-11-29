# net-guardian
Rewrite [opengfw](https://github.com/apernet/OpenGFW) in Rust.

> [!CAUTION]
> This project is still in very early stages of development. Use at your own risk.


## Features
* Written in Rust, focusing on performance and safety.
* Full IP/TCP reassembly, various protocol analyzers.
* a Web-UI which facilitates configuration and monitering.

## WIP
See [this issue](https://github.com/tkob-vh/net-guardian/issues/22)

##  Requriements
* The kernel modules about `conntrack` should be loaded.
* Need root permission to modify the nftables/iptables and `conntrack` system.
