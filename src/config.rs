//! Listener configuration shared by the GUI and the CLI.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Where the local proxy listens and whether it is allowed to relay anything
/// other than Telegram.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListenConfig {
    pub addr: SocketAddr,
    /// Relay non-Telegram destinations as a plain SOCKS5 proxy.
    ///
    /// Loopback listeners get this for free because only local processes can
    /// reach them. A listener the network can reach must opt in explicitly, so
    /// that sharing TGLock across a flat never silently turns the machine into
    /// an open SOCKS5 relay.
    pub allow_direct: bool,
}

impl ListenConfig {
    /// Listener with the default policy for the given address.
    pub fn new(ip: IpAddr, port: u16) -> Self {
        Self {
            addr: SocketAddr::new(ip, port),
            allow_direct: ip.is_loopback(),
        }
    }

    /// `127.0.0.1` — only this machine, non-Telegram traffic relayed.
    pub fn loopback(port: u16) -> Self {
        Self::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    /// `0.0.0.0` — reachable from the local network, Telegram destinations only.
    pub fn lan(port: u16) -> Self {
        Self::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)
    }

    /// Override the direct-relay policy. Used by `--allow-direct`.
    pub fn with_allow_direct(mut self, allow_direct: bool) -> Self {
        self.allow_direct = allow_direct;
        self
    }

    /// Host to advertise in a `tg://proxy` link for this listener.
    ///
    /// A wildcard bind is not a usable destination, so it is resolved to the
    /// address this machine uses to reach the network.
    pub fn advertised_host(&self) -> String {
        let ip = self.addr.ip();
        if ip.is_unspecified() {
            outbound_ip().unwrap_or_else(|| Ipv4Addr::LOCALHOST.to_string())
        } else {
            ip.to_string()
        }
    }

    /// `tg://proxy` link that points Telegram at this listener.
    pub fn telegram_link(&self, secret: &str) -> String {
        format!(
            "tg://proxy?server={}&port={}&secret={}",
            self.advertised_host(),
            self.addr.port(),
            secret
        )
    }
}

/// Local address of the interface that reaches the default route.
///
/// No packet is sent: connecting a UDP socket only makes the OS pick a route.
fn outbound_ip() -> Option<String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    Some(socket.local_addr().ok()?.ip().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_relays_direct_traffic() {
        let config = ListenConfig::loopback(1080);
        assert_eq!(config.addr.to_string(), "127.0.0.1:1080");
        assert!(config.allow_direct);
    }

    #[test]
    fn lan_restricts_to_telegram_by_default() {
        let config = ListenConfig::lan(1080);
        assert_eq!(config.addr.to_string(), "0.0.0.0:1080");
        assert!(!config.allow_direct);
    }

    #[test]
    fn any_routable_address_restricts_to_telegram() {
        for ip in ["192.168.1.10", "10.0.0.5", "::"] {
            let config = ListenConfig::new(ip.parse().unwrap(), 1080);
            assert!(
                !config.allow_direct,
                "{ip} must not relay non-Telegram traffic without an explicit opt-in"
            );
        }
    }

    #[test]
    fn ipv6_loopback_is_treated_as_local() {
        let config = ListenConfig::new("::1".parse().unwrap(), 1080);
        assert!(config.allow_direct);
        assert_eq!(config.addr.to_string(), "[::1]:1080");
    }

    #[test]
    fn allow_direct_override_is_explicit_in_both_directions() {
        assert!(ListenConfig::lan(1080).with_allow_direct(true).allow_direct);
        assert!(
            !ListenConfig::loopback(1080)
                .with_allow_direct(false)
                .allow_direct
        );
    }

    #[test]
    fn link_uses_concrete_host_and_port() {
        let link = ListenConfig::new("192.168.1.10".parse().unwrap(), 1443).telegram_link("ddaa");
        assert_eq!(link, "tg://proxy?server=192.168.1.10&port=1443&secret=ddaa");
    }

    #[test]
    fn wildcard_bind_never_advertises_itself() {
        let host = ListenConfig::lan(1080).advertised_host();
        assert_ne!(host, "0.0.0.0");
        assert!(!host.is_empty());
    }
}
