//! Network connection monitoring

use serde::{Deserialize, Serialize};
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Network connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionState {
    Established,
    Listen,
    TimeWait,
    CloseWait,
    SynSent,
    SynRecv,
    FinWait1,
    FinWait2,
    Close,
    LastAck,
    Closing,
    Unknown,
}

impl ConnectionState {
    pub fn from_hex(state: u8) -> Self {
        match state {
            1 => ConnectionState::Established,
            2 => ConnectionState::SynSent,
            3 => ConnectionState::SynRecv,
            4 => ConnectionState::FinWait1,
            5 => ConnectionState::FinWait2,
            6 => ConnectionState::TimeWait,
            7 => ConnectionState::Close,
            8 => ConnectionState::CloseWait,
            9 => ConnectionState::LastAck,
            10 => ConnectionState::Listen,
            11 => ConnectionState::Closing,
            _ => ConnectionState::Unknown,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            ConnectionState::Established => "ESTABLISHED",
            ConnectionState::Listen => "LISTEN",
            ConnectionState::TimeWait => "TIME_WAIT",
            ConnectionState::CloseWait => "CLOSE_WAIT",
            ConnectionState::SynSent => "SYN_SENT",
            ConnectionState::SynRecv => "SYN_RECV",
            ConnectionState::FinWait1 => "FIN_WAIT1",
            ConnectionState::FinWait2 => "FIN_WAIT2",
            ConnectionState::Close => "CLOSE",
            ConnectionState::LastAck => "LAST_ACK",
            ConnectionState::Closing => "CLOSING",
            ConnectionState::Unknown => "UNKNOWN",
        }
    }
}

/// Protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Tcp6,
    Udp,
    Udp6,
}

impl Protocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Tcp6 => "tcp6",
            Protocol::Udp => "udp",
            Protocol::Udp6 => "udp6",
        }
    }
}

/// Network connection information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionInfo {
    /// Protocol
    pub protocol: Protocol,
    /// Local IP address
    pub local_addr: IpAddr,
    /// Local port
    pub local_port: u16,
    /// Remote IP address
    pub remote_addr: IpAddr,
    /// Remote port
    pub remote_port: u16,
    /// Connection state
    pub state: ConnectionState,
    /// Process ID (if available)
    pub pid: Option<u32>,
    /// Process name (if available)
    pub process_name: Option<String>,
    /// Inode number
    pub inode: u64,
}

/// Get all network connections
#[cfg(target_os = "linux")]
pub fn get_connections() -> Vec<ConnectionInfo> {
    let mut connections = Vec::new();

    // Parse /proc/net/tcp, tcp6, udp, udp6
    if let Some(conns) = parse_proc_net("/proc/net/tcp", Protocol::Tcp) {
        connections.extend(conns);
    }
    if let Some(conns) = parse_proc_net("/proc/net/tcp6", Protocol::Tcp6) {
        connections.extend(conns);
    }
    if let Some(conns) = parse_proc_net("/proc/net/udp", Protocol::Udp) {
        connections.extend(conns);
    }
    if let Some(conns) = parse_proc_net("/proc/net/udp6", Protocol::Udp6) {
        connections.extend(conns);
    }

    // Try to map inodes to PIDs
    let inode_to_pid = build_inode_pid_map();

    for conn in &mut connections {
        if let Some(&pid) = inode_to_pid.get(&conn.inode) {
            conn.pid = Some(pid);
            conn.process_name = get_process_name(pid);
        }
    }

    connections
}

#[cfg(target_os = "macos")]
pub fn get_connections() -> Vec<ConnectionInfo> {
    // On macOS, use lsof or netstat
    // This is a simplified implementation
    Vec::new()
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn get_connections() -> Vec<ConnectionInfo> {
    Vec::new()
}

#[cfg(target_os = "linux")]
fn parse_proc_net(path: &str, protocol: Protocol) -> Option<Vec<ConnectionInfo>> {
    let content = fs::read_to_string(path).ok()?;
    let mut connections = Vec::new();

    for line in content.lines().skip(1) {
        // Skip header
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }

        // Parse local address:port
        let local_parts: Vec<&str> = parts[1].split(':').collect();
        if local_parts.len() != 2 {
            continue;
        }

        // Parse remote address:port
        let remote_parts: Vec<&str> = parts[2].split(':').collect();
        if remote_parts.len() != 2 {
            continue;
        }

        let is_ipv6 = matches!(protocol, Protocol::Tcp6 | Protocol::Udp6);

        let local_addr = parse_hex_addr(local_parts[0], is_ipv6)?;
        let local_port = u16::from_str_radix(local_parts[1], 16).ok()?;

        let remote_addr = parse_hex_addr(remote_parts[0], is_ipv6)?;
        let remote_port = u16::from_str_radix(remote_parts[1], 16).ok()?;

        let state_hex = u8::from_str_radix(parts[3], 16).unwrap_or(0);
        let state = ConnectionState::from_hex(state_hex);

        let inode = parts[9].parse().unwrap_or(0);

        connections.push(ConnectionInfo {
            protocol,
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            state,
            pid: None,
            process_name: None,
            inode,
        });
    }

    Some(connections)
}

fn parse_hex_addr(hex: &str, is_ipv6: bool) -> Option<IpAddr> {
    if is_ipv6 {
        if hex.len() != 32 {
            return None;
        }

        let mut bytes = [0u8; 16];
        for i in 0..16 {
            bytes[i] = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).ok()?;
        }

        // Reverse byte order for each 4-byte group (Linux stores in network byte order)
        for chunk in bytes.chunks_exact_mut(4) {
            chunk.reverse();
        }

        Some(IpAddr::V6(Ipv6Addr::from(bytes)))
    } else {
        if hex.len() != 8 {
            return None;
        }

        let addr = u32::from_str_radix(hex, 16).ok()?;
        Some(IpAddr::V4(Ipv4Addr::from(addr.to_le())))
    }
}

#[cfg(target_os = "linux")]
fn build_inode_pid_map() -> std::collections::HashMap<u64, u32> {
    use std::collections::HashMap;

    let mut map = HashMap::new();

    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.filter_map(|e| e.ok()) {
            let name = entry.file_name();
            if let Ok(pid) = name.to_string_lossy().parse::<u32>() {
                let fd_path = format!("/proc/{}/fd", pid);
                if let Ok(fds) = fs::read_dir(&fd_path) {
                    for fd in fds.filter_map(|e| e.ok()) {
                        if let Ok(link) = fs::read_link(fd.path()) {
                            let link_str = link.to_string_lossy();
                            if link_str.starts_with("socket:[") {
                                if let Some(inode_str) =
                                    link_str.strip_prefix("socket:[").and_then(|s| s.strip_suffix(']'))
                                {
                                    if let Ok(inode) = inode_str.parse() {
                                        map.insert(inode, pid);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    map
}

#[cfg(target_os = "linux")]
fn get_process_name(pid: u32) -> Option<String> {
    let comm_path = format!("/proc/{}/comm", pid);
    fs::read_to_string(comm_path)
        .ok()
        .map(|s| s.trim().to_string())
}

/// Get listening ports
pub fn get_listening_ports() -> Vec<ConnectionInfo> {
    get_connections()
        .into_iter()
        .filter(|c| c.state == ConnectionState::Listen)
        .collect()
}

/// Get established connections to external hosts
pub fn get_external_connections() -> Vec<ConnectionInfo> {
    get_connections()
        .into_iter()
        .filter(|c| {
            c.state == ConnectionState::Established
                && !is_local_addr(&c.remote_addr)
                && c.remote_port != 0
        })
        .collect()
}

fn is_local_addr(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback(),
    }
}

/// Summary of network connections
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ConnectionSummary {
    pub total_connections: usize,
    pub listening_ports: usize,
    pub established: usize,
    pub external_connections: usize,
    pub unique_remote_hosts: usize,
}

impl ConnectionSummary {
    pub fn from_connections(connections: &[ConnectionInfo]) -> Self {
        use std::collections::HashSet;

        let mut summary = Self::default();
        summary.total_connections = connections.len();

        let mut remote_hosts = HashSet::new();

        for conn in connections {
            match conn.state {
                ConnectionState::Listen => summary.listening_ports += 1,
                ConnectionState::Established => {
                    summary.established += 1;
                    if !is_local_addr(&conn.remote_addr) {
                        summary.external_connections += 1;
                        remote_hosts.insert(conn.remote_addr);
                    }
                }
                _ => {}
            }
        }

        summary.unique_remote_hosts = remote_hosts.len();
        summary
    }
}
