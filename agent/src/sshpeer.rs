//! 隧道连接 → 真实客户端 IP（ADR 0007 下 `whoami` 的数据源）。
//!
//! Noise 连接是 sshd 从 loopback 转发进来的，agent 只看到 `127.0.0.1`。持有这条 loopback
//! socket 的 sshd 会话进程，同时也持有客户端连进来的 SSH 连接；顺着 `/proc` 找到它，
//! 其对端地址就是主机实际看到的客户端 IP（nftables 匹配的正是这个地址）。
//! 仅 Linux 有效；任何环节失败返回 `None`，调用方回退为 loopback。

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

const TCP_ESTABLISHED: u8 = 0x01;

#[derive(Debug)]
struct TcpRow {
    local: SocketAddr,
    remote: SocketAddr,
    state: u8,
    inode: u64,
}

/// `local`/`peer` 是 agent 侧 accept 到的隧道连接两端。
pub fn resolve(local: SocketAddr, peer: SocketAddr, ssh_port: u16) -> Option<IpAddr> {
    let mut rows = Vec::new();
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(text) = std::fs::read_to_string(path) {
            rows.extend(parse_proc_net_tcp(&text));
        }
    }
    // sshd 侧的那一端：本地 = 我们看到的 peer，对端 = 我们的 local。
    let tunnel = rows
        .iter()
        .find(|r| same(r.local, peer) && same(r.remote, local) && r.inode != 0)?
        .inode;
    let owned = socket_inodes_of_owner(tunnel)?;
    pick_client(&rows, &owned, ssh_port)
}

/// 在持有隧道 socket 的进程里挑出客户端连接：已建立、对端非 loopback；
/// 多条时优先本地端口 = ssh_port 的那条。
fn pick_client(rows: &[TcpRow], owned: &HashSet<u64>, ssh_port: u16) -> Option<IpAddr> {
    let cands: Vec<&TcpRow> = rows
        .iter()
        .filter(|r| {
            owned.contains(&r.inode)
                && r.state == TCP_ESTABLISHED
                && !r.remote.ip().to_canonical().is_loopback()
        })
        .collect();
    let hit = cands.iter().find(|r| r.local.port() == ssh_port).or(match cands.as_slice() {
        [only] => Some(only),
        _ => None,
    })?;
    Some(hit.remote.ip().to_canonical())
}

/// 扫 `/proc/*/fd` 找持有 `inode` 的进程，返回该进程全部 socket inode。
fn socket_inodes_of_owner(inode: u64) -> Option<HashSet<u64>> {
    let target = format!("socket:[{inode}]");
    for proc_ent in std::fs::read_dir("/proc").ok()?.flatten() {
        let name = proc_ent.file_name();
        if !name.to_string_lossy().bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let Ok(fds) = std::fs::read_dir(proc_ent.path().join("fd")) else { continue };
        let links: Vec<String> = fds
            .flatten()
            .filter_map(|fd| std::fs::read_link(fd.path()).ok())
            .map(|l| l.to_string_lossy().into_owned())
            .collect();
        if links.contains(&target) {
            return Some(links.iter().filter_map(|l| parse_socket_link(l)).collect());
        }
    }
    None
}

fn parse_socket_link(l: &str) -> Option<u64> {
    l.strip_prefix("socket:[")?.strip_suffix(']')?.parse().ok()
}

/// 双栈 sshd 的 v4 连接在 tcp6 里是 `::ffff:a.b.c.d`，比较与输出前都还原为 v4。
fn same(a: SocketAddr, b: SocketAddr) -> bool {
    a.port() == b.port() && a.ip().to_canonical() == b.ip().to_canonical()
}

fn parse_proc_net_tcp(text: &str) -> Vec<TcpRow> {
    text.lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            Some(TcpRow {
                local: parse_addr(f.get(1)?)?,
                remote: parse_addr(f.get(2)?)?,
                state: u8::from_str_radix(f.get(3)?, 16).ok()?,
                inode: f.get(9)?.parse().ok()?,
            })
        })
        .collect()
}

/// 内核按「内存字节当本机序 u32」以 `%08X` 打印地址，故按 u32 解析后取 `to_ne_bytes` 即还原网络序字节。
fn parse_addr(s: &str) -> Option<SocketAddr> {
    let (ip, port) = s.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let word = |i: usize| u32::from_str_radix(ip.get(i * 8..i * 8 + 8)?, 16).ok().map(u32::to_ne_bytes);
    let ip = match ip.len() {
        8 => IpAddr::V4(Ipv4Addr::from(word(0)?)),
        32 => {
            let mut b = [0u8; 16];
            for i in 0..4 {
                b[i * 4..i * 4 + 4].copy_from_slice(&word(i)?);
            }
            IpAddr::V6(Ipv6Addr::from(b))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

#[cfg(all(test, target_endian = "little"))]
mod tests {
    use super::*;

    // 按 /proc/net/tcp{,6} 格式构造（小端机）：sshd 会话进程持有
    //   inode 1001：203.0.113.7:51234 → 本机 :2222（客户端 SSH 连接）
    //   inode 1002：127.0.0.1:40000 → 127.0.0.1:19187（转发进 agent 的隧道）
    const TCP: &str = "\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:4AF3 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 900 1 0 100 0 0 10 0
   1: 0A00000A:08AE 077100CB:C822 01 00000000:00000000 02:000A7B2F 00000000     0        0 1001 4 0 20 4 30 10 -1
   2: 0100007F:9C40 0100007F:4AF3 01 00000000:00000000 00:00000000 00000000     0        0 1002 1 0 20 4 30 10 -1
   3: 0100007F:4AF3 0100007F:9C40 01 00000000:00000000 00:00000000 00000000   998        0 1003 1 0 20 4 30 10 -1
";
    // 双栈 sshd 上的 v4 客户端：::ffff:198.51.100.9:50000 → :22
    const TCP6: &str = "\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0000000000000000FFFF00000A00000A:0016 0000000000000000FFFF0000096433C6:C350 01 00000000:00000000 00:00000000 00000000     0        0 2001 1 0 20 4 30 10 -1
   1: 00000000000000000000000001000000:0016 00000000000000000000000001000000:C351 01 00000000:00000000 00:00000000 00000000     0        0 2002 1 0 20 4 30 10 -1
";

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_v4_rows() {
        let rows = parse_proc_net_tcp(TCP);
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[1].local, sa("10.0.0.10:2222"));
        assert_eq!(rows[1].remote, sa("203.0.113.7:51234"));
        assert_eq!(rows[1].state, TCP_ESTABLISHED);
        assert_eq!(rows[2].inode, 1002);
    }

    #[test]
    fn picks_ssh_client_of_tunnel_owner() {
        let rows = parse_proc_net_tcp(TCP);
        // agent 侧 accept 到 local=127.0.0.1:19187, peer=127.0.0.1:40000 → sshd 侧 inode 1002。
        let tunnel = rows
            .iter()
            .find(|r| same(r.local, sa("127.0.0.1:40000")) && same(r.remote, sa("127.0.0.1:19187")))
            .unwrap();
        assert_eq!(tunnel.inode, 1002);
        let owned: HashSet<u64> = [1001, 1002].into();
        assert_eq!(pick_client(&rows, &owned, 2222), Some(sa("203.0.113.7:0").ip()));
        // ssh_port 配错时只剩一条非 loopback 也能认出。
        assert_eq!(pick_client(&rows, &owned, 22), Some(sa("203.0.113.7:0").ip()));
        // 进程里没有非 loopback 连接 → None（调用方回退）。
        assert_eq!(pick_client(&rows, &[1002].into(), 2222), None);
    }

    #[test]
    fn v4_mapped_v6_client_is_canonicalized() {
        let rows = parse_proc_net_tcp(TCP6);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].local, sa("[::1]:22"));
        assert_eq!(pick_client(&rows, &[2001, 2002].into(), 22), Some(sa("198.51.100.9:0").ip()));
    }
}

/// 真 /proc 端到端：本进程模拟 sshd 会话（一条非 loopback 的「SSH 连接」+ 一条转发进 agent 的
/// loopback 连接），resolve 应顺着隧道找回「SSH 连接」的对端。需要一块非 loopback 网卡。
#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use super::*;
    use std::net::{TcpListener, TcpStream, UdpSocket};

    #[test]
    fn resolves_through_real_proc() {
        // 取本机出口地址（UDP connect 不发包）。
        let Some(ext) = UdpSocket::bind("0.0.0.0:0")
            .and_then(|u| u.connect("192.0.2.1:9").map(|_| u))
            .and_then(|u| u.local_addr())
            .ok()
            .map(|a| a.ip())
            .filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
        else {
            eprintln!("无非 loopback 地址，跳过");
            return;
        };
        let sshd = TcpListener::bind((ext, 0)).unwrap();
        let ssh_port = sshd.local_addr().unwrap().port();
        let _client = TcpStream::connect(sshd.local_addr().unwrap()).unwrap();
        let (_sshd_conn, client_addr) = sshd.accept().unwrap();

        let agent = TcpListener::bind("127.0.0.1:0").unwrap();
        let _tunnel = TcpStream::connect(agent.local_addr().unwrap()).unwrap();
        let (agent_conn, peer) = agent.accept().unwrap();
        let local = agent_conn.local_addr().unwrap();

        assert_eq!(resolve(local, peer, ssh_port), Some(client_addr.ip()));
    }
}
