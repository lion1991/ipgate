#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
//! 经 ctnetlink 删除转发到某个目标的 conntrack 记录（ADR 0014 决策 9）。
//!
//! 目标判挂切走后，持续发包的 UDP 流会不断给旧记录续期、永远走死目标；删掉记录后下一个包
//! 重新经过 prerouting，按新规则 DNAT。不依赖服务器装 `conntrack` 命令。
//!
//! 只删「被 DNAT 过」的记录：回程源 = 目标 IP:端口、原始目的端口在监听段内、且原始目的
//! 不是目标本身。否则 agent 自己连目标的连接（含探测）也会被删，回包变 NEW 被 input 链丢。

use ipgate_proto::PortRange;
use std::net::Ipv4Addr;

const NFNL_SUBSYS_CTNETLINK: u16 = 1;
const IPCTNL_MSG_CT_GET: u16 = 1;
const IPCTNL_MSG_CT_DELETE: u16 = 2;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLA_TYPE_MASK: u16 = 0x3fff;
const AF_INET: u8 = 2;

const CTA_TUPLE_ORIG: u16 = 1;
const CTA_TUPLE_REPLY: u16 = 2;
const CTA_ZONE: u16 = 18;
const CTA_TUPLE_IP: u16 = 1;
const CTA_TUPLE_PROTO: u16 = 2;
const CTA_IP_V4_SRC: u16 = 1;
const CTA_IP_V4_DST: u16 = 2;
const CTA_PROTO_NUM: u16 = 1;
const CTA_PROTO_SRC_PORT: u16 = 2;
const CTA_PROTO_DST_PORT: u16 = 3;

/// 要删哪些记录。
#[derive(Debug, Clone, Copy)]
pub struct Filter {
    pub target_ip: Ipv4Addr,
    pub target_ports: PortRange,
    pub listen: PortRange,
    /// l4 协议号（tcp=6, udp=17）。
    pub protos: &'static [u8],
}

pub fn l4_numbers(p: ipgate_proto::ForwardProto) -> &'static [u8] {
    match p {
        ipgate_proto::ForwardProto::Tcp => &[6],
        ipgate_proto::ForwardProto::Udp => &[17],
        ipgate_proto::ForwardProto::Both => &[6, 17],
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Tuple {
    src: Option<Ipv4Addr>,
    dst: Option<Ipv4Addr>,
    proto: Option<u8>,
    sport: Option<u16>,
    dport: Option<u16>,
}

/// 遍历一段 netlink 属性：(类型, 含头的整段原文, 载荷)。
fn attrs(mut b: &[u8]) -> impl Iterator<Item = (u16, &[u8], &[u8])> {
    std::iter::from_fn(move || {
        if b.len() < 4 {
            return None;
        }
        let len = u16::from_ne_bytes([b[0], b[1]]) as usize;
        let ty = u16::from_ne_bytes([b[2], b[3]]) & NLA_TYPE_MASK;
        if len < 4 || len > b.len() {
            return None;
        }
        let item = (ty, &b[..len], &b[4..len]);
        let adv = (len + 3) & !3;
        b = &b[adv.min(b.len())..];
        Some(item)
    })
}

fn parse_tuple(b: &[u8]) -> Tuple {
    let mut t = Tuple::default();
    for (ty, _, p) in attrs(b) {
        match ty {
            CTA_TUPLE_IP => {
                for (ty, _, p) in attrs(p) {
                    if p.len() == 4 {
                        let ip = Ipv4Addr::new(p[0], p[1], p[2], p[3]);
                        match ty {
                            CTA_IP_V4_SRC => t.src = Some(ip),
                            CTA_IP_V4_DST => t.dst = Some(ip),
                            _ => {}
                        }
                    }
                }
            }
            CTA_TUPLE_PROTO => {
                for (ty, _, p) in attrs(p) {
                    match (ty, p.len()) {
                        (CTA_PROTO_NUM, 1) => t.proto = Some(p[0]),
                        (CTA_PROTO_SRC_PORT, 2) => t.sport = Some(u16::from_be_bytes([p[0], p[1]])),
                        (CTA_PROTO_DST_PORT, 2) => t.dport = Some(u16::from_be_bytes([p[0], p[1]])),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    t
}

fn in_range(p: Option<u16>, r: PortRange) -> bool {
    p.is_some_and(|p| r.start <= p && p <= r.end)
}

/// 一条 dump 出来的记录（nfgenmsg 之后的属性区）若命中 `f`，返回删除它要带的属性
/// （原始方向元组 + zone 的原文）。
fn match_entry(body: &[u8], f: &Filter) -> Option<Vec<u8>> {
    let (mut orig, mut reply, mut key) = (None, None, Vec::new());
    for (ty, raw, p) in attrs(body) {
        match ty {
            CTA_TUPLE_ORIG => {
                orig = Some(parse_tuple(p));
                key.extend_from_slice(raw);
                key.resize((key.len() + 3) & !3, 0);
            }
            CTA_TUPLE_REPLY => reply = Some(parse_tuple(p)),
            CTA_ZONE => {
                key.extend_from_slice(raw);
                key.resize((key.len() + 3) & !3, 0);
            }
            _ => {}
        }
    }
    let (o, r) = (orig?, reply?);
    let hit = r.src == Some(f.target_ip)
        && in_range(r.sport, f.target_ports)
        && r.proto.is_some_and(|p| f.protos.contains(&p))
        && in_range(o.dport, f.listen)
        && o.dst != Some(f.target_ip);
    hit.then_some(key)
}

fn message(ty: u16, flags: u16, seq: u32, body: &[u8]) -> Vec<u8> {
    let len = 16 + 4 + body.len();
    let mut m = Vec::with_capacity(len);
    m.extend_from_slice(&(len as u32).to_ne_bytes());
    m.extend_from_slice(&((NFNL_SUBSYS_CTNETLINK << 8) | ty).to_ne_bytes());
    m.extend_from_slice(&flags.to_ne_bytes());
    m.extend_from_slice(&seq.to_ne_bytes());
    m.extend_from_slice(&0u32.to_ne_bytes());
    // nfgenmsg：family、version(0)、res_id(大端 0)
    m.extend_from_slice(&[AF_INET, 0, 0, 0]);
    m.extend_from_slice(body);
    m
}

/// 一个 netlink 数据报里的各条消息：(类型, 载荷)。
fn messages(mut b: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    std::iter::from_fn(move || {
        if b.len() < 16 {
            return None;
        }
        let len = u32::from_ne_bytes([b[0], b[1], b[2], b[3]]) as usize;
        let ty = u16::from_ne_bytes([b[4], b[5]]);
        if len < 16 || len > b.len() {
            return None;
        }
        let item = (ty, &b[16..len]);
        let adv = (len + 3) & !3;
        b = &b[adv.min(b.len())..];
        Some(item)
    })
}

/// NLMSG_ERROR 载荷里的 errno（0 = ACK）。
fn error_code(p: &[u8]) -> i32 {
    if p.len() < 4 {
        return -1;
    }
    i32::from_ne_bytes([p[0], p[1], p[2], p[3]])
}

/// 删除命中 `f` 的全部记录，返回删掉的条数。
#[cfg(target_os = "linux")]
pub fn flush(f: &Filter) -> anyhow::Result<usize> {
    let sock = linux::Socket::open()?;
    let mut keys = Vec::new();
    sock.send(&message(IPCTNL_MSG_CT_GET, NLM_F_REQUEST | NLM_F_DUMP, 1, &[]))?;
    'dump: loop {
        let buf = sock.recv()?;
        for (ty, p) in messages(&buf) {
            match ty {
                // dump 中途出错时内核把 errno 放在 DONE 的载荷里。
                NLMSG_DONE => {
                    if p.len() >= 4 && error_code(p) < 0 {
                        anyhow::bail!("conntrack dump 失败：errno {}", -error_code(p));
                    }
                    break 'dump;
                }
                NLMSG_ERROR => {
                    let e = error_code(p);
                    if e != 0 {
                        anyhow::bail!("conntrack dump 失败：errno {}", -e);
                    }
                }
                _ if p.len() >= 4 => {
                    if let Some(k) = match_entry(&p[4..], f) {
                        keys.push(k);
                    }
                }
                _ => {}
            }
        }
    }
    let mut n = 0;
    for (i, k) in keys.iter().enumerate() {
        sock.send(&message(IPCTNL_MSG_CT_DELETE, NLM_F_REQUEST | NLM_F_ACK, 2 + i as u32, k))?;
        let buf = sock.recv()?;
        // ENOENT：记录已自己结束，不算失败。
        let code = messages(&buf).find(|(ty, _)| *ty == NLMSG_ERROR).map(|(_, p)| error_code(p));
        match code {
            Some(0) => n += 1,
            Some(e) if -e == libc::ENOENT => {}
            Some(e) => anyhow::bail!("conntrack 删除失败：errno {}", -e),
            None => {}
        }
    }
    Ok(n)
}

#[cfg(not(target_os = "linux"))]
pub fn flush(_f: &Filter) -> anyhow::Result<usize> {
    Ok(0)
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    const NETLINK_NETFILTER: libc::c_int = 12;

    pub struct Socket(OwnedFd);

    impl Socket {
        pub fn open() -> io::Result<Self> {
            // SAFETY: 普通 socket(2)，返回值检查后交给 OwnedFd 管理。
            let fd = unsafe {
                libc::socket(libc::AF_NETLINK, libc::SOCK_RAW | libc::SOCK_CLOEXEC, NETLINK_NETFILTER)
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: fd 刚由 socket(2) 返回且有效。
            let s = Socket(unsafe { OwnedFd::from_raw_fd(fd) });
            let tv = libc::timeval { tv_sec: 3, tv_usec: 0 };
            // SAFETY: 传入的指针与长度对应同一个 timeval。
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    &tv as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::timeval>() as libc::socklen_t,
                );
            }
            Ok(s)
        }

        pub fn send(&self, msg: &[u8]) -> io::Result<()> {
            // SAFETY: sockaddr_nl 全零即内核（pid 0）；指针与长度一致。
            let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
            addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
            let r = unsafe {
                libc::sendto(
                    self.0.as_raw_fd(),
                    msg.as_ptr() as *const libc::c_void,
                    msg.len(),
                    0,
                    &addr as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
                )
            };
            if r < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        pub fn recv(&self) -> io::Result<Vec<u8>> {
            let mut buf = vec![0u8; 1 << 18];
            loop {
                // SAFETY: buf 可写长度即传入长度。
                let n = unsafe {
                    libc::recv(self.0.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
                };
                if n >= 0 {
                    buf.truncate(n as usize);
                    return Ok(buf);
                }
                let e = io::Error::last_os_error();
                // 设了 SO_RCVTIMEO 的 recv 被信号打断不会自动重启。
                if e.kind() != io::ErrorKind::Interrupted {
                    return Err(e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attr(ty: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&((4 + payload.len()) as u16).to_ne_bytes());
        v.extend_from_slice(&ty.to_ne_bytes());
        v.extend_from_slice(payload);
        v.resize((v.len() + 3) & !3, 0);
        v
    }

    fn nested(ty: u16, parts: &[Vec<u8>]) -> Vec<u8> {
        attr(ty | 0x8000, &parts.concat())
    }

    fn tuple(ty: u16, src: [u8; 4], dst: [u8; 4], proto: u8, sport: u16, dport: u16) -> Vec<u8> {
        nested(
            ty,
            &[
                nested(CTA_TUPLE_IP, &[attr(CTA_IP_V4_SRC, &src), attr(CTA_IP_V4_DST, &dst)]),
                nested(
                    CTA_TUPLE_PROTO,
                    &[
                        attr(CTA_PROTO_NUM, &[proto]),
                        attr(CTA_PROTO_SRC_PORT, &sport.to_be_bytes()),
                        attr(CTA_PROTO_DST_PORT, &dport.to_be_bytes()),
                    ],
                ),
            ],
        )
    }

    fn filter() -> Filter {
        Filter {
            target_ip: "198.51.100.7".parse().unwrap(),
            target_ports: PortRange::single(51820),
            listen: PortRange::single(443),
            protos: &[17],
        }
    }

    #[test]
    fn matches_dnat_entry_and_keeps_orig_tuple_as_key() {
        // 客户端 203.0.113.5:40000 → 本机 192.0.2.1:443，DNAT 到 198.51.100.7:51820，SNAT 回 192.0.2.1
        let orig = tuple(CTA_TUPLE_ORIG, [203, 0, 113, 5], [192, 0, 2, 1], 17, 40000, 443);
        let reply = tuple(CTA_TUPLE_REPLY, [198, 51, 100, 7], [192, 0, 2, 1], 17, 51820, 40000);
        let zone = attr(CTA_ZONE, &0u16.to_be_bytes());
        let body = [orig.clone(), reply, attr(3, &[0, 0, 0, 8]), zone.clone()].concat();
        assert_eq!(match_entry(&body, &filter()), Some([orig, zone].concat()));
    }

    #[test]
    fn skips_unrelated_entries() {
        let f = filter();
        let reply_ok = tuple(CTA_TUPLE_REPLY, [198, 51, 100, 7], [192, 0, 2, 1], 17, 51820, 40000);
        // 原始目的端口不在监听段
        let o = tuple(CTA_TUPLE_ORIG, [203, 0, 113, 5], [192, 0, 2, 1], 17, 40000, 444);
        assert!(match_entry(&[o, reply_ok.clone()].concat(), &f).is_none());
        // 本机直连目标（未经 DNAT）：原始目的就是目标
        let o = tuple(CTA_TUPLE_ORIG, [192, 0, 2, 1], [198, 51, 100, 7], 17, 443, 51820);
        let r = tuple(CTA_TUPLE_REPLY, [198, 51, 100, 7], [192, 0, 2, 1], 17, 51820, 443);
        assert!(match_entry(&[o, r].concat(), &f).is_none());
        // 协议不符
        let o = tuple(CTA_TUPLE_ORIG, [203, 0, 113, 5], [192, 0, 2, 1], 6, 40000, 443);
        let r = tuple(CTA_TUPLE_REPLY, [198, 51, 100, 7], [192, 0, 2, 1], 6, 51820, 40000);
        assert!(match_entry(&[o, r].concat(), &f).is_none());
        // 其它目标
        let o = tuple(CTA_TUPLE_ORIG, [203, 0, 113, 5], [192, 0, 2, 1], 17, 40000, 443);
        let r = tuple(CTA_TUPLE_REPLY, [198, 51, 100, 8], [192, 0, 2, 1], 17, 51820, 40000);
        assert!(match_entry(&[o, r].concat(), &f).is_none());
        // 截断的属性不 panic
        assert!(match_entry(&[1, 0], &f).is_none());
    }

    #[test]
    fn message_header_and_parse_roundtrip() {
        let m = message(IPCTNL_MSG_CT_DELETE, NLM_F_REQUEST | NLM_F_ACK, 7, &[1, 2, 3, 4]);
        assert_eq!(m.len(), 24);
        assert_eq!(u16::from_ne_bytes([m[4], m[5]]), (1 << 8) | 2);
        assert_eq!(m[16], AF_INET);
        let got: Vec<_> = messages(&m).collect();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1, &[AF_INET, 0, 0, 0, 1, 2, 3, 4]);
    }
}
