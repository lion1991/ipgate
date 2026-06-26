//! dnat 工具的磁盘契约解析：conf 规则行 + `state.json`。
//!
//! 这是把 dnat（另一仓的 Go 工具）的**磁盘格式当 API** 读。格式来自 dnat 的
//! `config.go`（conf 行 `本地端口>网卡>远端:端口>源`）与 `state.go`（state.json）。
//! dnat 一旦改格式，回看此文件与 ADR 0006（契约钉版本）。

use anyhow::{anyhow, bail, Result};
use ipgate_proto::{ForwardSource, PortRange};
use serde::Deserialize;
use std::net::Ipv4Addr;

/// 一条 dnat conf 规则（解析自 `本地端口>网卡>远端主机:端口>源`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnatRule {
    pub listen: PortRange,
    pub iface: String,
    pub remote_host: String,
    pub dest_port: PortRange,
    pub source: ForwardSource,
}

impl DnatRule {
    /// dnat 的 PrefixKey：`本地端口段>网卡>`（含结尾 `>`，与 `config.go` 一致）。
    /// 同 `(端口段, 网卡)` 唯一——删除/去重/迁移都按它。
    pub fn prefix_key(&self) -> String {
        format!("{}>{}>", port_spec(&self.listen), self.iface)
    }
}

fn port_spec(p: &PortRange) -> String {
    if p.start == p.end {
        p.start.to_string()
    } else {
        format!("{}-{}", p.start, p.end)
    }
}

/// 解析端口或端口段：`443` 或 `8000-8010`（闭区间，终点须大于起点）。
fn parse_port_range(s: &str) -> Result<PortRange> {
    let s = s.trim();
    if let Some((a, b)) = s.split_once('-') {
        let start: u16 = a.trim().parse().map_err(|_| anyhow!("非法端口段起点 {a:?}"))?;
        let end: u16 = b.trim().parse().map_err(|_| anyhow!("非法端口段终点 {b:?}"))?;
        if start == 0 {
            bail!("端口不能为 0");
        }
        if end <= start {
            bail!("端口段终点须大于起点: {start}-{end}");
        }
        Ok(PortRange { start, end })
    } else {
        let p: u16 = s.parse().map_err(|_| anyhow!("非法端口 {s:?}"))?;
        if p == 0 {
            bail!("端口不能为 0");
        }
        Ok(PortRange::single(p))
    }
}

/// 解析一行 conf；空行/`#` 注释返回 `Ok(None)`（与 dnat 宽容口径一致）。
pub fn parse_line(line: &str) -> Result<Option<DnatRule>> {
    let t = line.trim();
    if t.is_empty() || t.starts_with('#') {
        return Ok(None);
    }
    let parts: Vec<&str> = t.split('>').collect();
    if parts.len() != 4 {
        bail!("格式错误，应为 4 段以 '>' 分隔: {t:?}");
    }
    let listen = parse_port_range(parts[0])?;
    let iface = parts[1].trim().to_string();
    if iface.is_empty() {
        bail!("网卡为空");
    }
    // host 不含 ':'（IPv4/域名皆然），rsplit 处理端口侧。
    let (host, rport) = parts[2]
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("远端应为 host:port: {:?}", parts[2]))?;
    let remote_host = host.trim().to_string();
    if remote_host.is_empty() {
        bail!("远端主机为空");
    }
    let dest_port = parse_port_range(rport)?;
    // 与 dnat config.go 一致：两侧都是区间时长度必须相等（单↔区间允许）。
    // 不做这一致性检查会把 dnat 自己会跳过的行当成实时规则 → 幻影冲突/幻影列表项。
    let l_range = listen.start != listen.end;
    let d_range = dest_port.start != dest_port.end;
    if l_range && d_range && (listen.end - listen.start) != (dest_port.end - dest_port.start) {
        bail!(
            "端口段长度不一致: {}-{} vs {}-{}",
            listen.start,
            listen.end,
            dest_port.start,
            dest_port.end
        );
    }
    let source = match parts[3].trim() {
        "" | "auto" => ForwardSource::Auto,
        ip => ForwardSource::Ip(ip.parse::<Ipv4Addr>().map_err(|_| anyhow!("非法源 IP {ip:?}"))?),
    };
    Ok(Some(DnatRule {
        listen,
        iface,
        remote_host,
        dest_port,
        source,
    }))
}

/// 解析整份 conf（跳过非法行，不致命——与 dnat `LoadRules` 一致）。
pub fn parse_conf(text: &str) -> Vec<DnatRule> {
    text.lines()
        .filter_map(|l| parse_line(l).ok().flatten())
        .collect()
}

/// 删除所有 PrefixKey **精确等于** `prefix` 的规则行；注释/空行/无法解析的行原样保留。
/// 返回（新文本, 是否删到）。
///
/// 刻意按解析后的 `prefix_key()` 精确比，而非裸 `starts_with`：否则一个部分前缀
/// （如 `8000`）会误删多条不相关规则（评审 CRITICAL）。`removed` 由是否真删到行决定，
/// 不靠文本 diff——避免 conf 非规范化（CRLF/缺尾换行）时把「没删到」误报成已删。
pub fn remove_rule_lines(text: &str, prefix: &str) -> (String, bool) {
    let mut kept: Vec<&str> = Vec::new();
    let mut removed = false;
    for line in text.lines() {
        match parse_line(line) {
            Ok(Some(rule)) if rule.prefix_key() == prefix => removed = true, // 丢弃
            _ => kept.push(line),                                            // 保留原样
        }
    }
    let mut out = kept.join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    (out, removed)
}

// ---- state.json（dnat `state.go`）----

#[derive(Debug, Clone, Default, Deserialize)]
pub struct DnatState {
    #[serde(default)]
    pub entries: Vec<DnatStateEntry>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DnatStateEntry {
    #[serde(rename = "localPort")]
    pub local_port: u16,
    pub interface: String,
    #[serde(rename = "remoteIP", default)]
    pub remote_ip: String,
}

impl DnatState {
    /// 找某 `(本地端口段起点, 网卡)` 的已解析项（取 `remoteIP` / 判 active 用）。
    pub fn find(&self, listen_start: u16, iface: &str) -> Option<&DnatStateEntry> {
        self.entries
            .iter()
            .find(|e| e.local_port == listen_start && e.interface == iface)
    }
}

/// 解析 state.json；缺失/损坏退回空状态（不致命）。
pub fn parse_state(text: &str) -> DnatState {
    serde_json::from_str(text).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_port_auto() {
        let r = parse_line("443>eth0>1.2.3.4:8443>auto").unwrap().unwrap();
        assert_eq!(r.listen, PortRange::single(443));
        assert_eq!(r.iface, "eth0");
        assert_eq!(r.remote_host, "1.2.3.4");
        assert_eq!(r.dest_port, PortRange::single(8443));
        assert_eq!(r.source, ForwardSource::Auto);
        assert_eq!(r.prefix_key(), "443>eth0>");
    }

    #[test]
    fn parse_range_with_ip_source_and_domain() {
        let r = parse_line("8000-8010>eth1>ex.com:9000-9010>10.0.0.5")
            .unwrap()
            .unwrap();
        assert_eq!(r.listen, PortRange { start: 8000, end: 8010 });
        assert_eq!(r.remote_host, "ex.com");
        assert_eq!(r.dest_port, PortRange { start: 9000, end: 9010 });
        assert_eq!(r.source, ForwardSource::Ip("10.0.0.5".parse().unwrap()));
        assert_eq!(r.prefix_key(), "8000-8010>eth1>");
    }

    #[test]
    fn empty_source_is_auto() {
        let r = parse_line("53>eth0>8.8.8.8:53>").unwrap().unwrap();
        assert_eq!(r.source, ForwardSource::Auto);
    }

    #[test]
    fn comments_and_blanks_skipped() {
        assert!(parse_line("   ").unwrap().is_none());
        assert!(parse_line("# a comment").unwrap().is_none());
    }

    #[test]
    fn bad_lines_rejected() {
        assert!(parse_line("443>eth0>1.2.3.4:8443").is_err()); // 仅 3 段
        assert!(parse_line("443>>1.2.3.4:8443>auto").is_err()); // 空网卡
        assert!(parse_line("443>eth0>1.2.3.4:8443>not-an-ip").is_err()); // 非法源
        assert!(parse_line("0>eth0>1.2.3.4:8443>auto").is_err()); // 0 端口
    }

    #[test]
    fn parse_conf_skips_bad_keeps_good() {
        let text = "443>eth0>1.2.3.4:8443>auto\n# c\nGARBAGE\n53>eth0>8.8.8.8:53>auto\n";
        let rules = parse_conf(text);
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].listen, PortRange::single(443));
        assert_eq!(rules[1].listen, PortRange::single(53));
    }

    #[test]
    fn remove_matches_exact_prefix_only() {
        let text = "443>eth0>1.2.3.4:8443>auto\n# keep\n53>eth0>8.8.8.8:53>auto\n";
        let (out, removed) = remove_rule_lines(text, "443>eth0>");
        assert!(removed);
        assert!(!out.contains("443>eth0>"));
        assert!(out.contains("# keep")); // 注释保留
        assert!(out.contains("53>eth0>")); // 不相关规则保留
    }

    #[test]
    fn remove_partial_prefix_deletes_nothing() {
        // 评审 CRITICAL：部分前缀绝不能误删（裸 starts_with 会删 `443>...` 与 `4430>...`）。
        let text = "443>eth0>1.2.3.4:8443>auto\n4430>eth0>1.2.3.4:9000>auto\n";
        for bad in ["4", "44", "443", "443>eth", "8000", ""] {
            let (out, removed) = remove_rule_lines(text, bad);
            assert!(!removed, "前缀 {bad:?} 不应删到任何行");
            assert_eq!(out, text);
        }
    }

    #[test]
    fn remove_nonexistent_returns_false_even_if_unnormalized() {
        // 无尾换行的手写 conf；删不存在的键应 removed=false（不靠文本 diff）。
        let text = "443>eth0>1.2.3.4:8443>auto"; // 注意无结尾 \n
        let (_, removed) = remove_rule_lines(text, "53>eth0>");
        assert!(!removed);
    }

    #[test]
    fn range_mismatch_rejected_like_dnat() {
        // 两侧都是区间但长度不等 → 跳过（与 dnat config.go 一致）。
        assert!(parse_line("8000-8010>eth0>1.2.3.4:9000-9005>auto").is_err());
        // 单↔区间允许。
        assert!(parse_line("443>eth0>1.2.3.4:8000-8010>auto").unwrap().is_some());
    }

    #[test]
    fn state_parses_and_finds() {
        let json = r#"{
          "version":1, "lastHash":"x", "lastError":"",
          "entries":[
            {"localPort":443,"interface":"eth0","remoteHost":"ex.com",
             "remotePort":8443,"source":"auto","remoteIP":"1.2.3.4","sourceIP":"10.0.0.5"}
          ]
        }"#;
        let st = parse_state(json);
        let e = st.find(443, "eth0").unwrap();
        assert_eq!(e.remote_ip, "1.2.3.4");
        assert!(st.find(443, "eth9").is_none());
    }

    #[test]
    fn state_corrupt_is_empty() {
        let st = parse_state("not json");
        assert!(st.entries.is_empty());
    }
}
