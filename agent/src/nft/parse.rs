//! 解析 `nft -j list set ...` 的 JSON 输出为 [`KernelElement`]。
//!
//! nft 的元素有多种形态：裸字符串地址、`{"prefix":{addr,len}}`、以及带 timeout 的
//! `{"elem":{"val":..,"expires":secs}}`。这里都覆盖；遇到完全未知的形态报错以便尽早暴露。

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Duration, Utc};
use ipgate_proto::KernelElement;
use ipnet::IpNet;
use serde_json::Value;
use std::net::IpAddr;

/// 把裸地址（host）补成 `/32` 或 `/128` 的 [`IpNet`]。
fn host_to_net(s: &str) -> Result<IpNet> {
    let ip: IpAddr = s.parse().with_context(|| format!("非法地址: {s}"))?;
    let len = if ip.is_ipv4() { 32 } else { 128 };
    Ok(IpNet::new(ip, len)?)
}

fn parse_prefix(p: &Value) -> Result<IpNet> {
    let addr = p
        .get("addr")
        .and_then(|a| a.as_str())
        .context("prefix.addr 缺失")?;
    let len = p
        .get("len")
        .and_then(|l| l.as_u64())
        .context("prefix.len 缺失")? as u8;
    let ip: IpAddr = addr.parse().with_context(|| format!("非法地址: {addr}"))?;
    Ok(IpNet::new(ip, len)?)
}

/// 解析一个元素的「值」（可能是裸字符串或 prefix 对象）。
fn parse_val(v: &Value) -> Result<IpNet> {
    match v {
        Value::String(s) => host_to_net(s),
        Value::Object(m) if m.contains_key("prefix") => parse_prefix(&m["prefix"]),
        _ => bail!("无法识别的元素值: {v}"),
    }
}

fn parse_elem(el: &Value, now: DateTime<Utc>) -> Result<KernelElement> {
    match el {
        Value::String(s) => Ok(KernelElement {
            target: host_to_net(s)?,
            expires_at: None,
        }),
        Value::Object(map) => {
            if map.contains_key("prefix") {
                Ok(KernelElement {
                    target: parse_prefix(&map["prefix"])?,
                    expires_at: None,
                })
            } else if let Some(inner) = map.get("elem") {
                let val = inner.get("val").context("elem.val 缺失")?;
                let target = parse_val(val)?;
                // nft 给的是「剩余秒数」，转成绝对到期时间。
                let expires_at = inner
                    .get("expires")
                    .and_then(|e| e.as_i64())
                    .map(|secs| now + Duration::seconds(secs));
                Ok(KernelElement { target, expires_at })
            } else {
                bail!("无法识别的 nft 元素: {el}")
            }
        }
        _ => bail!("无法识别的 nft 元素: {el}"),
    }
}

/// 解析 `nft -j list set <family> <table> <set>` 的输出。
pub fn parse_set_elements(json: &str, now: DateTime<Utc>) -> Result<Vec<KernelElement>> {
    let v: Value = serde_json::from_str(json).context("nft -j 输出非合法 JSON")?;
    let arr = v
        .get("nftables")
        .and_then(|x| x.as_array())
        .context("缺少 nftables 数组")?;
    let mut out = Vec::new();
    for item in arr {
        let Some(set) = item.get("set") else { continue };
        let Some(elems) = set.get("elem").and_then(|e| e.as_array()) else {
            continue;
        };
        for el in elems {
            out.push(parse_elem(el, now)?);
        }
    }
    Ok(out)
}

/// 把 nft 的人类时长（如 `1d2h3m`、`58m20s`）解析为秒。无法识别返回 `None`。
fn parse_nft_duration(s: &str) -> Option<i64> {
    let mut total = 0i64;
    let mut num = String::new();
    let mut saw_unit = false;
    for c in s.chars() {
        if c.is_ascii_digit() {
            num.push(c);
        } else {
            let n: i64 = num.parse().ok()?;
            num.clear();
            total += n * match c {
                'w' => 7 * 86400,
                'd' => 86400,
                'h' => 3600,
                'm' => 60,
                's' => 1,
                _ => return None,
            };
            saw_unit = true;
        }
    }
    saw_unit.then_some(total)
}

/// 解析 `nft list set <family> <table> <set>` 的**纯文本**输出（老 nft 0.8 无 `-j` 时的回退）。
///
/// 形如：`elements = { 198.51.100.7, 203.0.113.0/24, 192.0.2.9 timeout 1h expires 58m20s }`
/// （可能跨多行）。容错优先：无法解析的 token（如区间 `a-b`）跳过，不让整个 sync 失败。
pub fn parse_set_elements_text(text: &str, now: DateTime<Utc>) -> Result<Vec<KernelElement>> {
    let mut out = Vec::new();
    // 定位 `elements = { ... }`；无 elements 行 = 空 set。
    let Some(start) = text.find("elements") else {
        return Ok(out);
    };
    let Some(open) = text[start..].find('{') else {
        return Ok(out);
    };
    let after = &text[start + open + 1..];
    let end = after.find('}').context("nft 文本输出缺少 elements 闭合括号")?;
    for raw in after[..end].split(',') {
        let part = raw.trim();
        if part.is_empty() {
            continue;
        }
        let mut toks = part.split_whitespace();
        let Some(addr) = toks.next() else { continue };
        let target = match addr.parse::<IpNet>().ok().or_else(|| host_to_net(addr).ok()) {
            Some(n) => n,
            None => continue, // 跳过无法解析的 token，保证 sync 整体可用
        };
        // 找 `expires <dur>` → 绝对到期时间。
        let mut expires_at = None;
        let mut rest = part.split_whitespace();
        while let Some(t) = rest.next() {
            if t == "expires" {
                if let Some(secs) = rest.next().and_then(parse_nft_duration) {
                    expires_at = Some(now + Duration::seconds(secs));
                }
            }
        }
        out.push(KernelElement { target, expires_at });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
      "nftables": [
        {"metainfo": {"version": "1.0.9", "release_name": "Old Doc Yak"}},
        {"set": {
          "family": "inet", "name": "allow4", "table": "ipgate",
          "handle": 3, "type": "ipv4_addr", "flags": ["interval", "timeout"],
          "elem": [
            "198.51.100.7",
            {"prefix": {"addr": "203.0.113.0", "len": 24}},
            {"elem": {"val": "192.0.2.9", "expires": 3500, "timeout": 3600}}
          ]
        }}
      ]
    }"#;

    #[test]
    fn parses_all_three_elem_shapes() {
        let now = Utc::now();
        let els = parse_set_elements(SAMPLE, now).unwrap();
        assert_eq!(els.len(), 3);

        let host: IpNet = "198.51.100.7/32".parse().unwrap();
        let cidr: IpNet = "203.0.113.0/24".parse().unwrap();
        let timed: IpNet = "192.0.2.9/32".parse().unwrap();

        assert!(els.iter().any(|e| e.target == host && e.expires_at.is_none()));
        assert!(els.iter().any(|e| e.target == cidr && e.expires_at.is_none()));
        let t = els.iter().find(|e| e.target == timed).unwrap();
        assert!(t.expires_at.is_some());
        assert!(t.expires_at.unwrap() > now);
    }

    #[test]
    fn empty_set_yields_no_elements() {
        let json = r#"{"nftables":[{"set":{"family":"inet","name":"allow4","table":"ipgate","type":"ipv4_addr"}}]}"#;
        assert!(parse_set_elements(json, Utc::now()).unwrap().is_empty());
    }

    // 老 nft 0.8 文本回退（无 -j）。
    const TEXT_SAMPLE: &str = r#"table inet ipgate {
	set allow4 {
		type ipv4_addr
		flags interval,timeout
		elements = { 198.51.100.7,
			     203.0.113.0/24,
			     192.0.2.9 timeout 1h expires 58m20s }
	}
}"#;

    #[test]
    fn text_parser_handles_host_cidr_and_timeout() {
        let now = Utc::now();
        let els = parse_set_elements_text(TEXT_SAMPLE, now).unwrap();
        assert_eq!(els.len(), 3);

        let host: IpNet = "198.51.100.7/32".parse().unwrap();
        let cidr: IpNet = "203.0.113.0/24".parse().unwrap();
        let timed: IpNet = "192.0.2.9/32".parse().unwrap();
        assert!(els.iter().any(|e| e.target == host && e.expires_at.is_none()));
        assert!(els.iter().any(|e| e.target == cidr));
        let t = els.iter().find(|e| e.target == timed).unwrap();
        assert!(t.expires_at.unwrap() > now);
    }

    #[test]
    fn text_parser_empty_and_no_elements_line() {
        let now = Utc::now();
        let empty = "table inet ipgate {\n\tset allow4 {\n\t\ttype ipv4_addr\n\t\telements = {  }\n\t}\n}";
        assert!(parse_set_elements_text(empty, now).unwrap().is_empty());
        let none = "table inet ipgate {\n\tset allow6 {\n\t\ttype ipv6_addr\n\t}\n}";
        assert!(parse_set_elements_text(none, now).unwrap().is_empty());
    }

    #[test]
    fn nft_duration_parses_compound() {
        assert_eq!(parse_nft_duration("58m20s"), Some(58 * 60 + 20));
        assert_eq!(parse_nft_duration("1d2h"), Some(86400 + 7200));
        assert_eq!(parse_nft_duration("90s"), Some(90));
        assert_eq!(parse_nft_duration("nope"), None);
    }
}
