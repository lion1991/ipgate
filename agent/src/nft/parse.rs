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
}
