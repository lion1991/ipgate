//! agent 配置。

use anyhow::{bail, Context, Result};
use ipgate_proto::{PortRange, RulesetConfig, DEFAULT_MGMT_PORT};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AgentConfig {
    /// API 监听地址（默认 `0.0.0.0:19186`）。
    pub bind: SocketAddr,
    /// 管理端口：写入 ruleset 的字面放行端口，**永不**进受管名单。应与 `bind` 端口一致。
    pub mgmt_port: u16,
    /// 对全世界开放的 TCP 端口/区间。
    pub public_tcp: Vec<PortRange>,
    /// 对全世界开放的 UDP 端口/区间。
    pub public_udp: Vec<PortRange>,
    /// 数据目录（存储、密钥、证书）。
    pub data_dir: PathBuf,
    /// 管理 API 访问密钥门：要求每个请求带 `X-Ipgate-Key`，否则一律 404（端口对外「变暗」）。
    ///
    /// **默认 false**：升级既有部署时不会突然把现有客户端挡在门外（盲改 = 自找麻烦）。
    /// 全新安装由 install.sh 写成 true 并打印 join 串。开启前请确认客户端已带上访问密钥。
    pub require_access_key: bool,
    /// 每源 IP 每分钟最大请求数（0 = 不限）。挡探测/刷量/暴力。默认 120，对正常轮询绰绰有余。
    pub rate_limit_per_min: u32,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            bind: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), DEFAULT_MGMT_PORT),
            mgmt_port: DEFAULT_MGMT_PORT,
            public_tcp: Vec::new(),
            public_udp: Vec::new(),
            data_dir: PathBuf::from("/var/lib/ipgate"),
            // 默认关：保升级不锁现有客户端。全新安装由 install.sh 置 true。
            require_access_key: false,
            rate_limit_per_min: 120,
        }
    }
}

impl AgentConfig {
    /// 从 JSON 文件加载；文件不存在时返回默认配置。
    pub fn load(path: &Path) -> Result<Self> {
        if path.exists() {
            let text = std::fs::read_to_string(path)
                .with_context(|| format!("读取配置失败: {}", path.display()))?;
            serde_json::from_str(&text).with_context(|| format!("解析配置失败: {}", path.display()))
        } else {
            Ok(Self::default())
        }
    }

    /// 校验不变量：管理端口不能为 0，否则会把自己锁死（ADR 0002/0003）。
    pub fn validate(&self) -> Result<()> {
        if self.mgmt_port == 0 {
            bail!("mgmt_port 不能为 0（会挡住管理端口、锁死自己）");
        }
        for p in self.public_tcp.iter().chain(&self.public_udp) {
            if !p.is_valid() {
                bail!("非法端口区间: {}-{}", p.start, p.end);
            }
        }
        Ok(())
    }

    pub fn ruleset(&self) -> RulesetConfig {
        RulesetConfig {
            mgmt_port: self.mgmt_port,
            public_tcp: self.public_tcp.clone(),
            public_udp: self.public_udp.clone(),
        }
    }

    pub fn store_path(&self) -> PathBuf {
        self.data_dir.join("state.json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_uses_19186() {
        let c = AgentConfig::default();
        assert_eq!(c.mgmt_port, 19186);
        assert_eq!(c.bind.port(), 19186);
        assert_eq!(c.ruleset().mgmt_port, 19186);
        c.validate().unwrap();
    }

    #[test]
    fn rejects_zero_mgmt_port() {
        let c = AgentConfig {
            mgmt_port: 0,
            ..AgentConfig::default()
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn partial_config_fills_defaults() {
        // 只给 mgmt_port，其余走默认（serde(default)）。
        let c: AgentConfig = serde_json::from_str(r#"{"mgmt_port": 20000}"#).unwrap();
        assert_eq!(c.mgmt_port, 20000);
        assert_eq!(c.data_dir, PathBuf::from("/var/lib/ipgate"));
    }
}
