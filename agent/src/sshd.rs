//! 探测系统 sshd 的认证态势（best-effort，读 `sshd -T` 的生效配置）。
//!
//! ADR 0007 把 SSH 当作 agent 的唯一入口，且 SSH 端口默认对全网开放（自锁不变量）。
//! 若服务器仍开着密码登录，这唯一的门就暴露在爆破面下——故把这点回报给客户端，便于告警。
//!
//! 局限：`sshd -T`（不带 `-C`）取的是**全局生效值**，`Match` 块里针对特定用户/来源放开的
//! 密码登录探测不到；任何环节拿不到（无 root / 无 sshd 二进制 / 调用失败）时各项为 `None`。

use std::process::Command;

/// sshd 的认证相关生效配置（各项 `None` = 探测不到）。
#[derive(Debug, Clone, Default)]
pub struct SshAuth {
    /// `PasswordAuthentication` 是否为 yes（密码登录开启）。
    pub password: Option<bool>,
    /// `KbdInteractiveAuthentication`（旧名 `ChallengeResponseAuthentication`）是否为 yes：
    /// 开着 + PAM 可变相做密码登录，故视作密码登录面的一部分。
    pub kbd_interactive: Option<bool>,
    /// `PermitRootLogin` 原值（yes / no / prohibit-password / forced-commands-only）。
    pub permit_root: Option<String>,
}

/// 跑 `sshd -T` 并解析认证项；任何环节失败都退化为「探测不到」（不 panic、不报错）。
pub fn probe() -> SshAuth {
    match run_sshd_t() {
        Some(text) => parse(&text),
        None => SshAuth::default(),
    }
}

/// 依次尝试 PATH 与常见绝对路径（systemd 服务里 root 的 PATH 常不含 /usr/sbin）。
fn run_sshd_t() -> Option<String> {
    for bin in ["sshd", "/usr/sbin/sshd", "/usr/bin/sshd", "/sbin/sshd"] {
        if let Ok(out) = Command::new(bin).arg("-T").output() {
            if out.status.success() {
                if let Ok(s) = String::from_utf8(out.stdout) {
                    return Some(s);
                }
            }
        }
    }
    None
}

/// 解析 `sshd -T` 输出（每行 `key value`，key 恒为小写）。
fn parse(text: &str) -> SshAuth {
    let mut a = SshAuth::default();
    for line in text.lines() {
        let mut it = line.split_whitespace();
        let (Some(key), Some(val)) = (it.next(), it.next()) else {
            continue;
        };
        let yes = val.eq_ignore_ascii_case("yes");
        match key {
            "passwordauthentication" => a.password = Some(yes),
            // 新版 sshd 打印 kbdinteractive…，老版打印 challengeresponse…；两者都认，kbd 优先。
            "kbdinteractiveauthentication" => a.kbd_interactive = Some(yes),
            "challengeresponseauthentication" if a.kbd_interactive.is_none() => {
                a.kbd_interactive = Some(yes)
            }
            "permitrootlogin" => a.permit_root = Some(val.to_string()),
            _ => {}
        }
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hardened_config() {
        let t = "port 22\npasswordauthentication no\nkbdinteractiveauthentication no\npermitrootlogin prohibit-password\n";
        let a = parse(t);
        assert_eq!(a.password, Some(false));
        assert_eq!(a.kbd_interactive, Some(false));
        assert_eq!(a.permit_root.as_deref(), Some("prohibit-password"));
    }

    #[test]
    fn parses_open_config_and_legacy_key() {
        let t = "passwordauthentication yes\nchallengeresponseauthentication yes\npermitrootlogin yes\n";
        let a = parse(t);
        assert_eq!(a.password, Some(true));
        assert_eq!(a.kbd_interactive, Some(true));
        assert_eq!(a.permit_root.as_deref(), Some("yes"));
    }

    #[test]
    fn newer_kbd_key_wins_over_legacy() {
        // 两个键都在时（理论上不会），以 kbdinteractive 为准。
        let t = "kbdinteractiveauthentication no\nchallengeresponseauthentication yes\n";
        assert_eq!(parse(t).kbd_interactive, Some(false));
    }

    #[test]
    fn missing_keys_stay_none() {
        let a = parse("port 2222\nciphers aes256-gcm@openssh.com\n");
        assert!(a.password.is_none());
        assert!(a.kbd_interactive.is_none());
        assert!(a.permit_root.is_none());
    }
}
